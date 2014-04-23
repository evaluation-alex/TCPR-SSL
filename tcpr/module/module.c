#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/nsproxy.h>
#include <linux/netfilter/x_tables.h>
#include <net/route.h>
#include <net/ip.h>

#include <tcpr/types.h>
#include <tcpr/filter.h>

struct connection {
	struct list_head list;
	struct tcpr_ip4 state;
	struct net *net_ns;
	uint32_t address;
	spinlock_t tcpr_lock;
};

static rwlock_t connections_lock;
static struct list_head connections;

static uint32_t shorten(uint32_t n)
{
        return (n >> 16) + (n & 0xffff);
}

static void fix_checksums(struct iphdr *ip, struct tcphdr *tcp, uint32_t old, uint32_t new)
{
	uint32_t check;

	check = ip->check ^ 0xffff;
	check += shorten(~old);
	check += shorten(new);
	ip->check = ~shorten(shorten(check));

	check = tcp->check ^ 0xffff;
	check += shorten(~old);
	check += shorten(new);
	tcp->check = ~shorten(shorten(check));
}

static struct connection *lookup_internal(uint32_t peer_address,
					  uint16_t peer_port,
					  uint32_t address,
					  uint16_t port,
					  struct net *net_ns)
{
	struct connection *c;

 	list_for_each_entry(c, &connections, list)
		if (c->state.peer_address == peer_address
		    && c->state.tcpr.hard.peer.port == peer_port
		    && c->state.address == address
		    && c->state.tcpr.port == port
		    && c->net_ns == net_ns)
			return c;
	return NULL;
}

static struct connection *lookup_external(uint32_t peer_address,
					  uint16_t peer_port,
					  uint32_t address,
					  uint16_t port,
					  struct net *net_ns)
{
	struct connection *c;

	list_for_each_entry(c, &connections, list)
		if (c->state.peer_address == peer_address
		    && c->state.tcpr.hard.peer.port == peer_port
		    && c->address == address
		    && c->state.tcpr.hard.port == port
		    && c->net_ns == net_ns)
			return c;
	return NULL;
}

static struct connection *connection_create(uint32_t peer_address,
					    uint16_t peer_port,
					    uint32_t hard_address,
					    uint16_t hard_port,
					    uint32_t address,
					    uint16_t port,
					    struct net *net_ns)
{
	struct connection *c;

	write_lock(&connections_lock);
	c = lookup_internal(peer_address, peer_port, address, port, net_ns);
	if (c != NULL) {
		write_unlock(&connections_lock);
		return c;
	}

	c = kmalloc(sizeof(*c), GFP_ATOMIC);
	if (!c) {
		write_unlock(&connections_lock);
		return NULL;
	}

	memset(&c->state.tcpr, 0, sizeof(c->state.tcpr));
	c->state.peer_address = peer_address;
	c->state.tcpr.hard.peer.port = peer_port;
	c->address = hard_address;
	c->state.tcpr.hard.port = hard_port;
	c->state.address = address;
	c->state.tcpr.port = port;
	c->net_ns = net_ns;

	INIT_LIST_HEAD(&c->list);
	spin_lock_init(&c->tcpr_lock);
	list_add(&c->list, &connections);
	write_unlock(&connections_lock);
	return c;
}

static void connection_done(struct connection *c)
{
	write_lock(&connections_lock);
	list_del(&c->list);
	write_unlock(&connections_lock);
	kfree(c);
}

static void inject_ip(struct iphdr *ip, struct sk_buff *oldskb)
{
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + ntohs(ip->tot_len), GFP_ATOMIC);
	if (skb == NULL) {
		if (net_ratelimit())
			printk(KERN_DEBUG "TCPR cannot allocate SKB\n");
		return;
	}
	
	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	skb_put(skb, ntohs(ip->tot_len));
	memcpy(skb->data, ip, ntohs(ip->tot_len));
	skb->ip_summed = CHECKSUM_NONE;
	skb_dst_set(skb, dst_clone(skb_dst(oldskb)));
	if (ip_route_me_harder(skb, RTN_UNSPEC) < 0) {
		if (net_ratelimit())
			printk(KERN_DEBUG "TCPR cannot route\n");
		kfree_skb(skb);
		return;
	}
	if (skb->len > dst_mtu(skb_dst(skb))) {
		if (net_ratelimit())
			printk(KERN_DEBUG "TCPR generated packet that would fragment\n");
		kfree_skb(skb);
		return;
	}

	ip_local_out(skb);
}

static void inject_tcp(struct connection *c, enum tcpr_verdict tcpr_verdict, struct sk_buff *oldskb)
{
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
		char opts[40];
	} packet;

	memset(&packet, 0, sizeof(packet));
	packet.ip.ihl = sizeof(packet.ip) / 4;
	packet.ip.version = 4;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_TCP;

	switch (tcpr_verdict) {
	case TCPR_RESET:
		tcpr_reset(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->state.peer_address;
		packet.ip.daddr = c->state.address;
		break;

	case TCPR_RECOVER:
		tcpr_recover(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->state.peer_address;
		packet.ip.daddr = c->state.address;
		break;

	default:
		tcpr_acknowledge(&packet.tcp, &c->state.tcpr);
		packet.ip.saddr = c->address;
		packet.ip.daddr = c->state.peer_address;
	}

	packet.ip.tot_len = htons(sizeof(packet.ip) + packet.tcp.doff * 4);
        packet.ip.check = ip_fast_csum(&packet.ip, packet.ip.ihl);
	packet.tcp.check = csum_tcpudp_magic(packet.ip.saddr, packet.ip.daddr,
					     packet.tcp.doff * 4, IPPROTO_TCP,
					     csum_partial(&packet.tcp,
							  packet.tcp.doff * 4,
							  0));

	inject_ip(&packet.ip, oldskb);
}

static void inject_update(struct iphdr *ip, struct udphdr *udp, struct tcpr_ip4 *state, struct sk_buff *oldskb)
{
	struct {
		struct iphdr ip;
		struct udphdr udp;
		struct tcpr_ip4 state;
	} packet;

	memset(&packet, 0, sizeof(packet));
	packet.ip.ihl = sizeof(packet.ip) / 4;
	packet.ip.version = 4;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.tot_len = htons(sizeof(packet));
        packet.ip.check = ip_fast_csum(&packet.ip, packet.ip.ihl);
	packet.ip.saddr = ip->daddr;
	packet.ip.daddr = ip->saddr;
	packet.udp.source = udp->dest;
	packet.udp.dest = udp->source;
	packet.udp.len = htons(sizeof(packet.udp) + sizeof(packet.state));
	memcpy(&packet.state, state, sizeof(packet.state));
	inject_ip(&packet.ip, oldskb);
}

static unsigned int tcpr_tg_update(struct sk_buff *skb, uint32_t address, struct net *net_ns)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct tcpr_ip4 *update;
	struct connection *c;
	enum tcpr_verdict tcpr_verdict;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_UDP)
		return NF_DROP;
	udp = (struct udphdr *)((uint32_t *)ip + ip->ihl);
	update = (struct tcpr_ip4 *)(udp + 1);

	read_lock(&connections_lock);
	c = lookup_external(update->peer_address, update->tcpr.hard.peer.port,
			    address, update->tcpr.hard.port, net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (!update->tcpr.port) {
			inject_update(ip, udp, update, skb);
			return NF_DROP;
		}
		printk(KERN_INFO "TCPR new connection from update"); /* XXX */
		c = connection_create(update->peer_address,
				      update->tcpr.hard.peer.port,
				      address,
				      update->tcpr.hard.port,
				      update->address,
				      update->tcpr.port,
				      net_ns);
		if (!c)
			return NF_DROP;
	}

	spin_lock(&c->tcpr_lock);
	if (update->address) {
		if (c->state.address != update->address)
			printk(KERN_INFO "TCPR updated soft address"); /* XXX */
		c->state.address = update->address;
	} else
		update->address = c->state.address;
	if (c->state.peer_address && c->state.tcpr.hard.peer.port) {
		tcpr_verdict = tcpr_update(&c->state.tcpr, &update->tcpr);
		if (tcpr_verdict == TCPR_DELIVER)
			inject_update(ip, udp, update, skb);
		else if (tcpr_verdict != TCPR_DROP)
			inject_tcp(c, tcpr_verdict, skb);
		if (c->state.tcpr.done)
			connection_done(c);
	} else {
		inject_update(ip, udp, update, skb);
	}
	spin_unlock(&c->tcpr_lock); /* XXX race if connection done */
	return NF_DROP;
}

static unsigned int tcpr_tg_application(struct sk_buff *skb, uint32_t address, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	enum tcpr_verdict tcpr_verdict;
	unsigned int verdict = NF_DROP;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_TCP)
		return tcpr_tg_update(skb, address, net_ns);
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	read_lock(&connections_lock);
	c = lookup_internal(ip->daddr, tcp->dest, ip->saddr, tcp->source, net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;
		printk(KERN_INFO "TCPR new connection from application"); /* XXX */
		c = connection_create(ip->daddr, tcp->dest,
				      address, tcp->source,
				      ip->saddr, tcp->source, net_ns);
		if (!c)
			return NF_DROP;
	}

	spin_lock(&c->tcpr_lock);
	tcpr_verdict = tcpr_filter(&c->state.tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	if (tcpr_verdict == TCPR_DELIVER) {
		fix_checksums(ip, tcp, ip->saddr, c->address);
		ip->saddr = c->address;
		verdict = NF_ACCEPT;
	} else if (tcpr_verdict != TCPR_DROP) {
		inject_tcp(c, tcpr_verdict, skb);
	}
	if (c->state.tcpr.done)
		connection_done(c);
	spin_unlock(&c->tcpr_lock); /* XXX race */
	return verdict;
}

static unsigned int tcpr_tg_peer(struct sk_buff *skb, struct net *net_ns)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct connection *c;
	struct connection *p;
	enum tcpr_verdict tcpr_verdict;
	unsigned int verdict = NF_DROP;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_TCP)
		return NF_DROP;
	tcp = (struct tcphdr *)((uint32_t *)ip + ip->ihl);

	read_lock(&connections_lock);
	c = lookup_external(ip->saddr, tcp->source, ip->daddr, tcp->dest, net_ns);
	read_unlock(&connections_lock);
	if (!c) {
		if (tcp->ack)
			return NF_DROP;

		read_lock(&connections_lock);
		p = lookup_external(0, 0, ip->daddr, tcp->dest, net_ns);
		read_unlock(&connections_lock);
		if (!p)
			return NF_DROP;

		printk(KERN_INFO "TCPR new connection from peer"); /* XXX */
		c = connection_create(ip->saddr, tcp->source,
				      ip->daddr, tcp->dest,
				      p->state.address, p->state.tcpr.port,
				      net_ns);
		if (!c)
			return NF_DROP;
	}

	spin_lock(&c->tcpr_lock);
	tcpr_verdict = tcpr_filter_peer(&c->state.tcpr, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
	if (tcpr_verdict == TCPR_DELIVER) {
		fix_checksums(ip, tcp, ip->daddr, c->state.address);
		ip->daddr = c->state.address;
		inject_ip(ip, skb);
	} else if (tcpr_verdict != TCPR_DROP) {
		inject_tcp(c, tcpr_verdict, skb);
	}
	if (c->state.tcpr.done)
		connection_done(c);
	spin_unlock(&c->tcpr_lock); /* XXX race */
	return verdict;
}

static unsigned int tcpr_tg(struct sk_buff *skb,
			    const struct xt_action_param *par)
{
	const uint32_t *address = par->targinfo;
	struct net *net_ns = dev_net(par->in ? par->in : par->out);

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	if (*address)
		return tcpr_tg_application(skb, *address, net_ns);
	else
		return tcpr_tg_peer(skb, net_ns);
}

static struct xt_target tcpr_tg_reg = {
	.name = "TCPR",
	.family = AF_INET,
	.target = tcpr_tg,
	.targetsize = sizeof(uint32_t),
	.me = THIS_MODULE,
};

static int __init tcpr_tg_init(void)
{
	rwlock_init(&connections_lock);
	INIT_LIST_HEAD(&connections);
	return xt_register_target(&tcpr_tg_reg);
}

static void __exit tcpr_tg_exit(void)
{
	xt_unregister_target(&tcpr_tg_reg);
}

module_init(tcpr_tg_init);
module_exit(tcpr_tg_exit);

MODULE_AUTHOR("Robert Surton <burgess@cs.cornell.edu>");
MODULE_DESCRIPTION("Xtables: TCPR target");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("ipt_tcpr");
