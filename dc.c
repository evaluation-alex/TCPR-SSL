#include "log.h"

#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <tcpr/types.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define CERT_FILE  "TrustStore.pem"
#define PRI_KEY    "privatekey.key"

extern char  __data_start, __bss_start, _edata, _end; 

/*
 * There are two SSL contexts active at a time; between DC and PMU Player
 * and between DC and PMU Dumper.
 */ 
BIO                *bio, *bio1;
BIO                *sbio, *sbio1;
SSL                *ssl = NULL, *ssl1 = NULL;
SSL_CTX            *ctx, *ctx1;
int                tcpr_sock;
struct tcpr_ip4    state1;
struct sockaddr_in pulladdr1;
int                port1;

struct arguments {
	char *name;
	char *logprefix;
	int logbytes;
	int logcount;
	char *pullhost;
	char *pullport;
	char *pushhost;
	char *pushport;
	char *id;
	uint32_t port;
};

static int get_tcpr_state(struct tcpr_ip4 *state, int tcprsock,
			  struct sockaddr_in *peeraddr, uint16_t bindport) {
	memset(state, 0, sizeof(*state));
	state->peer_address = peeraddr->sin_addr.s_addr;
	state->tcpr.hard.peer.port = peeraddr->sin_port;
	state->tcpr.hard.port = htons(bindport);
	
	if (send(tcprsock, state, sizeof(*state), 0) < 0)
		return -1;
	if (recv(tcprsock, state, sizeof(*state), 0) < 0) {
		return -1;
	}
	return 0;
}

/*
 * This function sends acknoledgements to the TCPR when DC receives
 * data from PMU Player. If DC would stop sending the acknolegements then
 * TCPR would stop forwarding packets to DC from PMU Player.
 */ 
long tcpr_feedback(BIO *bio,int cmd,const char *argp,int argi,
        long argl,long ret) {
	long r = 1;
	if (BIO_CB_RETURN & cmd)
		r=ret;
	if(cmd == (BIO_CB_READ|BIO_CB_RETURN)) {
		get_tcpr_state(&state1, tcpr_sock, &pulladdr1, port1);
		
		state1.tcpr.hard.ack =
			    htonl(ntohl(state1.tcpr.hard.ack) + ret);
		if (send(tcpr_sock, &state1, sizeof(state1), 0) < 0) {
			printf("Error in callback!\n");
		}			
	}	
	return r;
}

static void usage(struct arguments *args) {
	fprintf(stderr, "Usage: %s [args] "
		"src-ip src-port stream-id dst-ip dst-port\n", args->name);
	fprintf(stderr, "Optional arguments:\n");
	fprintf(stderr, "	-l log-file:  "
		"prefix of log file name [default = no logging]\n");
	fprintf(stderr, "	-s log-size:  "
		"maximum size of a log file [default = unlimited]\n");
	fprintf(stderr, "	-n log-count: "
		"maximum #log files [default = unlimited]\n");
	fprintf(stderr, "	-p port-number: "
		"port number for data collector [default = 10000]\n");
	exit(1);
}

static void parse_arguments(struct arguments *args, int argc, char **argv) {
	int c;

	args->name = argv[0];
	while ((c = getopt(argc, argv, "l:n:s:p:")) != -1)
		switch (c) {
		case 'l':
			args->logprefix = optarg;
			break;
		case 's':
			args->logbytes = atoi(optarg);
			if (args->logbytes <= 0)
				usage(args);
			break;
		case 'n':
			args->logcount = atoi(optarg);
			if (args->logcount <= 0)
				usage(args);
			break;
		case 'p':
			args->port = atoi(optarg);
			break;
		default:
			usage(args);
		}

	if (argc - optind != 5)
		usage(args);

	args->pullhost = argv[optind++];
	args->pullport = argv[optind++];
	args->id = argv[optind++];
	args->pushhost = argv[optind++];
	args->pushport = argv[optind++];
}

static int resolve_address(struct sockaddr_in *addr, const char *host,
			   const char *port) {
	struct addrinfo hints;
	struct addrinfo *ai;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(host, port, &hints, &ai);
	if (err)
		return err;

	memcpy(addr, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	return 0;
}

static int connect_to_peer(struct sockaddr_in *peeraddr, uint16_t bindport, int recovering) {

	int s;
	int yes = 1;
	struct sockaddr_in self;

	if(ssl == NULL) {
		//Connect with PMU Player
		ctx = SSL_CTX_new(SSLv23_client_method());
		if(! SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)) {
			fprintf(stderr, "Error loading trust store\n");
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return 0;
		}

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0)
			return -1;

		if (bindport) {
			self.sin_family = AF_INET;
			self.sin_addr.s_addr = htonl(INADDR_ANY);
			self.sin_port = htons(bindport);

			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

			if (bind(s, (struct sockaddr *)&self, sizeof(self)) < 0) {
				close(s);
				return -1;
			}
		}
		
		if (connect(s, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0) {
			close(s);
			return -1;
		}
		
		get_tcpr_state(&state1, tcpr_sock, &pulladdr1, port1);
			
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_timeout(ctx, 6000);
		ssl = SSL_new(ctx);
		sbio = BIO_new(BIO_s_socket());
		BIO_set_fd(sbio, s, BIO_NOCLOSE);
		SSL_set_bio(ssl, sbio, sbio);
		BIO_set_callback(sbio,tcpr_feedback);
		//If the connection is not new then it is not required to do handshake again. 
		if(!recovering) {			
			SSL_connect(ssl);
		}
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
				
	} else {
		//Connect with PMU Dumper		
		ctx1 = SSL_CTX_new(SSLv23_client_method());

		if(! SSL_CTX_load_verify_locations(ctx1, CERT_FILE, NULL)) {
			fprintf(stderr, "Error loading trust store\n");
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx1);
			return 0;
		}

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0)
			return -1;

		if (bindport) {
			self.sin_family = AF_INET;
			self.sin_addr.s_addr = htonl(INADDR_ANY);
			self.sin_port = htons(bindport);

			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

			if (bind(s, (struct sockaddr *)&self, sizeof(self)) < 0) {
				close(s);
				return -1;
			}
		}
		
		if (connect(s, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0) {
			close(s);
			return -1;
		}
		
		get_tcpr_state(&state1, tcpr_sock, &pulladdr1, port1);
		
		SSL_CTX_set_mode(ctx1, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_timeout(ctx1, 6000);
		ssl1 = SSL_new(ctx1);
		sbio1 = BIO_new(BIO_s_socket());
		BIO_set_fd(sbio1, s, BIO_NOCLOSE);
		SSL_set_bio(ssl1, sbio1, sbio1);
		SSL_connect(ssl1);
		
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	}
	return s;
}

static const uint16_t masterport = 6666;

static void *do_handle_slaves(void *arg) {
	int sock;
	int slavesock;
	int yes = 1;
	struct sockaddr_in self;
	char buffer[1];

	(void)arg;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	self.sin_family = AF_INET;
	self.sin_port = htons(masterport);
	self.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *)&self, sizeof(self)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (listen(sock, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		slavesock = accept(sock, NULL, NULL);
		if (slavesock < 0) {
			perror("accept");
			continue;
		}

		while (recv(slavesock, buffer, sizeof(buffer), 0) > 0) ;

		close(slavesock);
	}

	close(sock);
	return NULL;
}

static void handle_slaves(void) {
	pthread_t t;

	if (pthread_create(&t, NULL, do_handle_slaves, NULL)) {
		perror("Creating thread to handle slaves");
		exit(EXIT_FAILURE);
	}

	pthread_detach(t);
}

static int connect_to_tcpr(struct sockaddr_in *tcpraddr) {
	int s;
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)tcpraddr, sizeof(*tcpraddr)) < 0) {
		close(s);
		return -1;
	}

	return s;
}

static int claim_tcpr_state(struct tcpr_ip4 *state, int tcprsock,
			    struct sockaddr_in *peeraddr, uint16_t bindport) {
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	if (getsockname(tcprsock, (struct sockaddr *)&addr, &len) < 0)
		return -1;

	if (get_tcpr_state(state, tcprsock, peeraddr, bindport) < 0)
		return -1;

	state->address = addr.sin_addr.s_addr;
	if (send(tcprsock, state, sizeof(*state), 0) < 0)
		return -1;

	return 0;
}

static int wait_for_master(struct tcpr_ip4 *state) {
	int s;
	char buffer[1];
	struct sockaddr_in masteraddr;

	if (!state->address)
		return 0;

	masteraddr.sin_family = AF_INET;
	masteraddr.sin_addr.s_addr = state->address;
	masteraddr.sin_port = htons(masterport);

	s = connect_to_peer(&masteraddr, 0, 1);
	if (s < 0)
		return 1;

	while (recv(s, buffer, sizeof(buffer), 0) > 0) ;

	close(s);
	return 1;
}

static int copy_data(struct tcpr_ip4 *state, struct log *log, int pullsock,
		     int pushsock, int tcprsock) {
	char buffer[65536];
	ssize_t nr;
	ssize_t ns;
	size_t n;
	FILE *fp;
	
	for (;;) {
		nr = SSL_read(ssl,buffer,sizeof(buffer));
		
		//Take backup of data section and BSS
		fp = fopen("bss_backup","wb");
		fwrite(&__bss_start,1,&_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","wb");
		fwrite(&__data_start,1,&_edata - &__data_start,fp);
		fclose(fp);
		
		/*
		 * Sleep is put after taking backup because it helps to simulate
		 * crash and recovery. If we would have not placed sleep then while
		 * simulating crash, it might so happen that program was in the 
		 * process of creating backup files. Therefore to prevent such 
		 * errors we have put sleep.
		 */ 
		sleep(5);
		
		if (nr < 0) {			
			return -1;
		}
		else if (nr == 0) {
			break;
		}

		if (log) {
			if (log_write(log, buffer, nr) < (size_t)nr)
				return -1;
		}

		for (n = 0; n < (size_t)nr; n += ns) {
			ns = SSL_write(ssl1, &buffer[n], nr-n);
			
			//Take backup of data section and BSS
			fp = fopen("bss_backup","wb");
			fwrite(&__bss_start,1,&_end - &__bss_start,fp);
			fclose(fp);
		
			fp = fopen("data_backup","wb");
			fwrite(&__data_start,1,&_edata - &__data_start,fp);
			fclose(fp);
			
			sleep(5);
			
			if (ns < 0)
				return -1;		
		}
	}

	state->tcpr.hard.done_reading = 1;
	state->tcpr.hard.done_writing = 1;
	if (send(tcprsock, state, sizeof(*state), 0) < 0)
		return -1;
	return 0;
}

int main(int argc, char **argv) {
	struct sockaddr_in pulladdr;
	struct sockaddr_in pushaddr;
	int pullsock;
	int pushsock;
	int err;
	int recovering = 0;
	struct arguments args;
	struct log *log = NULL;
	int tcprsock;
	struct tcpr_ip4 state;
	FILE *fp;

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	
	memset(&args, 0, sizeof(args));
	parse_arguments(&args, argc, argv);

	err = resolve_address(&pulladdr, args.pullhost, args.pullport);
	if (err) {
		fprintf(stderr, "%s:%s: %s\n", args.pullhost, args.pullport,
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	err = resolve_address(&pushaddr, args.pushhost, args.pushport);
	if (err) {
		fprintf(stderr, "%s:%s: %s\n", args.pushhost, args.pushport,
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	if (!args.port)
		args.port = 10000;

	printf("Connecting to TCPR.\n");
	tcprsock = connect_to_tcpr(&pulladdr);
	if (tcprsock < 0) {
		perror("Connecting to TCPR");
		exit(EXIT_FAILURE);
	}
	
	pulladdr1 = pulladdr;
	port1 = args.port;
	tcpr_sock = tcprsock;
	
	printf("Waiting for existing master, if any.\n");
	if (get_tcpr_state(&state, tcprsock, &pulladdr, args.port) < 0) {
		perror("Getting TCPR state");
		exit(EXIT_FAILURE);
	}
	
	recovering = wait_for_master(&state);
	if (recovering) {
		printf("Recovering from failed master.\n");
		if (claim_tcpr_state(&state, tcprsock, &pulladdr, args.port) < 0) {
			perror("Claiming TCPR state");
			exit(EXIT_FAILURE);
		}
	} else {
		printf("Creating fresh connection.\n");
	}

	handle_slaves();
	
	printf("Connecting to data source.\n");
	pullsock = connect_to_peer(&pulladdr, args.port, recovering);
	if (pullsock < 0) {
		perror("Connecting to data source");
		exit(EXIT_FAILURE);
	}
	
	if(recovering) {
		fp = fopen("bss_backup","rb");
		fread(&__bss_start,1, &_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","rb");
		fread(&__data_start,1, &_edata - &__data_start,fp);
		fclose(fp);
		
		printf("Done loading backup...\n");		
	}
	
	printf("Connecting to data sink.\n");
	pushsock = connect_to_peer(&pushaddr, 0, recovering);
	if (pushsock < 0) {
		perror("Connecting to data sink");
		exit(EXIT_FAILURE);
	}
	
	if (args.logprefix) {
		printf("Opening log.\n");
		log = log_start(args.logprefix, args.logbytes, args.logcount);
	}

	if (get_tcpr_state(&state, tcprsock, &pulladdr, args.port) < 0) {
		perror("Getting TCPR state");
		exit(EXIT_FAILURE);
	}
	
	if (!recovering) {
		printf("Sending ID to data source.\n");
		if (send(pullsock, args.id, strlen(args.id), 0) < 0) {
			perror("Sending session ID");
			exit(EXIT_FAILURE);
		}
		
		//Take backup of data section and BSS
		fp = fopen("bss_backup","wb");
		fwrite(&__bss_start,1,&_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","wb");
		fwrite(&__data_start,1,&_edata - &__data_start,fp);
		fclose(fp);
	} 
	
	if (get_tcpr_state(&state, tcprsock, &pulladdr, args.port) < 0) {
		perror("Getting TCPR state");
		exit(EXIT_FAILURE);
	}
	/*
	 * After recovery DC makes new socket but backed up SSL context contains 
	 * old socket so associate new socket with stored SSL context.  
	 */ 
	BIO_set_fd(sbio, pullsock, BIO_NOCLOSE);
	printf("Copying data from source to sink.\n");
	if (copy_data(&state, log, pullsock, pushsock, tcprsock) < 0) {
		perror("Copying data");
		exit(EXIT_FAILURE);
	}

	printf("Done.\n");
	close(tcprsock);
	close(pushsock);
	close(pullsock);
	return EXIT_SUCCESS;
}
