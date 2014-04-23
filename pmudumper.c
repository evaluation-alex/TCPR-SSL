#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "c37.h"

#define DFL_PORT	3360
#define CERT_FILE   "TrustStore.pem"
#define PRI_KEY     "privatekey.key"

extern char  __data_start, __bss_start,_edata,_end;
BIO          *bio;
SSL          *ssl;
SSL_CTX      *ctx;

/* Global stuff gleaned from program arguments.
 */
struct prog_args {
	char *name;
	char *port;
} prog_args;

static void usage() {
	fprintf(stderr, "Usage: %s [args]\n", prog_args.name);
	fprintf(stderr, "Optional argument:\n");
	fprintf(stderr, "	-p port: TCP server port [default = %d]\n", DFL_PORT);
	exit(1);
}

int do_copy(int fd) {
	FILE *input = fdopen(fd, "r");
	if (input == 0) {
		fprintf(stderr, "%s: fdopen failed\n", prog_args.name);
		exit(1);
	}

	/* Copy input.
	 */
	while (!feof(input)) {
		/* Read one frame.
		 */
		char buf[FRAME_SIZE];
		int n = SSL_read(ssl,buf,FRAME_SIZE);//fread(buf, FRAME_SIZE, 1, input);
					
		if (n == 0) {
			break;
		}
		if (n < 0) {
			perror("do_copy: fread");
			exit(1);
		}	

		/* Convert the frame.
		 */ 
		 
		c37_packet *pkt = get_c37_packet(buf);
		if (pkt == 0) {
			fprintf(stderr, "%s: do_copy: bad packet\n", prog_args.name);
			exit(1);
		}
		if (pkt->framesize != FRAME_SIZE) {
			fprintf(stderr, "%s: do_copy: bad frame size\n", prog_args.name);
			exit(1);
		}

		/* Write the packet to standard output.
		 */ 
		 
		write_c37_packet_readable(stdout, pkt);
		free(pkt);
	}

	fclose(input);
	return 1;
}

void do_recv(int s) {
	int fd;
	for (;;) {
		if (listen(s, 1) < 0) {
			perror("listen");
			exit(1);
		}
		printf("Waiting for connection...\n");
		if ((fd = accept(s, 0, 0)) < 0) {
			perror("accept");
			exit(1);
		}

		printf("Got connection...\n");
		
		SSL_set_fd(ssl, fd);
		SSL_accept(ssl);
				
		do_copy(fd);
		printf("Connection closed...\n");
	}
}

static void get_args(int argc, char *argv[]) {
	prog_args.name = argv[0];

	int c;
	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
			case 'p':
				if (prog_args.port != 0) {
					fprintf(stderr, "%s: can specify only one port\n",
					                prog_args.name);
					exit(1);
				}
				if ((prog_args.port = optarg) == 0) {
					fprintf(stderr, "%s: -p takes a port argument\n",
					        prog_args.port);
					exit(1);
				}
				break;
			case '?':
			default:
				usage();
		}
	}

	/* Get the remaining args.
	 */
	if (argc - optind != 0) {
		usage();
	}
}

/* If called without arguments, listen for connections.  Otherwise make a
 * connection to the specified first argument.
 */
int main(int argc, char *argv[]) {
	get_args(argc, argv);
	
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	int port = DFL_PORT;
	if (prog_args.port != 0) {
		if ((port = atoi(prog_args.port)) <= 0) {
			fprintf(stderr, "%s: port must be positive integer\n",
			        prog_args.name);
			exit(1);
		}
	}

	/* Create and bind the socket.
	 */
	int s;
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(1);
	}
	
	printf("Attempting to create SSL context... ");
	ctx = SSL_CTX_new(SSLv23_server_method());

	if(ctx == NULL) {
		printf("Failed. Aborting.\n");
		return 0;
	}

	printf("\nLoading certificates...\n");
	if(!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}
	if(!SSL_CTX_use_PrivateKey_file(ctx, PRI_KEY, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_timeout(ctx, 6000);
	ssl = SSL_new(ctx);

	do_recv(s);
	
	return 0;
}
