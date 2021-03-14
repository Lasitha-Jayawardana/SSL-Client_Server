
//gcc -o test test.c -lssl -lcrypto
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char *argv[]){
    
    
   int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	BIO *outbio = NULL;
	SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	char *req;
	int req_len;
	char hostname[] = "www.example.com";
	//char certs[] = "/etc/ssl/certs/ca-certificates.crt";
	int port = 8443;
	int bytes;
	char buf[1024];

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	outbio	= BIO_new(BIO_s_file());
	outbio	= BIO_new_fp(stdout, BIO_NOCLOSE);

        
        
        
        
        
	if(SSL_library_init() < 0){
		BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
	}

	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	host = gethostbyname(hostname);
	sd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1 ) {
		BIO_printf(outbio, "%s: Cannot connect to host %s [%s] on port %d.\n", argv[0], hostname, inet_ntoa(addr.sin_addr), port);
	}

	ssl = SSL_new(ctx); 
	SSL_set_fd(ssl, sd);
	SSL_connect(ssl);

	req = "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding:  \r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n";	
	req_len = strlen(req);
	SSL_write(ssl, req, req_len);

	memset(buf, '\0', sizeof(buf));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	while(bytes > 0){
		write(STDOUT_FILENO, buf, bytes);
		memset(buf, '\0', sizeof(buf));
		bytes = SSL_read(ssl, buf, sizeof(buf));
	}
        printf("%s", "...............");
	SSL_free(ssl);
	close(sd);
	SSL_CTX_free(ctx);
}