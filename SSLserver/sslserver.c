
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


 


int create_socket(int port)
{int on = 1;
    int s;
    struct sockaddr_in addr;
 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
 int rv;
    s = socket(AF_INET, SOCK_STREAM, 0);
    //rv = evutil_make_socket_nonblocking(s);
    if (rv == -1) {
		 printf("Error making socket nonblocking: %s (%i)\n",
		               strerror(errno), errno);
		evutil_closesocket(s);
		return -1;
	}
    
  //  rv = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on));
	if (rv == -1) {
		 printf("Error from setsockopt(SO_KEEPALIVE): %s (%i)\n",
		               strerror(errno), errno);
		evutil_closesocket(s);
		return -1;
	}

	//rv = evutil_make_listen_socket_reuseable(s);
	if (rv == -1) {
		printf("Error from setsockopt(SO_REUSABLE): %s\n",
		               strerror(errno));
		evutil_closesocket(s);
		return -1;
	}
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

     if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }
  
    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert
    if (SSL_CTX_use_certificate_file(ctx, "/home/paraqum/WORK/Lasitha/sslsplit_analyzer_2/sslsplit/ca.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/paraqum/WORK/Lasitha/sslsplit_analyzer_2/sslsplit/ca.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    } */
      if (SSL_CTX_use_certificate_file(ctx, "/etc/symbion/cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/symbion/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
     
    
     int bytes;
	char buf[128];
    
    
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(12443);

    //Handle connections 
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "<div><h1>Example Domain</h1> <p>This domain is established to be used for illustrative examples in documents. You may use this domain in examples without prior coordination or asking for permission.</p> <p><a href='http://www.iana.org/domains/example'>More information...</a></p></div>";

         int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
      
      memset(buf, '\0', sizeof(buf));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	while(bytes > 0){
		write(STDOUT_FILENO, buf, bytes);
		memset(buf, '\0', sizeof(buf));
		bytes = SSL_read(ssl, buf, sizeof(buf));
                if (bytes<128){
                  write(STDOUT_FILENO, buf, bytes);

                    break;
                }
                
              
	}        
             SSL_write(ssl, reply, strlen(reply));   
      
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
 
}



