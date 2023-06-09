#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8444
#define CERT_FILE "bob1-crt.pem"
#define CA_CERTS_DIR "/certswe"

int main()
{
    // initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    // create a new TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // connect to the server
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect() failed");
        exit(EXIT_FAILURE);
    }

    // create a new SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        perror("SSL_CTX_new() failed");
        exit(EXIT_FAILURE);
    }

    // load the trusted server certificate
    if (SSL_CTX_load_verify_locations(ctx, NULL, "./") <= 0)
    {
        perror("SSL_CTX_load_verify_locations() failed");
        exit(EXIT_FAILURE);
    }


    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        perror("SSL_new() failed");
        exit(EXIT_FAILURE);
    }

    // wrap the TCP socket with SSL object
    if (SSL_set_fd(ssl, sockfd) == 0)
    {
        perror("SSL_set_fd() failed");
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    // perform SSL handshake
    if (SSL_connect(ssl) <= 0)
    {
        perror("SSL_connect() failed");
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
           sockfd,
           SSL_get_version(ssl),
           SSL_get_cipher(ssl));

    // SSL_set_cert_store(ssl, store);
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert)
    {
        // handle error

        printf("No certificate ");
    }
    

    // X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    // X509_STORE_CTX_init(store_ctx, store, server_cert, NULL);

    int res = SSL_get_verify_result(ssl);
    // int res  = X509_verify_cert(store_ctx);
    printf("%d res X509 %d\n", res, X509_V_OK);
    if (res != X509_V_OK)
    {
        char errbuf[256];
        ERR_error_string(res, errbuf);
        fprintf(stderr, "SSL verification failed: %s\n", errbuf);
        // handle error
    }

    // send data to the server
    char *message = "Hello, server!";
    int len = SSL_write(ssl, message, strlen(message));
    if (len < 0)
    {
        perror("SSL_write() failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    // receive a response from the server
    char buffer[1024] = {0};
    len = SSL_read(ssl, buffer, sizeof(buffer));
    if (len < 0)
    {
        perror("SSL_read() failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }
    printf("Received message: %s\n", buffer);

    // close the SSL connection and clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
