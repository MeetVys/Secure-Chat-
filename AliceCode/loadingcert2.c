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
#define SERVER_PORT 8443
#define CERT_FILE "bob1-crt.pem"

int load_ca_certificates(SSL_CTX* ctx, const char* ca_dir)
{
    int count = 0;
    X509_STORE* store = NULL;

    // Create a new certificate store object
    store = X509_STORE_new();
    if (store == NULL) {
        printf("Error creating certificate store.\n");
        return -1;
    }

    // Load CA certificates from the specified directory
    count = X509_STORE_load_locations(store, NULL, ca_dir);
    printf("%d count\n",count) ;
    if (count < 0) {
        printf("Error loading CA certificates from directory.\n");
        X509_STORE_free(store);
        return -1;
    }
    X509 *ca_cert = load_certificate("rootr1-crt.pem");
    if (ca_cert == NULL) {
    /* Handle error */
        printf("error ca 42 \n") ;  
    }   
    if (X509_STORE_add_cert(store, ca_cert) != 1) {
   printf("error ca 45 \n") ; 
}
    // Set the certificate store object for the SSL context
    SSL_CTX_set_cert_store(ctx, store);

    
}
int verify_server_cert(SSL* ssl)
{
    long res = SSL_get_verify_result(ssl);

    if (res != X509_V_OK) {
        printf("Certificate verification failed: %s\n", X509_verify_cert_error_string(res));
        return -1;
    }

    printf("Certificate verification succeeded.\n");
    return 0;
}


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

   if (load_ca_certificates(ctx, "/certs") != 0) {
        printf("Error loading CA certificates.\n");
        SSL_CTX_free(ctx);
        return -1;
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
   
 if (verify_server_cert(ssl) != 0) {
        printf("Error verifying server certificate.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
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




