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

#define CERT_FILE "bob1-crt.pem"
#define KEY_FILE "bob1.pem"

int main() {
    // initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // create a new TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // bind to a local address and port
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(8444);
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    // listen for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    // create a new SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("SSL_CTX_new() failed");
        exit(EXIT_FAILURE);
    }

    // load the server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file() failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file() failed");
        exit(EXIT_FAILURE);
    }

    // accept incoming connections and handle them
    while (1) {
        // accept a new connection
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_len = sizeof(client_addr);
        int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (clientfd < 0) {
            perror("accept() failed");
            continue;
        }

        // create a new SSL object
        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            perror("SSL_new() failed");
            close(clientfd);
            continue;
        }

        // wrap the TCP socket with SSL object
        if (SSL_set_fd(ssl, clientfd) == 0) {
            perror("SSL_set_fd() failed");
            SSL_free(ssl);
            close(clientfd);
            continue;
        }

        // perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            perror("SSL_accept() failed");
            SSL_free(ssl);
            close(clientfd);
            continue;
        }

        // receive data from the client
        char buffer[1024] = {0};
        int len = SSL_read(ssl, buffer, sizeof(buffer));
        if (len < 0) {
            perror("SSL_read() failed");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(clientfd);
            continue;
        }
        printf("Received message: %s\n", buffer);

        // send a response back to the client
        char* response = "Hello, client!";
        len = SSL_write(ssl, response, strlen(response));
}
}