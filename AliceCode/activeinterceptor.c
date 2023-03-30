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
#define SERVER_PORT 9091

int strcmp (const char* str1, const char* str2);
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
    server_addr.sin_port = htons(8988);
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
    if (SSL_CTX_load_verify_locations(ctx, NULL, "./") <= 0)
    {
        perror("SSL_CTX_load_verify_locations() failed");
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
    printf("Meet Vyas\n") ;
    while (1) {
        printf("while Meet Vyas\n") ;

        // accept a new connection
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_len = sizeof(client_addr);
         printf("Meet Vyas before acceot \n") ;
        int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
         printf("Meet Vyas after\n") ;
        if (clientfd < 0) {
            perror("accept() failed");
            continue;
        }
        printf("Meet Vyas\n") ;
        char buffer1[1024] ={0} ;
        int valread = read(clientfd, buffer1, sizeof(buffer1));
        printf("Client >>>>>> %s\n",buffer1) ;
        int send_flag =send(clientfd,"Hello Lets Chat unencrypted",sizeof("Hello Lets Chat unencrypted"),0);
        printf("Server >>>>>> Hello Lets Chat unencrypted\n") ;
        if (send_flag == -1) {
            printf("Sending Failed\n");
            // what to do ????
        }

        // connecting to original server

        int original_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (original_sockfd < 0){
        perror("socket() failed");
        exit(EXIT_FAILURE);
        }   

    // connect to the server
        struct sockaddr_in ori_server_addr = {0};
        ori_server_addr.sin_family = AF_INET;
        ori_server_addr.sin_port = htons(SERVER_PORT);
        ori_server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(original_sockfd, (struct sockaddr *)&ori_server_addr, sizeof(ori_server_addr)) < 0){
            perror("connect() failed");
            exit(EXIT_FAILURE);
        }
        int sending_flag_client = send(original_sockfd,  "Hello chat starts", sizeof("Hello chat starts"), 0);
        printf("Client >>>>> Hello chat starts\n");
        char buffer_in[1024] ={0} ;
         valread = read(original_sockfd, buffer_in, sizeof(buffer_in));
        printf("Server >>>>>%s\n",buffer_in) ;
        

        // connecting to original server ends


        int wfg = 1;
        while (wfg){
            printf("Client >>>>>> ") ;
            valread = read(clientfd, buffer1, sizeof(buffer1));
            
            printf("%s\n",buffer1) ;
            if (strcmp(buffer1,"START_TLS")==0){
              
                send_flag =send(clientfd,"OK_START_TLS",sizeof("OK_START_TLS"),0);
                printf("Server >>>>>> OK_START_TLS\n") ;
                if (send_flag == -1) {
                    printf("Sending Failed\n");
                   
                }

                send_flag =send(original_sockfd,"START_TLS",sizeof("START_TLS"),0);
           
                if (send_flag == -1) {
                    printf("Sending Failed\n");
            // what to do ????
                }

                valread = read(original_sockfd, buffer1, sizeof(buffer1));
            
                printf("if star %s\n",buffer1) ;

                break ;
            }

            send_flag =send(original_sockfd,buffer1,sizeof(buffer1),0);
           
            if (send_flag == -1) {
                printf("Sending Failed\n");
            // what to do ????
            }

            valread = read(original_sockfd, buffer1, sizeof(buffer1));
            
            printf("%s\n",buffer1) ;
            printf("Server >>>>> ");
        
            send_flag =send(clientfd,buffer1,sizeof(buffer1),0);
           
            if (send_flag == -1) {
                printf("Sending Failed\n");
            // what to do ????
            }
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
            perror("SSL_accept() failed interceptor from client");
            SSL_free(ssl);
            close(clientfd);
            continue;
        }
        


        // connect to client over ssl 
     

         
        SSL_CTX *ctx2 = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(ctx2, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx2, TLS1_2_VERSION);
        if (SSL_CTX_set_cipher_list(ctx2, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384") <= 0) {
            printf("2: -- Error setting the cipher list.\n");
            exit(0);
        }
        if (!ctx2){
            perror("SSL_CTX_new() 2     failed");
            exit(EXIT_FAILURE);
        }

    // load the trusted server certificate
        if (SSL_CTX_load_verify_locations(ctx2, NULL, "./") <= 0){
            perror("SSL_CTX_load_verify_locations() 2 failed");
            exit(EXIT_FAILURE);
        }


        SSL *ssl2 = SSL_new(ctx2);
    if (!ssl2)
    {
        perror("SSL_new() 2 failed");
        exit(EXIT_FAILURE);
    }

    // wrap the TCP socket with SSL object
    if (SSL_set_fd(ssl2, original_sockfd) == 0)
    {
        perror("SSL_set_fd() 2 failed");
        SSL_free(ssl2);
        exit(EXIT_FAILURE);
    }

    // perform SSL handshake
    if (SSL_connect(ssl2) <= 0)
    {
        perror("SSL_connect()2 failed");
        SSL_free(ssl2);
        exit(EXIT_FAILURE);
    }

    printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
           original_sockfd,
           SSL_get_version(ssl2),
           SSL_get_cipher(ssl2));

// ends connect to client over ssl
        // receive data from the client
        printf("\n\n----------------------Chat is now Encrypte--------------------------------------------\n") ;
        while(1){
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
            

            len = SSL_write(ssl2, buffer, strlen(buffer));
            len = SSL_read(ssl2, buffer, sizeof(buffer));
            if (len < 0) {
                perror("SSL_read() failed");
                SSL_shutdown(ssl2);
                SSL_free(ssl2);
                close(original_sockfd);
                continue;
            }
            printf("Received message: %s\n", buffer);
            

        // send a response back to the client
            
            len = SSL_write(ssl, buffer, strlen(buffer));

            if (strcmp(buffer,"OK_BYE")==0){
                break;
            }

        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientfd);
        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(original_sockfd);
        
    }


    
    SSL_CTX_free(ctx);
}