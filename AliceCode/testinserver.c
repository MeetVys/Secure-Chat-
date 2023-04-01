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
#include <netdb.h>

#define CERT_FILE_SERVER "bob1-crt.pem"
#define KEY_FILE_SERVER "bob1.pem"

#define SERVER_IP "127.0.0.1"

#define SERVER_PORT 9092

char *fhostname(char *hostname)
{

    struct hostent *host_info = gethostbyname(hostname);
    printf("set one\n");

    if (host_info != NULL)
    {
        printf("Hostname: %s\n", hostname);
        printf("IP Address: %s\n", inet_ntoa(*(struct in_addr *)host_info->h_addr_list[0]));
    }
    else
    {
        printf("Failed to resolve hostname %s\n", hostname);
    }

    return inet_ntoa(*(struct in_addr *)host_info->h_addr_list[0]);
}

int main()
{
    // printf("%s\n", fhostname("www.google.com"));
    // initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // create a new TCP socket Server Socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // bind to a local address and port
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    // listen for incoming connections
    if (listen(sockfd, 5) < 0)
    {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    printf("addresss %d", server_addr.sin_addr.s_addr);

    // create a new SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        perror("SSL_CTX_new() failed");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"my_app", strlen("my_app"));

    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384") <= 0)
    {
        printf("Error setting the cipher list.\n");
        exit(0);
    }
    // load the server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE_SERVER, SSL_FILETYPE_PEM) <= 0)
    {
        perror("SSL_CTX_use_certificate_file() failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE_SERVER, SSL_FILETYPE_PEM) <= 0)
    {
        perror("SSL_CTX_use_PrivateKey_file() failed");
        exit(EXIT_FAILURE);
    }

    // accept incoming connections and handle them
    printf("Meet Vyas\n");
    while (1)
    {
        printf("while Meet Vyas\n");

        // accept a new connection
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_len = sizeof(client_addr);
        printf("Meet Vyas before acceot \n");
        int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        printf("Meet Vyas after\n");
        if (clientfd < 0)
        {
            perror("accept() failed");
            continue;
        }
        printf("Meet Vyas\n");
        char buffer1[1024] = {0};
        int valread = read(clientfd, buffer1, sizeof(buffer1));
        printf("Client >>>>>> %s\n", buffer1);
        int send_flag = send(clientfd, "chat_ok_reply", sizeof("chat_ok_reply"), 0);
        printf("Server >>>>>> chat_ok_reply\n");
        if (send_flag == -1)
        {
            printf("Sending Failed\n");
            // what to do ????
        }
        int wfg = 1;
        while (wfg)
        {
            printf("Client >>>>>> ");
            valread = read(clientfd, buffer1, sizeof(buffer1));

            printf("%s\n", buffer1);
            if (strcmp(buffer1, "chat_START_SSL") == 0)
            {
                wfg = 0;
                send_flag = send(clientfd, "chat_START_SSL_ACK", sizeof("chat_START_SSL_ACK"), 0);
                printf("Server >>>>>> chat_START_SSL_ACK\n");
                if (send_flag == -1)
                {
                    printf("Sending Failed\n");
                }

                break;
            }
            if (strcmp(buffer1, "chat_close") == 0)
            {
                printf("Server has closed the TCP with client upon request of Client\n");
                close(clientfd);
                break;
            }

            printf("Server >>>>> ");
            scanf("%s", buffer1);
            send_flag = send(clientfd, buffer1, sizeof(buffer1), 0);

            if (send_flag == -1)
            {
                printf("Sending Failed\n");
            }
            if (strcmp(buffer1, "chat_close") == 0)
            {
                printf("Server has closed the TCP with client by itself\n");
                close(clientfd);
                break;
            }
        }

        if (wfg == 1) // means that no ssl connection
            continue;

        // create a new SSL object
        SSL *ssl = SSL_new(ctx);
        if (!ssl)
        {
            perror("SSL_new() failed");
            close(clientfd);
            continue;
        }

        // wrap the TCP socket with SSL object
        if (SSL_set_fd(ssl, clientfd) == 0)
        {
            perror("SSL_set_fd() failed");
            SSL_free(ssl);
            close(clientfd);
            continue;
        }

        // perform SSL handshake
        if (SSL_accept(ssl) <= 0)
        {
            perror("SSL_accept() failed");
            ERR_print_errors_fp(stderr);

            SSL_free(ssl);
            close(clientfd);
            continue;
        }

        if (SSL_session_reused(ssl))
        {
            printf("Session resumed\n");
        }
        else
        {
            printf("New session negotiated\n");
        }

        // receive data from the client
        printf("\n\n----------------------Chat is now Encrypte--------------------------------------------\n");
        while (1)
        {
            char buffer[1024] = {0};
            int len = SSL_read(ssl, buffer, sizeof(buffer));
            if (len < 0)
            {
                perror("SSL_read() failed");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(clientfd);
                continue;
            }
            printf("Received message: %s\n", buffer);
            if (strcmp(buffer, "chat_close") == 0)
            {
                break;
            }
            // send a response back to the client
            char response[1024] = {0};
            printf("Server >>>> ");
            scanf("%s", response);
            len = SSL_write(ssl, response, strlen(response));

            if (strcmp(response, "chat_close") == 0)
            {
                break;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientfd);
    }

    SSL_CTX_free(ctx);
}