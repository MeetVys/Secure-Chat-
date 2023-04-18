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

#define CERT_FILE_MITM "./Certs/fakebob.crt"
#define KEY_FILE_MITM "./Keys/fakebobpvt.pem"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9092

#define MITM_IP "127.0.0.2"
#define MITM_PORT 9092

#define CERT_FILE_CLIENT_MITM "./Certs/fakealice.crt"
#define KEY_FILE_CLIENT_MITM "./Keys/fakealice_key.pem"
#define CA_CERTS_DIR "./Certs"
#define SESSION_ID_FILE_MITM "./Session_tickets/session_id_mitm.bin"
#define SESSION_ID_FILE2_MITM "./Session_tickets/session_id_mitm2.bin"

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
    // initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // create a new TCP socket
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
    server_addr.sin_port = htons(MITM_PORT);
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

    // create a new SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"my_app", strlen("my_app"));

    if (!ctx)
    {
        perror("SSL_CTX_new() failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(ctx, NULL, CA_CERTS_DIR) <= 0)
    {
        perror("SSL_CTX_load_verify_locations() failed");
        exit(EXIT_FAILURE);
    }
    // load the server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE_MITM, SSL_FILETYPE_PEM) <= 0)
    {
        perror("SSL_CTX_use_certificate_file() failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE_MITM, SSL_FILETYPE_PEM) <= 0)
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

        // connecting to original server

        int original_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (original_sockfd < 0)
        {
            perror("socket() failed");
            exit(EXIT_FAILURE);
        }

        // connect to the server
        struct sockaddr_in ori_server_addr = {0};
        ori_server_addr.sin_family = AF_INET;
        ori_server_addr.sin_port = htons(SERVER_PORT);
        ori_server_addr.sin_addr.s_addr = inet_addr(fhostname("bob1"));
        if (connect(original_sockfd, (struct sockaddr *)&ori_server_addr, sizeof(ori_server_addr)) < 0)
        {
            perror("connect() failed");
            exit(EXIT_FAILURE);
        }
        int sending_flag_client = send(original_sockfd, "chat_hello", sizeof("chat_hello"), 0);
        printf("Client >>>>> chat_hello\n");
        char buffer_in[1024] = {0};
        valread = read(original_sockfd, buffer_in, sizeof(buffer_in));
        printf("Server >>>>>%s\n", buffer_in);

        // connecting to original server ends

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
                // printf("Server >>>>>> OK_START_TLS\n");
                if (send_flag == -1)
                {
                    printf("Sending Failed\n");
                }

                send_flag = send(original_sockfd, "chat_START_SSL", sizeof("chat_START_SSL"), 0);

                if (send_flag == -1)
                {
                    printf("Sending Failed\n");
                }

                valread = read(original_sockfd, buffer1, sizeof(buffer1));

                printf("Server >>>>>> %s\n", buffer1);

                break;
            }

            send_flag = send(original_sockfd, buffer1, sizeof(buffer1), 0);

            if (send_flag == -1)
            {
                printf("Sending Failed\n");
                // what to do ????
            }

            // ok bye
            if (strcmp(buffer1, "chat_close") == 0)
            {
                close(clientfd);
                close(original_sockfd);
                break;
            }

            valread = read(original_sockfd, buffer1, sizeof(buffer1));

            printf("Server >>>>> ");
            printf("%s\n", buffer1);

            send_flag = send(clientfd, buffer1, sizeof(buffer1), 0);

            if (send_flag == -1)
            {
                printf("Sending Failed\n");
                // what to do ????
            }

            // ok bye
            if (strcmp(buffer1, "chat_close") == 0)
            {
                close(clientfd);
                close(original_sockfd);
                break;
            }
        }

        if (wfg == 1)
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
            perror("SSL_accept() failed interceptor from client");
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

        // connect to client over ssl2

        SSL_CTX *ctx2 = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(ctx2, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx2, TLS1_2_VERSION);
        if (SSL_CTX_set_cipher_list(ctx2, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384") <= 0)
        {
            printf("2: -- Error setting the cipher list.\n");
            exit(0);
        }
        if (!ctx2)
        {
            perror("SSL_CTX_new() 2     failed");
            exit(EXIT_FAILURE);
        }

        // load the trusted server certificate
        if (SSL_CTX_load_verify_locations(ctx2, NULL, "./") <= 0)
        {
            perror("SSL_CTX_load_verify_locations() 2 failed");
            exit(EXIT_FAILURE);
        }

        /// ssession resumption
        SSL_SESSION *session = NULL;

        FILE *fp = fopen(SESSION_ID_FILE_MITM, "rb");
        if (fp != NULL)
        {
            session = PEM_read_SSL_SESSION(fp, NULL, 0, NULL);
            fclose(fp);
        }
        else
            printf("fp null\n");

        if (session == NULL)
        {
            printf("NULL session key ");
        }
        else
            printf("Not null Session ");

        fp = fopen(SESSION_ID_FILE2_MITM, "wb");
        if (fp != NULL)
        {
            PEM_write_SSL_SESSION(fp, session);
            fclose(fp);
        }

        // SSL_CTX_set_session(ctx, session);

        //// session resumption till here

        SSL *ssl2 = SSL_new(ctx2);
        SSL_set_session_id_context(ssl2, (const unsigned char *)"my_app", strlen("my_app"));

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

        SSL_set_session(ssl2, session);
        // perform SSL handshake
        if (SSL_connect(ssl2) <= 0)
        {
            perror("SSL_connect()2 failed");
            SSL_free(ssl2);
            exit(EXIT_FAILURE);
        }

        session = SSL_get1_session(ssl2);
        fp = fopen(SESSION_ID_FILE_MITM, "wb");
        if (fp != NULL)
        {
            PEM_write_SSL_SESSION(fp, session);
            fclose(fp);
        }

        printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
               original_sockfd,
               SSL_get_version(ssl2),
               SSL_get_cipher(ssl2));

        // ends connect to client over ssl
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
            printf("Client >>>>> %s\n", buffer);
            scanf("%s", buffer);
            len = SSL_write(ssl2, buffer, strlen(buffer));
            if (strcmp(buffer, "chat_close") == 0)
            {
                break;
            }
            len = SSL_read(ssl2, buffer, sizeof(buffer));
            if (len < 0)
            {
                perror("SSL_read() failed");
                SSL_shutdown(ssl2);
                SSL_free(ssl2);
                close(original_sockfd);
                continue;
            }
            printf("Server >>>>> %s\n", buffer);

            // send a response back to the client
            scanf("%s", buffer);
            len = SSL_write(ssl, buffer, strlen(buffer));

            if (strcmp(buffer, "chat_close") == 0)
            {
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