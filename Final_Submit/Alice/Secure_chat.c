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
#include <netdb.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define CERT_FILE_CLIENT "./Certs/alice1-crt.pem"
#define KEY_FILE_CLIENT "./Keys/alice1-key.pem"

#define CERT_FILE_SERVER "./Certs/bob1-crt.pem"
#define KEY_FILE_SERVER "./Keys/bob1.pem"

#define CA_CERTS_DIR "./Certs/"
#define SESSION_ID_FILE "./Session_tickets/session_id.bin"
#define SESSION_ID_FILE2 "./Session_tickets/session_id2.bin"

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

int server_function()
{

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

    return 0;
}

int client_function()
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
    server_addr.sin_addr.s_addr = inet_addr(fhostname("bob1"));
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect() failed");
        exit(EXIT_FAILURE);
    }
    int sending_flag_client = send(sockfd, "chat_hello", sizeof("chat_hello"), 0);
    printf("Client >>>>> Hello chat starts\n");
    char buffer_in[1024] = {0};
    int valread = read(sockfd, buffer_in, sizeof(buffer_in));
    printf("Server >>>>>%s\n", buffer_in);
    char buffer1[1024] = {0};
    int wfg = 1;
    while (1)
    {
        printf("Client >>>>> ");
        scanf("%s", buffer1);
        sending_flag_client = send(sockfd, buffer1, sizeof(buffer1), 0);

        if (strcmp(buffer1, "chat_close") == 0)
        {
            printf("Client has closed the TCP with Server by itself\n");
            break;
        }

        printf("Server >>>>> ");
        valread = read(sockfd, buffer_in, sizeof(buffer_in));
        printf("%s\n", buffer_in);
        if (strcmp(buffer_in, "chat_START_SSL_ACK") == 0)
        {
            wfg = 0;
            break;
        }
        if (strcmp(buffer_in, "chat_close") == 0)
        {
            printf("Client has closed the TCP with Server by Server\n");
            break;
        }
    }

    if (wfg == 0)
    {

        // create a new SSL context
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384") <= 0)
        {
            printf("Error setting the cipher list.\n");
            exit(0);
        }
        if (!ctx)
        {
            perror("SSL_CTX_new() failed");
            exit(EXIT_FAILURE);
        }

        // load the trusted server certificate
        if (SSL_CTX_load_verify_locations(ctx, NULL, CA_CERTS_DIR) <= 0)
        {
            perror("SSL_CTX_load_verify_locations() failed");
            exit(EXIT_FAILURE);
        }

        /// ssession resumption
        SSL_SESSION *session = NULL;

        FILE *fp = fopen(SESSION_ID_FILE, "rb");
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

        fp = fopen(SESSION_ID_FILE2, "wb");
        if (fp != NULL)
        {
            PEM_write_SSL_SESSION(fp, session);
            fclose(fp);
        }

        // SSL_CTX_set_session(ctx, session);

        //// session resumption till here

        SSL *ssl = SSL_new(ctx);
        SSL_set_session_id_context(ssl, (const unsigned char *)"my_app", strlen("my_app"));

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
        SSL_set_session(ssl, session);

        if (SSL_connect(ssl) <= 0)
        {
            perror("SSL_connect() failed");
            SSL_free(ssl);
            exit(EXIT_FAILURE);
        }

        // storing session
        // session = SSL_get_session(ssl);
        // fp = fopen(SESSION_ID_FILE, "wb");
        // SSL_SESSION_print_fp(fp, session);
        // fclose(fp);

        session = SSL_get1_session(ssl);
        fp = fopen(SESSION_ID_FILE, "wb");
        if (fp != NULL)
        {
            PEM_write_SSL_SESSION(fp, session);
            fclose(fp);
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

        printf("\n\n----------------------Chat is now Encrypte--------------------------------------------\n");

        while (1)
        {
            // send data to the server
            char message[1024] = {0};
            printf("Client >>>> ");
            scanf("%s", message);
            int len = SSL_write(ssl, message, strlen(message));
            if (len < 0)
            {
                perror("SSL_write() failed");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                exit(EXIT_FAILURE);
            }
            if (strcmp(message, "chat_close") == 0)
            {
                break;
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

            if (strcmp(buffer, "chat_close") == 0)
            {
                break;
            }
        }

        // close the SSL connection and clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);
    printf("Successfully exit \n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (strcmp(argv[1], "-c") == 0)
    {
        int flg = client_function();
        printf("%d", flg);
    }
    else if (strcmp(argv[1], "-s") == 0)
    {
        int flg = server_function();
        printf("%d", flg);
    }

    else
        printf("Invalid Command\n");

    return 0;
}