#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    const char* hostname = "bob1";
    struct hostent* host_info = gethostbyname(hostname);
    printf("set one\n") ;

    if (host_info != NULL) {
        printf("Hostname: %s\n", hostname);
        printf("IP Address: %s\n", inet_ntoa(*(struct in_addr*)host_info->h_addr_list[0]));
    } else {
        printf("Failed to resolve hostname %s\n", hostname);
    }

    return 0;
}
