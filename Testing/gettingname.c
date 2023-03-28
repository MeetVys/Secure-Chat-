#include <stdio.h>
#include <netdb.h>

int main() {
    const char* hostname = "www.example.com";
    struct hostent* host_info = gethostbyname(hostname);

    if (host_info != NULL) {
        printf("Hostname: %s\n", hostname);
        printf("IP Address: %s\n", inet_ntoa(*(struct in_addr*)host_info->h_addr_list[0]));
    } else {
        printf("Failed to resolve hostname %s\n", hostname);
    }

    return 0;
}
