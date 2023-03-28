#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
using namespace std;
#define PORT 8080

int ServerSide () {
    int ServerFD = socket(AF_INET, SOCK_STREAM, 0) ;  // TCP / IP IPv4

    if (ServerFD < 0){
        cout << "Socket Creation Failed" << endl;
        return -1 ;    
    }

    
    struct sockaddr_in address ;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    int bind_flag = bind(ServerFD,(struct sockaddr*)&address,sizeof(address));

    if (bind_flag <0){
        cout << "Binding Failed" << endl  ;
        return -1 ;

    }

    int listen_falg = listen(ServerFD,3);
    cout << "Listening \n" ;
    if (listen_falg <0){
        cout << "Listening Falied" << endl  ;
        return -1 ;
    }
    int addrlen = sizeof(address);
    cout << "accepting\n";
    int temp_socket= accept(ServerFD, (struct sockaddr*)&address,(socklen_t*)&addrlen) ;

    if (temp_socket<0){
        cout << "Acception Failed" << endl ;
        return -1 ;
    }

    
    while (1){
        
        char buffer[4096] = { 0 };
        int valread = read(temp_socket, buffer, 4096);
        cout << buffer << endl ;


        char mFromS[4096] = { 0 }; 
        cin >> mFromS ;
        // mFromS = "Hello, you are connected to the Server\n" ;
        int send_flag =send(temp_socket,mFromS,4096,0);
        if (send_flag == -1) {
            cout << "Sending Failed" << endl ;
            // what to do ????
        }
    }

    close(temp_socket);

    shutdown(ServerFD
    , SHUT_RDWR);
    return 1 ;

}


int ClientSide () {
    int ClientFD = socket(AF_INET, SOCK_STREAM, 0) ;  // TCP / IP IPv4

    if (ClientFD < 0){
        cout << "Socket Creation Failed" << endl;
        return -1 ;    
    }


    struct sockaddr_in ServerAddress ;
    ServerAddress.sin_family = AF_INET;
    //ServerAddress.sin_addr.s_addr = inet_addr("127.0.0.2");
    ServerAddress.sin_port = htons(PORT);
    
     if (inet_pton(AF_INET, "127.0.0.1", &ServerAddress.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    int connect_flag=connect(ClientFD,(struct sockaddr*)&ServerAddress,sizeof(ServerAddress));
    if (connect_flag <0){
        cout << "Coonect falg";
    }
    else {
        cout << "Connection Success\n" ;
    }
    while (1){
        
        char buffer[4096] = {0} ;
        cin >> buffer ;
        int sending_flag_client = send(ClientFD,  buffer, 4096, 0);
        cout << "Message Sent "<< sending_flag_client << endl ;
        char buffer_in[4096] = {0} ;
        int valread = read(ClientFD, buffer_in, 4096);
        cout << buffer_in << endl ;
    }

    close(ClientFD);

    return 1 ;

}

int main (int argc, char** argv) {

    cout << argc << endl ;
    cout << argv[0] << " " << argv[1] << endl ;
    if ((argv[1][0] == '-' && argv[1][1] == 'S') && argv[1][2]== '\0')  {
        cout << "Server Matched \n" ;
        int function_flag = ServerSide() ;
        if (function_flag == 1){
            cout << "Server Successfully executed\n" ; 
        }
    }

    else if ((argv[1][0] == '-' && argv[1][1] == 'C') && argv[1][2]== '\0') {
        cout << "Client Matched \n" ;
        int function_flag = ClientSide() ;
        if (function_flag == 1){
            cout << "Client Successfully executed\n" ; 
        }
    }

    else {
        cout << "no valid command" << endl ;
    }

    return 0 ;
}