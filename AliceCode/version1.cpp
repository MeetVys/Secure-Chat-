#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;


int ServerSide () {
    int ServerFD = socket(AF_INET, SOCK_STREAM, 0) ;  // TCP / IP IPv4

    if (ServerFD < 0){
        cout << "Socket Creation Failed" << endl;
        return -1 ;    
    }

    int PORT = 9090 ;
    struct sockaddr_in address ;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(PORT);

    int bind_flag = bind(ServerFD,(struct sockaddr*)&ServerFD,sizeof(ServerFD));

    if (bind_flag ==-1){
        cout << "Binding Failed" << endl  ;
        return -1 ;

    }

    int listen_falg = listen(ServerFD,3);
    if (listen_falg == -1){
        cout << "Listening Falied" << endl  ;
        return -1 ;
    }
    int addrlen = sizeof(address);
    int temp_socket= accept(ServerFD, (struct sockaddr*)&address,(socklen_t*)&addrlen) ;

    if (temp_socket<0){
        cout << "Acception Failed" << endl ;
        return -1 ;
    }

    char buffer[4096] = { 0 };
    while (1){
        

        int valread = read(temp_socket, buffer, 4096);
        cout << buffer << endl ;


        char mFromS[4096] = { 0 }; 
        cin >> mFromS ;
        // mFromS = "Hello, you are connected to the Server\n" ;
        int send_flag =send(temp_socket,mFromS,sizeof(mFromS),0);
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

    int PORT = 9090 ;
    struct sockaddr_in ServerAddress ;
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    ServerAddress.sin_port = htons(PORT);

    int connect_flag=connect(ClientFD,(struct sockaddr*)&ClientFD,sizeof(ClientFD));

    while (1){
        
        char buffer[4096] = {0} ;
        cin >> buffer ;
        send(ClientFD,  buffer, 4096, 0);
        cout << "Message Sent" << endl ;
        int valread = read(ClientFD, buffer, 1024);
        cout << buffer << endl ;
    }

    close(ClientFD);

    return 1 ;

}

int main (int argc, char** argv) {

    cout << argc << endl ;
    cout << argv[0] << " " << argv[1] << endl ;
    if ((argv[1][0] == '-' && argv[1][1] == 'S') && argv[1][2]== '\0')  {
        cout << "Server Matched \n" ;
        // int function_flag = ServerSide() ;
        // if (function_flag == 1){
        //     cout << "Server Successfully executed\n" ; 
        // }
    }

    else if ((argv[1][0] == '-' && argv[1][1] == 'C') && argv[1][2]== '\0') {
        cout << "Client Matched \n" ;
        // int function_flag = ClientSide() ;
        // if (function_flag == 1){
        //     cout << "Client Successfully executed\n" ; 
        // }
    }

    else {
        cout << "no valid command" << endl ;
    }

    return 0 ;
}