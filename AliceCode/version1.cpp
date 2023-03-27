#include <bits/stdc++.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

    int bind_flag = bind(sock_desc,(struct sockaddr*)&server,sizeof(server));

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

    string buffer = "" ;
    while (1){
        

        int valread = read(new_socket, buffer, 4096);
        cout << buffer << endl ;


        string mFromS  ;
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

    int connect_flag=connect(ClientFD,(struct sockaddr*)&client,sizeof(client));

    while (1){
        string buffer = "" ;
        cin >> buffer ;
        send(ClientFD,  buffer, 4096, 0);
        cout << "Message Sent" << endl ;
        int valread = read(ClientFD, buffer, 1024);
        cout << buffer << endl ;
    }

    close(client_fd);

    return 1 ;

}

int main (int argc, char** argv) {



    return 0 ;
}