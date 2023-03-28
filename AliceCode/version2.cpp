#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <tpf/tpfeq.h>
#include <tpf/tpfio.h>
#include <sys/types.h>

#include <openssl/ssl.h>
using namespace std;
#define PORT 8080


int servertls (int &Connected_socket) {
    SSL_METHOD *meth;
    SSL_CTX  *ctx;
    SSL  *myssl;
     /* Initialize the SSL libraries*/
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /*Set SSLv23 for the connection*/
  meth=TLSv1_2_server_method();   // Forcing TLS1.2
  ctx=SSL_CTX_new(meth);
  if (!ctx) {
    printf("Error creating the context.\n");
    exit(0);
  }

    /*Set the Cipher List*/
  if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384") <= 0) {
    printf("Error setting the cipher list.\n");
    exit(0);
  }

// -------------------------------------------------------------- TO Be set
    // /*Set the certificate to be used.*/    ????????????????????????????????
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    exit(0);
  }

  /*Load the password for the Private Key*/
  SSL_CTX_set_default_passwd_cb_userdata(ctx,KEY_PASSWD);

  /*Indicate the key file to be used*/
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    exit(0);
  }

  /*Make sure the key and certificate file match*/
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    exit(0);
  }
// ----------------------- ----------------- CLient Authentication---------------

  /*Used only if client authentication will be used*/
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);

  /* Load certificates of trusted CAs based on file provided*/
  if (SSL_CTX_load_verify_locations(ctx,CA_FILE,CA_DIR)<1) {
    printf("Error setting the verify locations.\n");
    exit(0);
  }

  /* Set CA list used for client authentication. */
  if (SSL_CTX_load_and_set_client_CA_file(ctx,CA_FILE) <1) {
    printf("Error setting CA list.\n");
    exit(0);
  }

//   --------------------------------------- Binding the sockets and initialising 


  /*Create new ssl object*/
  myssl=SSL_new(ctx);

  if(!myssl) {
    printf("Error creating SSL structure.\n");
    exit(0);
  }


  /* Bind the ssl object with the socket*/
  SSL_set_fd(myssl,Connected_socket);

  /*Do the SSL Handshake*/
    int err=SSL_accept(myssl);


//   ------------------------------------ Error Handling 

  /* Check for error in handshake*/
  if (err<1) {
    err=SSL_get_error(myssl,err);
    printf("SSL error #%d in SSL_accept,program terminated\n",err);
    if(err==5){printf("sockerrno is:%d\n",sock_errno());}
      close(connection_socket);
      SSL_CTX_free(ctx);
      exit(0);
  }

  /* Check for Client authentication error */
  if (SSL_get_verify_result(myssl) != X509_V_OK) {
      printf("SSL Client Authentication error\n");
      SSL_free(myssl);
      close(connection_socket);
      SSL_CTX_free(ctx);
      exit(0);
  }


    /*Print out connection details*/
  printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
  Connected_socket,
  SSL_get_version(myssl),
  SSL_get_cipher(myssl));

}

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
    int Connected_socket= accept(ServerFD, (struct sockaddr*)&address,(socklen_t*)&addrlen) ;

    if (Connected_socket<0){
        cout << "Acception Failed" << endl ;
        return -1 ;
    }

    
    while (1){
        
        char buffer[4096] = { 0 };
        int valread = read(Connected_socket, buffer, 4096);
        cout << buffer << endl ;


        char mFromS[4096] = { 0 }; 
        cin >> mFromS ;
        // mFromS = "Hello, you are connected to the Server\n" ;
        int send_flag =send(Connected_socket,mFromS,4096,0);
        if (send_flag == -1) {
            cout << "Sending Failed" << endl ;
            // what to do ????
        }
    }

    close(Connected_socket);

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