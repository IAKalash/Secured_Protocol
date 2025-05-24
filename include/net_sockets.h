#ifndef NET_SOCKETS
    #define NET_SOCKETS

    #include "crypto_functions.h"

    #ifdef _WIN32
        #include <winsock2.h>
        #include <ws2tcpip.h>
        typedef int socklen_t;
    #else
        #include <unistd.h>
        #include <errno.h>
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <netdb.h>
        #include <arpa/inet.h>
        #include <poll.h>
        #define closesocket(s) close(s) 
    #endif

    // Structure for sent/received messages
    typedef struct message {
        unsigned char IV[12];
        unsigned char tag[16];
        unsigned char text[404];
        int32_t text_len;
        unsigned char sign[72];
        uint32_t sign_len;
        // Additional non-encrypted data (commented out)
        // unsigned char AAD[144];
        // int AAD_len;
    } message;

    // Initializes a TCP server and returns a client socket
    int init_server(char *port);

    // Connects to a TCP server and returns a socket
    int init_client(const char *ip, char *port);

    // Sends a message (IV, tag, signature, ciphertext)
    int send_message(int socket, const unsigned char *key, EC_KEY *sign_key, const unsigned char *text, int text_len);

    // Receives a message (IV, tag, signature, ciphertext)
    int recv_message(int socket, const unsigned char *key, const unsigned char *mate_PK, KeyPair *mypair, message *out_buf);

#endif