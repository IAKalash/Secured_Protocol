#include "crypto_functions.h"
#include "net_sockets.h"
#include <string.h>
#ifndef _WIN32
    #include <regex.h>
#else
    #include "applink.h"
    #include <conio.h>
#endif

int main(int argc, char *argv[]) {

    #ifdef _WIN32
        OPENSSL_Applink();
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
    #endif

    //Arguments check-up
    int ifserver = (argc > 1 && !strcmp(argv[1], "--server"));
    int ifclient = (argc > 1 && !strcmp(argv[1], "--client"));

    //Checking the number and correctness of arguments
    if ((ifclient && argc != 4) || (ifserver && argc != 3) || (!ifserver && !ifclient)) {
        printf("Usage: ./build/bin/ProtocolApp(.exe) --server <port>\n   OR: ./build/bin/ProtocolApp(.exe) --client <hostname(or IP)> <port>\n");
        exit(1);
    }

    //Server arguments check-up
    if (ifserver) {
        //Checking a port number
        if (atoi(argv[2]) < 1025) {
            printf("You can't use ports below 1025, please, choose another one\n");
            exit(1);
        }
    }
    //Client arguments check-up
    else {
        //Checking a port number
        if (atoi(argv[3]) < 1025) {
            printf("You can't use ports below 1025, please, choose another one\n");
            exit(1);
        }
        #ifndef _WIN32
            //Checking correctness of IP address via regular expressions
            const char *IPv4_pattern = "^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])$";
            const char *IPv6_pattern = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){0,6}(:[0-9a-fA-F]{1,4}){1,7}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$";
            regex_t IPv4_regexp, IPv6_regexp;
            regcomp(&IPv4_regexp, IPv4_pattern, REG_EXTENDED);
            regcomp(&IPv6_regexp, IPv6_pattern, REG_EXTENDED);

            if (regexec(&IPv4_regexp, argv[2], 0, NULL, 0) == REG_NOMATCH) {
                if (regexec(&IPv6_regexp, argv[2], 0, NULL, 0) == REG_NOMATCH) {
                    printf("Incorrect IP address. You should use the host IPv4 or IPv6 address\nFor example: 127.0.0.1 (IPv4) or ::1 (IPv6)\n");
                    exit(1);
                }
            }  
            regfree(&IPv4_regexp);
            regfree(&IPv6_regexp);
        #endif
    }

    //OpenSSL initialization
    OpenSSL_add_all_algorithms(); //Algorythms initialization
    ERR_load_CRYPTO_strings();    //Error decoder initialization

    KeyPair *my_pair = genKeys(); //Generation of unique pair of keys
    unsigned char *mate_PK = malloc(my_pair->PKsize);
    int mate_socket;

    // Winsock initialization for Windows
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("WSAStartup failed: %d\n", WSAGetLastError());
            exit(1);
        }
    #endif

    //Exchanging keys
    if (ifserver) {
        mate_socket = init_server(argv[2]);
        send(mate_socket, my_pair->public_key, my_pair->PKsize, 0);
        recv(mate_socket, mate_PK, my_pair->PKsize, 0);
    }
    else {
        mate_socket = init_client(argv[2], argv[3]);
        recv(mate_socket, mate_PK, my_pair->PKsize, 0);
        send(mate_socket, my_pair->public_key, my_pair->PKsize, 0);
    }
    
    //Computation of secret
    size_t secret_size;
    unsigned char *secret = computeSecret(my_pair->key, mate_PK, my_pair->PKsize, &secret_size);

    //Setting up a static salt
    const unsigned char *salt = (unsigned char *)"protocol salt";

    //Generating a key from secret
    unsigned char *key = hkdf(secret, salt, strlen("protocol salt"), NULL, 0);
    char *hexKey = PKhex(key, sizeof(key));
    printf("Conversation key: %s\n", hexKey);

    #ifdef _WIN32
        WSAPOLLFD fds[1];
        fds[0].fd = mate_socket;
        fds[0].events = POLLIN;
    #else
        struct pollfd fds[2];
        fds[0].fd = mate_socket;
        fds[0].events = POLLIN;
        fds[1].fd = fileno(stdin);
        fds[1].events = POLLIN;
    #endif
    char buffer[404];
    int status;
    message msg;
    printf("\nPrint /close to stop the conversation\n---\n");
    while (1) {
        #ifdef _WIN32
            WSAPoll(fds, 1, 50);
        #else
            poll(fds, 2, -1);
        #endif

        if (fds[0].revents) {
            if ((status = recv_message(mate_socket, key, mate_PK, my_pair, &msg)) == -1) {
                printf("---\n[STATUS] Conversation is finished by your mate\n---\n");
                break;
            }
            else if (status == 0) {
                printf("---\n[WARNING] The sign of this message is incorrect. Furthest conversation may be unsafe\n---\n");
            }
            printf("Mate> ");
            for (int i = 0; i < msg.text_len; ++i) {
                printf("%c", msg.text[i]);
            }
            printf("\n");
        }

        #ifdef _WIN32
            if (_kbhit()) {
                if (fgets(buffer, 404, stdin) != NULL) {
                    printf("\n");
                    if (strcmp(buffer, "/close\n") == 0) {
                        send(mate_socket, "/close", 6, 0);
                        break;
                    } else {
                        if (send_message(mate_socket, key, my_pair->key, (unsigned char *)buffer, strlen(buffer)) == -1) {
                            fprintf(stderr, "Send message failed\n");
                            break;
                        }
                    }
                }
            }
        #else
            if (fds[1].revents) {
                fgets(buffer, 404, stdin);
                if (strcmp(buffer, "/close\n") == 0) {
                    break;
                }
                else {
                    printf("\n");
                    send_message(mate_socket, key, my_pair->key, (unsigned char *)buffer, strlen(buffer));
                }
            }
        #endif
    }

    closesocket(mate_socket);

    //Freeing allocated memory
    free(mate_PK);
    free(secret);
    free(key);
    free(hexKey);
    freeKeys(my_pair);

    ERR_free_strings();
    OPENSSL_cleanup();

    #ifdef _WIN32
        WSACleanup();
    #endif
}