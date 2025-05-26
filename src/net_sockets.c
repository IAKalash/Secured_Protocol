#include "net_sockets.h"

//Returns an IPv4 or IPv6 address of socket
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Initializes a server and returns a socket
int init_server(char *port) {
    int status;
    int sockfd, new_fd;
	#ifdef _WIN32 
		const char yes = '1';
	#else
		int yes = 1;
	#endif
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    
	//Server settings
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;      //Any IP version
    hints.ai_socktype = SOCK_STREAM; //Stream TCP socket
    hints.ai_flags = AI_PASSIVE;     //Fill my IP automatically

	//Setting up a server socket
    if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    
	//Setting up a server on the users port
    for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}
    
    freeaddrinfo(servinfo);

    if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	//Starting to wait for connections
	if (listen(sockfd, 5) == -1) {
		fprintf(stderr, "server: failed to listen\n");
		exit(1);
	}

    printf("\n---\nserver: waiting for connections...\n\n");

	//Accepting an incoming connection
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        #ifdef _WIN32
            fprintf(stderr, "server: failed to accept: %d\n", WSAGetLastError());
        #else
            perror("server: failed to accept");
        #endif
        closesocket(sockfd);
		exit(1);
    }

    inet_ntop(their_addr.ss_family,
        get_in_addr((struct sockaddr *)&their_addr),
        s, sizeof s);
    printf("server: got connection from %s\n", s);

    closesocket(sockfd);
    return new_fd;
}

//Connects to a TCP server and returns a socket
int init_client(const char *ip, char *port) {
    int status;
    int sockfd;
    struct addrinfo hints, *servinfo, *p;

	//Settings for the socket
    memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;      //Any adress family
	hints.ai_socktype = SOCK_STREAM;  //Stream socket

	if ((status = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	//Setting up a socket and connecting to server
	printf("\n---\nClient: Connecting to server...\n");
    for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		int timer = 0;
		while (timer < 15) {
			if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) break;
			
			if (errno != ECONNREFUSED) {
				perror("client: connect");
				closesocket(sockfd);
				break;
			}

			#ifndef _WIN32
				sleep(2);
			#else
				Sleep(2000);
			#endif
			timer++;
			if (timer == 14) {
				printf("Server not found. Connection timeout\n");
				closesocket(sockfd);
				freeaddrinfo(servinfo);
				return -1;
			}
		}
		break;
	}

	if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        freeaddrinfo(servinfo);
        return -1;
    }

	freeaddrinfo(servinfo);

    printf("\nclient: successfully connected to %s\n", ip);
    return(sockfd);
}

//Encrypts and sends a message
int send_message(int socket, const unsigned char *key, EC_KEY *sign_key, const unsigned char *text, int text_len) {
    message msg;
    msg.text_len = text_len;

	//Making an initialization vector
    RAND_bytes(msg.IV, 12);

	//Message encryption
    encrypt(key, msg.IV, text, msg.text_len, msg.text, msg.tag);

	//Making a signature of the message
    ecdsa_sign(sign_key, text, text_len, msg.sign, &msg.sign_len);

	//Sending a message:
	//1. Sending IV
    if (send(socket, msg.IV, 12, 0) != 12) {
		perror("IV sending");
		return -1;
	}

	//2. Sending a tag
	if (send(socket, msg.tag, 16, 0) != 16) {
		perror("Tag sending");
		return -1;
	}

	//3. Sending a lenght of the text
	
	#ifdef _WIN32
		char net_text_len[4];
		snprintf(net_text_len, 4, "%d", msg.text_len);
	#else
		int32_t n_text_len = htonl(msg.text_len);
		int32_t *net_text_len = &n_text_len;
	#endif
	if (send(socket, net_text_len, 4, 0) != 4) {
		perror("Text lenght sending");
		return -1;
	}

	//4. Sending a text
	if (send(socket, msg.text, msg.text_len, 0) != msg.text_len) {
		perror("Text sending");
		return -1;
	}

	//5. Sending a lenght of signature
	#ifdef _WIN32
		char net_sign_len[4];
		snprintf(net_sign_len, 4, "%d", msg.sign_len);
	#else
		uint32_t sign_len = htonl(msg.sign_len);
		uint32_t *net_sign_len = &sign_len;
	#endif
	if (send(socket, net_sign_len, 4, 0) != 4) {
		perror("Sign lenght sending");
		return -1;
	}

	//6. Sending a signature
	if (send(socket, msg.sign, msg.sign_len, 0) != msg.sign_len) {
		perror("Sign sending");
		return -1;
	}

    return 1;
}

//Receives and decrypts a message
int recv_message(int socket, const unsigned char *key, const unsigned char *mate_PK, KeyPair *mypair, message *out_buf) {
	
	//Receiving a message:
	//1. Receiving IV
	if (recv(socket, out_buf->IV, 12, 0) != 12) {
		perror("IV receiving");
		return -1;
	}

	//2. Receiving the tag
	if (recv(socket, out_buf->tag, 16, 0) != 16) {
		perror("Tag receiving");
		return -1;
	}

	//3. Receiving a lenght of the text
	
	#ifdef _WIN32
		char net_text_len[4];
		if (recv(socket, net_text_len, 4, 0) != 4) {
			perror("Text lenght receiving");
			return -1;
		}
		out_buf->text_len = atoi(net_text_len);
	#else
		int32_t net_text_len;
		if (recv(socket, &net_text_len, 4, 0) != 4) {
			perror("Text lenght receiving");
			return -1;
		}
		out_buf->text_len = ntohl(net_text_len);
	#endif
	

	//4. Receiving the encrypted text
	if (recv(socket, out_buf->text, out_buf->text_len, 0) != out_buf->text_len) {
		perror("Text receiving");
		return -1;
	}

	//5. Receiving a lenght of the signature
	#ifdef _WIN32
		char net_sign_len[4];
		if (recv(socket, net_sign_len, 4, 0) != 4) {
			perror("Sign lenght receiving");
			return -1;
		}
		out_buf->sign_len = atoi(net_sign_len);
	#else
		uint32_t net_sign_len;
		if (recv(socket, &net_sign_len, 4, 0) != 4) {
			perror("Sign lenght receiving");
			return -1;
		}
		out_buf->sign_len = ntohl(net_sign_len);
	#endif

	//6. Receiving the signature
	if (recv(socket, out_buf->sign, out_buf->sign_len, 0) != out_buf->sign_len) {
		perror("Sign receiving");
		return -1;
	}

	unsigned char *text = (unsigned char *)malloc(out_buf->text_len);
	if (!text) error(2);

	//Decrypting the message
    out_buf->text_len = decrypt(key, out_buf->IV, out_buf->text, out_buf->text_len, out_buf->tag, text);

	memcpy(out_buf->text, text, out_buf->text_len);
	free(text);

	int status;

	//Verifying of the signature
    if ((status = ecdsa_verify(mypair->key, mate_PK, mypair->PKsize, out_buf->text, out_buf->text_len, out_buf->sign, out_buf->sign_len)))
        return 1;   //Successful decryption
    else if (status == 0)
		return 0;   //Wrong signature
	else return -1; //Verification error
}