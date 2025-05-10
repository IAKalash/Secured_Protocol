#include "net_sockets.h"

//Получение IP адреса сокета (IPv4 или IPv6)
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Инициализация сервера и возврат сокета для общения
int init_server(char *port) {
    int status;
    int sockfd, new_fd, yes = 1;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     //Произвольная версия IP
    hints.ai_socktype = SOCK_STREAM; //Потоковый сокет TCP
    hints.ai_flags = AI_PASSIVE;     //Автозаполнение IP
    
    if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    
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
			close(sockfd);
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

	if (listen(sockfd, 5) == -1) {
		fprintf(stderr, "server: failed to listen\n");
		exit(1);
	}

    printf("server: waiting for connections...\n");

    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        fprintf(stderr, "server: failed to accept\n");
		exit(1);
    }

    inet_ntop(their_addr.ss_family,
        get_in_addr((struct sockaddr *)&their_addr),
        s, sizeof s);
    printf("server: got connection from %s\n", s);

    close(sockfd);
    return new_fd;
}

//Соединение с TCP сервером и возврат сокета для общения
int init_client(const char *ip, char *port) {
    int status;
    int sockfd;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}

    for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

    if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(1);
	}

    printf("client: successfully connected to %s\n", ip);
    return(sockfd);
}

//Отправка сообщения
int send_message(int socket, const unsigned char *key, EC_KEY *sign_key, const unsigned char *text, int text_len) {
    message msg;
    msg.text_len = text_len;

    RAND_bytes(msg.IV, 12);  //Создание вектора инициализации

    encrypt(key, msg.IV, text, msg.text_len, msg.text, msg.tag); //Шифрование сообщения

    ecdsa_sign(sign_key, text, text_len, msg.sign, &msg.sign_len); //Подпись исходного сообщения

    if (send(socket, &msg, sizeof(msg), 0) == -1) { //Отправка сообщения
		perror("send");
		return -1;
	}

    return 1;
}

//Получение и дешифровка сообщения
int recv_message(int socket, const unsigned char *key, const unsigned char *mate_PK, KeyPair *mypair, message *out_buf) {
	if (recv(socket, out_buf, sizeof(message), 0) == -1) { //Получение сообщения
		perror("recv");
		return -1;
	}

	unsigned char *text = (unsigned char *)malloc(out_buf->text_len);
	if (!text) error(2);
    out_buf->text_len = decrypt(key, out_buf->IV, out_buf->text, out_buf->text_len, out_buf->tag, text);  //Дешифровка сообщения

	memcpy(out_buf->text, text, out_buf->text_len);
	free(text);

	int status;
	//Проверка подписи
    if ((status = ecdsa_verify(mypair->key, mate_PK, mypair->PKsize, out_buf->text, out_buf->text_len, out_buf->sign, out_buf->sign_len)))
        return 1; //Успешное завершение дешифровки
    else if (status == 0)
		return 0; //Неправильная подпись
	else return -1; //Ошибка проверки
}