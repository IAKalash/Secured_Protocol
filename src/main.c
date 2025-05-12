#include "crypto_functions.h"
#include "net_sockets.h"
#include <string.h>

/* TODO:
-проверка на долбаёба
-сериализация данных
-Проыерка ключа при получении и переотправка при необходимости
-Проверка потери пакетов в recv send
-AAD
-README(Документация)
-структуризация (+ комментарии)
-Провеока проекта на другом ПК/Linux/Windows
*/
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./bin/protocol --server <port>\n   OR: ./bin/protocol --client <hostname(or IP)> <port>\n");
        exit(1);
    }

    //Инициализация OpenSSL
    OpenSSL_add_all_algorithms(); //Инициализацияя алгоритмов
    ERR_load_CRYPTO_strings();    //Инициализация ошибок

    KeyPair *my_pair = genKeys(); //Генерация уникальной ключевой пары
    unsigned char *mate_PK = malloc(my_pair->PKsize);
    int mate_socket;

    if (strcmp("--server", argv[1]) == 0) {
        mate_socket = init_server(argv[2]);
        ssize_t sent = send(mate_socket, my_pair->public_key, my_pair->PKsize, 0);
        if (sent != my_pair->PKsize) error(8); //////////////////////
        ssize_t received = recv(mate_socket, mate_PK, my_pair->PKsize, 0);
        if (received != my_pair->PKsize) error(8); /////////////////
    }
    else {
        mate_socket = init_client(argv[2], argv[3]);
        recv(mate_socket, mate_PK, my_pair->PKsize, 0);
        send(mate_socket, my_pair->public_key, my_pair->PKsize, 0);
    }

    size_t secret_size;
    unsigned char *secret = computeSecret(my_pair->key, 
                        mate_PK, my_pair->PKsize, &secret_size);    //Расчёт секрета

    const unsigned char *salt = (unsigned char *)"protocol salt";   //Создание статичной соли

    unsigned char *key = hkdf(secret, salt, strlen("protocol salt"), NULL, 0); //Генерация ключа из секрета

    struct pollfd fds[2];
    fds[0].fd = mate_socket;
    fds[0].events = POLLIN;
    fds[1].fd = fileno(stdin);
    fds[1].events = POLLIN;
    char buffer[256];
    message msg;
    printf("Print /close to stop the conversation\n---\n");
    while (1) {
        poll(fds, 2, -1);
        if (fds[0].revents) {
            if (recv_message(mate_socket, key, mate_PK, my_pair, &msg) == -1) {
                printf("---\n[STATUS] Conversation is finished by your mate\n---");
                break;
            }
            printf("Mate> %s\n", msg.text);
        }
        if (fds[1].revents) {
            fgets(buffer, 256, stdin);
            if (strcmp(buffer, "/close\n") == 0) {
                break;
            }
            else {
                printf("\n");
                send_message(mate_socket, key, my_pair->key, (unsigned char *)buffer, 256);
            }
        }
    }

    close(mate_socket);

    free(mate_PK);
    free(secret);
    free(key);
    freeKeys(my_pair);

    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    OPENSSL_cleanup();      // Очистка алгоритмов
}