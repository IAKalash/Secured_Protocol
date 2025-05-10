#include "crypto_functions.h"
#include "net_sockets.h"
#include <string.h>

/* TODO:
-AAD
-poll
-Уведомление о полученном сообщении
-README(Документация)
-команды(--help --send --receive ...)
-структуризация (+ комментарии)
-Проверка сети
-Провеока проекта на другом ПК/Linux/Windows
-Возможно разработка установщиков (.bat, .sh)
*/
int main(int argc, char *argv[]) {
    if (argc < 3) {
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
        send(mate_socket, my_pair->public_key, my_pair->PKsize, 0);
        recv(mate_socket, mate_PK, my_pair->PKsize, 0);
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

    unsigned char *key = hkdf(secret, salt, sizeof(salt), NULL, 0); //Генерация ключа из секрета

    if (strcmp("--server", argv[1]) == 0) {
        unsigned char text[20] = "Hello, World!!!";
        if (send_message(mate_socket, key, my_pair->key, text, sizeof(text))) {
            printf("Сообщение отправлено успешно\n");
        }
    }
    else {
        int rm;
        message msg;
        if ((rm = recv_message(mate_socket, key, mate_PK, my_pair, &msg))) 
            printf("%s\n", msg.text);
        else if (rm == 0)
            printf("Invalid sign\n");
    }

    close(mate_socket);

    free(my_pair);
    free(mate_PK);
    free(secret);
    free(key);

    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    EVP_cleanup();      // Очистка алгоритмов
}