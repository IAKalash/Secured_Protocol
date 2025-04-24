#include "crypto_utils.h"

int main() {
    //Инициализация OpenSSL
    OpenSSL_add_all_algorithms(); //Инициализацияя алгоритмов
    ERR_load_CRYPTO_strings();    //Инициализация ошибок

    KeyPair *pair = genKeys();
    char *hex = PKhex(pair->public_key, pair->PKsize);

    printf("%s\n", hex);

    free(hex);
    freeKeys(pair);
    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    EVP_cleanup();      // Очистка алгоритмов
}