#include "crypto_utils.h"

int main() {
    //Инициализация OpenSSL
    OpenSSL_add_all_algorithms(); //Инициализацияя алгоритмов
    ERR_load_CRYPTO_strings();    //Инициализация ошибок

    KeyPair *mikhail_pair = genKeys();
    KeyPair *alexandra_pair = genKeys();

    size_t mikhail_secret_size;
    unsigned char *mikhail_secret = computeSecret(mikhail_pair->key, 
        alexandra_pair->public_key, alexandra_pair->PKsize, &mikhail_secret_size);

    size_t alexandra_secret_size;
    unsigned char *alexandra_secret = computeSecret(alexandra_pair->key, 
        mikhail_pair->public_key, mikhail_pair->PKsize, &alexandra_secret_size);


    char *mikhail_secret_hex = PKhex(mikhail_secret, mikhail_secret_size);
    char *alexandra_secret_hex = PKhex(alexandra_secret, alexandra_secret_size);
    printf("%s\n%s\n", mikhail_secret_hex, alexandra_secret_hex);

    free(mikhail_secret_hex);
    free(mikhail_secret);
    free(alexandra_secret_hex);
    free(alexandra_secret);

    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    EVP_cleanup();      // Очистка алгоритмов
}