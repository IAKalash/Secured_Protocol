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

    const unsigned char *salt = (unsigned char *)"protocol salt";

    unsigned char *mikhail_key = hkdf(mikhail_secret, NULL, 0, NULL, 0);
    unsigned char *alexandra_key = hkdf(alexandra_secret, NULL, 0, NULL, 0);

    char *mikhail_key_hex = PKhex(mikhail_key, 32);
    char *alexandra_key_hex = PKhex(alexandra_key, 32);

    printf("%s\n%s\n", mikhail_key_hex, alexandra_key_hex);

    free(mikhail_secret);
    free(alexandra_secret);
    free(mikhail_key);
    free(alexandra_key);
    free(mikhail_key_hex);
    free(alexandra_key_hex);
    freeKeys(mikhail_pair);
    freeKeys(alexandra_pair);

    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    EVP_cleanup();      // Очистка алгоритмов
}