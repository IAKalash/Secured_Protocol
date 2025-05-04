#include "crypto_utils.h"

int main() {
    //Инициализация OpenSSL
    OpenSSL_add_all_algorithms(); //Инициализацияя алгоритмов
    ERR_load_CRYPTO_strings();    //Инициализация ошибок

    KeyPair *mikhail_pair = genKeys();   //Генерация уникальных ключевых пар
    KeyPair *alexandra_pair = genKeys();

    size_t mikhail_secret_size;
    unsigned char *mikhail_secret = computeSecret(mikhail_pair->key, 
        alexandra_pair->public_key, alexandra_pair->PKsize, &mikhail_secret_size); //Расчёт первого секрета

    size_t alexandra_secret_size;
    unsigned char *alexandra_secret = computeSecret(alexandra_pair->key, 
        mikhail_pair->public_key, mikhail_pair->PKsize, &alexandra_secret_size);  //Расчёт второго секрета 

    const unsigned char *salt = (unsigned char *)"protocol salt"; //Создание статичной соли

    unsigned char *mikhail_key = hkdf(mikhail_secret, salt, sizeof(salt), NULL, 0);      //Генерация ключей из секретов
    unsigned char *alexandra_key = hkdf(alexandra_secret, salt, sizeof(salt), NULL, 0);

    unsigned char iv[12];   //Создание вектора инициализации
    RAND_bytes(iv, 12);
    unsigned char message[50] = "Hello, Alexandra!!!";
    unsigned char tag[16] = {0};
    unsigned char encrypted_msg[sizeof(message)];

    printf("Original message: %s\n", message);
    encrypt(mikhail_key, iv, message, sizeof(message), encrypted_msg, tag); //Шифрование сообщения

    char *encrypt_hex = PKhex(encrypted_msg, sizeof(encrypted_msg));
    printf("Crypt: %s\n", encrypt_hex);

    //tag[0] *= 2;

    unsigned char decrypted_msg[sizeof(encrypted_msg)];
    decrypt(alexandra_key, iv, encrypted_msg, sizeof(encrypted_msg), tag, decrypted_msg);  //Дешифровка сообщения

    printf("Decrypted message: %s\n", decrypted_msg);

    free(mikhail_secret);
    free(alexandra_secret);
    free(mikhail_key);
    free(alexandra_key);
    free(encrypt_hex);
    freeKeys(mikhail_pair);
    freeKeys(alexandra_pair);

    //Освобождение памяти от OpenSSL
    ERR_free_strings(); // Освобождение строк ошибок
    EVP_cleanup();      // Очистка алгоритмов
}