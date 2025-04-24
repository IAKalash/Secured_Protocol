#include "crypto_utils.h"

void error(int err) { //Вывод ошибок и завершение программы
    ERR_print_errors_fp(stderr);
    if (err == 2) {
        fprintf(stderr, "Memory allocation failed\n");
    }
    else if (err == 3) {
        fprintf(stderr, "Key generation error\n");
    }
    exit(err);
}

KeyPair *genKeys(void) { //Генерация ключевой пары ECDH на кривой

    KeyPair *keys = (KeyPair *)calloc(1, sizeof(KeyPair));
    if (!keys) error(2);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1); //Создание объекта для кривой secp256k1
    if (!key) error(3);

    if (!EC_KEY_generate_key(key)) error(3); //Генерация ключей

    const EC_POINT *point = EC_KEY_get0_public_key(key); //Извлечение публичного ключа
    const EC_GROUP *group = EC_KEY_get0_group(key);        //Извлечение группы кривой

    size_t size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL); //Расчёт размера буфера публичного ключа
    if (!size) error(3);

    unsigned char *public_key = (unsigned char *)malloc(size);
    if (!public_key) error(2);

    size_t check = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, public_key, size, NULL); //Заполнение буфера ключа (перевод в октеты)
    if (check != size) error(3);

    //Заполнение и возврат структуры
    keys->key = key; 
    keys->public_key = public_key;
    keys->PKsize = size;

    return keys;
}

void freeKeys(KeyPair *pair) { //Освобождение структуры
    if (pair) { //if pair != NULL
        EC_KEY_free(pair->key);
        free(pair->public_key);
        free(pair);
    }
}

char *PKhex(unsigned char *pub_key, size_t size) { //Перевод public_key в hex-строку
    char *hex = (char *)malloc(2 * size + 1);
    if (!hex) error(2);

    for (int i = 0; i < size; ++i) {
        sprintf(&hex[2 * i], "%02x", pub_key[i]);
    }
    hex[2 * size] = '\0';

    return hex;
}