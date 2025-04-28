#include "crypto_utils.h"

void error(int err) { //Вывод ошибок и завершение программы
    ERR_print_errors_fp(stderr);
    if (err == 2) {
        fprintf(stderr, "Memory allocation failed\n");
    }
    else if (err == 3) {
        fprintf(stderr, "Key generation error\n");
    }
    else if (err == 4) {
        fprintf(stderr, "Secret computation error\n");
    }
    else if (err == 5) {
        fprintf(stderr, "HKDF derivation error\n");
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

    for (size_t i = 0; i < size; ++i) {
        sprintf(&hex[2 * i], "%02x", pub_key[i]);
    }
    hex[2 * size] = '\0';

    return hex;
}

unsigned char *computeSecret(EC_KEY *own_key, const unsigned char *pub_key, size_t keySize, size_t *secretSize) {

    const EC_GROUP *group = EC_KEY_get0_group(own_key);

    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) error(2);

    if (EC_POINT_oct2point(group, pub_point, pub_key, keySize, NULL) != 1) {
        EC_POINT_free(pub_point);
        error(3);
    }

    *secretSize = 32; //фиксированная длина для secp256k1
    unsigned char *secret = malloc(*secretSize);

    size_t secret_check = ECDH_compute_key(secret, *secretSize, pub_point, own_key, NULL);
    if (secret_check != *secretSize) {
        EC_POINT_free(pub_point);
        error(4);
    }

    EC_POINT_free(pub_point);
    return secret;
}

unsigned char *hkdf(const unsigned char *secret, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {

    unsigned char *prk = (unsigned char *)malloc(32); //псевдослучайный ключ
    if (!prk) error(2);
    unsigned int prk_len;

    if (!salt) {
        unsigned char empty_salt[32] = {0};
        HMAC(EVP_sha256(), empty_salt, 32, secret, 32, prk, &prk_len);
    }
    else 
        HMAC(EVP_sha256(), salt, salt_len, secret, 32, prk, &prk_len);

    if (prk_len != 32) {
        free(prk);
        error(5);
    }

    unsigned char *key = (unsigned char *)malloc(32);
    if (!key) {
        free(prk);
        error(2);
    }
    unsigned int key_len;

    if (!info) {
        unsigned char empty_info[32] = {0};
        HMAC(EVP_sha256(), prk, 32, empty_info, 32, key, &key_len);
    }
    else 
        HMAC(EVP_sha256(), prk, 32, info, info_len, key, &key_len);

    free(prk);
    return key;
}