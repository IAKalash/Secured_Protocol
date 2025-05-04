#include "crypto_utils.h"

void error(int err) { //Обработка и вывод ошибок
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
    else if (err == 6) {
        fprintf(stderr, "Encryption/Decryption error\n");
    }
    else if (err == 7) {
        fprintf(stderr, "Wrong tag! The data is corrupted or changed\n");
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

char *PKhex(unsigned char *pub_key, size_t size) { //Перевод в hex-строку
    char *hex = (char *)malloc(2 * size + 1);
    if (!hex) error(2);

    for (size_t i = 0; i < size; ++i) {
        sprintf(&hex[2 * i], "%02x", pub_key[i]);
    }
    hex[2 * size] = '\0';

    return hex;
}

unsigned char *computeSecret(EC_KEY *own_key, const unsigned char *pub_key, size_t keySize, size_t *secretSize) { //Расчёт секрета

    const EC_GROUP *group = EC_KEY_get0_group(own_key);  //Извлечение группы кривой

    EC_POINT *pub_point = EC_POINT_new(group);           //Инициализация точки на кривой
    if (!pub_point) error(2);

    if (EC_POINT_oct2point(group, pub_point, pub_key, keySize, NULL) != 1) { //Восстановление точки из публичного ключа
        EC_POINT_free(pub_point);
        error(3);
    }

    *secretSize = 32; //фиксированная длина для secp256k1
    unsigned char *secret = malloc(*secretSize);

    size_t secret_check = ECDH_compute_key(secret, *secretSize, pub_point, own_key, NULL); //Расчёт секрета
    if (secret_check != *secretSize) {
        EC_POINT_free(pub_point);
        error(4);
    }

    EC_POINT_free(pub_point);
    return secret;
}

//Получение ключа из секрета (шифрование с помощью SHA256)
unsigned char *hkdf(const unsigned char *secret, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {

    unsigned char *prk = (unsigned char *)malloc(32); //псевдослучайный ключ
    if (!prk) error(2);
    unsigned int prk_len;

    if (!salt) {
        unsigned char empty_salt[32] = {0};
        HMAC(EVP_sha256(), empty_salt, 32, secret, 32, prk, &prk_len); //Получение псевдослучайного ключа (Соль отсутствует)
    }
    else 
        HMAC(EVP_sha256(), salt, salt_len, secret, 32, prk, &prk_len); //Получение псевдослучайного ключа из соли и секрета

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
        HMAC(EVP_sha256(), prk, 32, empty_info, 32, key, &key_len);   //Получение ключа из ПСК
    }
    else 
        HMAC(EVP_sha256(), prk, 32, info, info_len, key, &key_len);   //Получение ключа из ПСК и метаданных

    free(prk);
    return key;
}

//Шифрование сообщения
int encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, unsigned char *out_buffer, unsigned char *tag_buffer) {
    
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new(); //Создание контекста шифрования
    if (!context) error(2);

    if (EVP_EncryptInit(context, EVP_aes_256_gcm(), key, iv) != 1) error(6); //Инициализация контекста под текущий шифр

    int out_len = 0;
    int temp_len;
    if (EVP_EncryptUpdate(context, out_buffer, &temp_len, text, text_len) != 1) error(6); //Шифрование сообщения
    out_len += temp_len;

    if (EVP_EncryptFinal_ex(context, out_buffer, &temp_len) != 1) error(6);  //Завершение шифрования
    out_len += temp_len;

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag_buffer) != 1) error(6);//Извлечение тега

    EVP_CIPHER_CTX_free(context);
    return out_len;
}

int decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, const unsigned char *tag, unsigned char *out_buffer) {
    
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new(); //Создание контекста
    if (!context) error(2);

    if (EVP_DecryptInit(context, EVP_aes_256_gcm(), key, iv) != 1) error(6); //Инициализация контекста под текущий шифр

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) error(6); //Установка тега в контекст

    int out_len = 0;
    int temp_len;
    if (EVP_DecryptUpdate(context, out_buffer, &temp_len, text, text_len) != 1) error(6);  //Дешифровка текста
    out_len += temp_len;

    if (EVP_DecryptFinal_ex(context, out_buffer, &temp_len) != 1) error(7); //Завершение дешифровки и проверка тега на подлинность
    out_len += temp_len;

    EVP_CIPHER_CTX_free(context);
    return out_len;
}