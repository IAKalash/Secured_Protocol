#include "crypto_functions.h"

//Handles errors and gives additional info
void error(int err) {
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
    else if (err == 8) {
        fprintf(stderr, "ECDSA computation failed\n");
    }
    exit(err);
}

//Generates ECDH KeyPair on the curve
KeyPair *genKeys(void) {

    KeyPair *keys = (KeyPair *)calloc(1, sizeof(KeyPair));
    if (!keys) error(2);

    //Generation of new object for secp256k1 curve
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1); 
    if (!key) error(3);

    //Keys generation
    if (!EC_KEY_generate_key(key)) error(3); 

    //Getting public key
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    //Getting curve group
    const EC_GROUP *group = EC_KEY_get0_group(key);

    //Computation of size of buffer for public key
    size_t size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (!size) error(3);

    unsigned char *public_key = (unsigned char *)malloc(size);
    if (!public_key) error(2);

    //Filling of buffer key by data octets
    size_t check = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, public_key, size, NULL);
    if (check != size) error(3);

    //Filling and returning the structure
    keys->key = key; 
    keys->public_key = public_key;
    keys->PKsize = size;

    return keys;
}

//Frees a KeyPair structure
void freeKeys(KeyPair *pair) {
    if (pair) {
        EC_KEY_free(pair->key);
        free(pair->public_key);
        free(pair);
    }
}

//Translates a string into hex-string
char *PKhex(unsigned char *pub_key, size_t size) {
    char *hex = (char *)malloc(2 * size + 1);
    if (!hex) error(2);

    for (size_t i = 0; i < size; ++i) {
        sprintf(&hex[2 * i], "%02x", pub_key[i]);
    }
    hex[2 * size] = '\0';

    return hex;
}

//Computes a secret
unsigned char *computeSecret(EC_KEY *own_key, const unsigned char *pub_key, size_t keySize, size_t *secretSize) {
    
    //getting curve group
    const EC_GROUP *group = EC_KEY_get0_group(own_key);

    //Initialization of a point on the curve
    EC_POINT *pub_point = EC_POINT_new(group);           
    if (!pub_point) error(2);

    //Getting a point from public key
    if (EC_POINT_oct2point(group, pub_point, pub_key, keySize, NULL) != 1) {
        EC_POINT_free(pub_point);
        error(3);
    }

    //32 bytes - fixed size of secret for secp256k1 curve
    *secretSize = 32;
    unsigned char *secret = malloc(*secretSize);

    //Secret computation
    size_t secret_check = ECDH_compute_key(secret, *secretSize, pub_point, own_key, NULL);
    if (secret_check != *secretSize) {
        EC_POINT_free(pub_point);
        error(4);
    }

    EC_POINT_free(pub_point);
    return secret;
}

//Gets a key from secret (encrypting via SHA256)
unsigned char *hkdf(const unsigned char *secret, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {
    
    //Pseudo-random key
    unsigned char *prk = (unsigned char *)malloc(32);
    if (!prk) error(2);
    unsigned int prk_len;

    //Getting a PRK (without salt)
    if (!salt) {
        unsigned char empty_salt[SHA256_DIGEST_LENGTH] = {0};
        HMAC(EVP_sha256(), empty_salt, SHA256_DIGEST_LENGTH, secret, SHA256_DIGEST_LENGTH, prk, &prk_len);
    }
    //Getting a PRK from secret with salt
    else 
        HMAC(EVP_sha256(), salt, salt_len, secret, SHA256_DIGEST_LENGTH, prk, &prk_len);

    if (prk_len != SHA256_DIGEST_LENGTH) {
        free(prk);
        error(5);
    }

    unsigned char *key = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    if (!key) {
        free(prk);
        error(2);
    }
    unsigned int key_len;

    //Getting a key from PRK
    if (!info) {
        unsigned char empty_info[SHA256_DIGEST_LENGTH] = {0};
        HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, empty_info, SHA256_DIGEST_LENGTH, key, &key_len);
    }
    //Getting a key from PRK using additional metadata
    else 
        HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, info, info_len, key, &key_len);

    free(prk);
    return key;
}

//Encrypts the message
int encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, unsigned char *out_buffer, unsigned char *tag_buffer) {
    
    //Making a context of cipher
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) error(2);

    //Initialization of context for AES256
    if (EVP_EncryptInit(context, EVP_aes_256_gcm(), key, iv) != 1) error(6);

    int out_len = 0;
    int temp_len;

    //Message encryption
    if (EVP_EncryptUpdate(context, out_buffer, &temp_len, text, text_len) != 1) error(6);
    out_len += temp_len;

    //End of encryption
    if (EVP_EncryptFinal_ex(context, out_buffer, &temp_len) != 1) error(6);
    out_len += temp_len;

    //Getting a tag from context
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag_buffer) != 1) error(6);

    EVP_CIPHER_CTX_free(context);
    return out_len;
}

//Decrypts the message
int decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, const unsigned char *tag, unsigned char *out_buffer) {
    
    //Making a context of cipher
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) error(2);

    //Context initialization for AES256
    if (EVP_DecryptInit(context, EVP_aes_256_gcm(), key, iv) != 1) error(6);

    //Putting a tag into context
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) error(6);

    int out_len = 0;
    int temp_len;
    
    //Message decryption
    if (EVP_DecryptUpdate(context, out_buffer, &temp_len, text, text_len) != 1) error(6);
    out_len += temp_len;

    //End of decryption and tag checkout
    if (EVP_DecryptFinal_ex(context, out_buffer, &temp_len) != 1) error(7);
    out_len += temp_len;

    EVP_CIPHER_CTX_free(context);
    return out_len;
}

//Makes an ECDSA sign
void ecdsa_sign(EC_KEY *key, const unsigned char *msg, size_t msg_len, unsigned char *sign, unsigned int *sign_len) {
    
    //Making a hash of message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, hash);

    //Generation of ECDSA signature
    if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, sign, sign_len, key) != 1) error(8);
}

//Verifies an ECDSA sign
int ecdsa_verify(EC_KEY *own_key, const unsigned char *pub_key, size_t pub_key_len, const unsigned char *msg, size_t msg_len, const unsigned char *sign, unsigned int sign_len) {

    //Getting a curve group
    const EC_GROUP *group = EC_KEY_get0_group(own_key);

    //Partial recovery of EC_KEY for verification:
    EC_KEY *pub_ec_key = EC_KEY_new();
    if (!pub_ec_key) error(2);

    //1. Group recovery
    if (EC_KEY_set_group(pub_ec_key, group) != 1) {
        EC_KEY_free(pub_ec_key);
        error(8);
    }

    //Initialization of a point on the curve
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        EC_KEY_free(pub_ec_key);
        error(2);
    }

    //2. A point recovery from a public key
    if (EC_POINT_oct2point(group, pub_point, pub_key, pub_key_len, NULL) != 1) {
        EC_KEY_free(pub_ec_key);
        EC_POINT_free(pub_point);
        error(8);
    }

    //Recovered EC_KEY
    if (EC_KEY_set_public_key(pub_ec_key, pub_point) != 1) {
        EC_KEY_free(pub_ec_key);
        EC_POINT_free(pub_point);
        error(8);
    }

    //Making a hash from a message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, hash);

    //Key verification
    int res = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, sign, sign_len, pub_ec_key);

    EC_KEY_free(pub_ec_key);
    EC_POINT_free(pub_point);

    return res;
}