#ifndef CRYPTO_UTILITIES
    #define CRYPTO_UTILITIES

    #include <openssl/ec.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
    #include <openssl/hmac.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #include <stdio.h>
    #include <stdlib.h>

    //A structure for ECDH key pair
    typedef struct KeyPair {
        EC_KEY *key;
        unsigned char *public_key;
        size_t PKsize;
    } KeyPair;

    //Handles errors
    //2 - memory allocation failed
    //3 - key generation error
    //4 - ComputeSecret function error
    //5 - hkdf error
    //6 - Encryption/Decryption error
    //7 - data is corrupted or changed
    void error(int);

    //Generates ECDH keys (secp256k1)
    KeyPair *genKeys(void);

    //Frees a KeyPair structure
    void freeKeys(KeyPair *pair);

    //Converts a public key to a hex string
    //(is needed to print it easily)
    //Returns a hex string
    char *PKhex(unsigned char *pub_key, size_t size);

    //Computes and returns the ECDH shared secret using own key and your mate's public key
    unsigned char *computeSecret(EC_KEY *own_key, const unsigned char *pub_key, size_t keySize, size_t *secretSize);

    //Derives and returns a symmetric key using HKDF from the shared secret.
    unsigned char *hkdf(const unsigned char *secret, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len);

    //Encrypts a message using AES-256-GCM.
    //Returns the lenght of cipher text.
    int encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, unsigned char *out_buffer, unsigned char *tag_buffer);

    //Decrypts a message using AES-256-GCM.
    //Returns the lenght of decrypted text.
    int decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *text, size_t text_len, const unsigned char *tag, unsigned char *out_buffer);

#endif