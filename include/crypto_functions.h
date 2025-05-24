#ifndef CRYPTO_UTILITIES
    #define CRYPTO_UTILITIES

    #include <stdio.h>
    #include <stdlib.h>
    #include <openssl/ec.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
    #include <openssl/hmac.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>

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
    //8 - ECDSA computation failed
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

    //Signs a message using ECDSA with a private key.
    void ecdsa_sign(EC_KEY *key, const unsigned char *message, size_t message_len, unsigned char *signature_buffer, unsigned int *signature_len_buffer);

    //Verifies an ECDSA signature using a public key.
    //Returns 1 - sign verified successfully,
    //        0 - sign is incorrect,
    //       -1 - error.
    int ecdsa_verify(EC_KEY *own_key, const unsigned char *pub_key, size_t pub_key_len, const unsigned char *message, size_t message_len, const unsigned char *signature, unsigned int signature_len);

#endif