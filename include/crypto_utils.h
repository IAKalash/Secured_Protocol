#ifndef CRYPTO_UTILITIES
    #define CRYPTO_UTILITIES

    #include <openssl/ec.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
    #include <openssl/hmac.h>
    #include <stdio.h>
    #include <stdlib.h>

    typedef struct KeyPair {
        EC_KEY *key;
        unsigned char *public_key;
        size_t PKsize;
    } KeyPair;

    void error(int); //Errors print
    //2 - allocation failed
    //3 - key generation error

    //Generates an ECDH keys (secp256k1)
    KeyPair *genKeys(void);

    //Frees a KeyPair structure
    void freeKeys(KeyPair *pair);

    //Converts a public key to a hex string
    //(is needed to print it easily)
    char *PKhex(unsigned char *pub_key, size_t size);

    // Computes the ECDH shared secret using own key and your mate's public key
    unsigned char *computeSecret(EC_KEY *own_key, const unsigned char *pub_key, size_t keySize, size_t *secretSize);

    // Derives a symmetric key using HKDF from the shared secret.
    unsigned char *hkdf(const unsigned char *secret, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len);

#endif