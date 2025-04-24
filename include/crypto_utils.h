#ifndef CRYPTO_UTILITIES
    #define CRYPTO_UTILITIES

    #include <openssl/ec.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
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
    void freeKeys(KeyPair *);

    //Converts a public key to a hex string
    char *PKhex(unsigned char *pub_key, size_t size);

#endif