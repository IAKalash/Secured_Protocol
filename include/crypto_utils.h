#ifndef CRYPTO_UTILITIES
    #define CRYPTO_UTILITIES

    #include <openssl/ec.h>
    #include <openssl/err.h>
    #include <stdio.h>
    #include <stdlib.h>

    typedef struct Keys {
        EC_KEY *key;
        unsigned char* public_key;
        int PCsize;
    } Keys;

    int ErrSSL();

    Keys *genKeys();

    void freeKeys();

    char *PChex();

#endif