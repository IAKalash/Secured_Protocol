#include "crypto_utils.h"

int main() {
    printf("%lu", OpenSSL_version_num());
    return 0;
}