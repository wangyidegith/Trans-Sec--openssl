#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>

void main() {
    unsigned char *key = (unsigned char *)"secret";
    unsigned char *data = (unsigned char *)"message";
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    // 计算 HMAC
    HMAC(EVP_sha256(), key, strlen((char *)key), data, strlen((char *)data), hmac, &hmac_len);

    // 输出 HMAC
    printf("HMAC: ");
    for (int i = 0; i < hmac_len; i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");
}
