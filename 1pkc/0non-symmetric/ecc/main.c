// main.c
#include <stdio.h>
#include <string.h>
#include "ecc-sv.h"

int main() {
    const char *message = "Hello, ECC!";
    unsigned int sig_len;

    // 生成 ECC 密钥对
    ECCKeyPair *keypair = ecc_generate_keypair();
    if (!keypair) {
        fprintf(stderr, "Key pair generation failed\n");
        return 1;
    }

    // 签名
    unsigned char *signature = ecc_sign(keypair, (unsigned char *)message, strlen(message), &sig_len);
    if (!signature) {
        fprintf(stderr, "Signing failed\n");
        ecc_free_keypair(keypair);
        return 1;
    }

    // 验证签名
    if (ecc_verify(keypair, (unsigned char *)message, strlen(message), signature, sig_len) == 0) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed!\n");
    }

    // 清理
    free(signature);
    ecc_free_keypair(keypair);
    return 0;
}
