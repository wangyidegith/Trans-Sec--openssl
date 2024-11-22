#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *generateRSAKeyPair() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    // 初始化密钥生成
    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

    // 设置密钥长度
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();

    EVP_PKEY *pkey = NULL;
    // 生成密钥对
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx); // 释放上下文
    return pkey;
}

unsigned char *signMessage(EVP_PKEY *pkey, const char *message, unsigned int *sigLen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *signature = malloc(EVP_PKEY_size(pkey));

    if (!ctx) handleErrors();

    if (EVP_SignInit(ctx, EVP_sha256()) != 1) handleErrors();
    if (EVP_SignUpdate(ctx, message, strlen(message)) != 1) handleErrors();
    if (EVP_SignFinal(ctx, signature, sigLen, pkey) != 1) handleErrors();

    EVP_MD_CTX_free(ctx);
    return signature;
}

int verifySignature(EVP_PKEY *pkey, const char *message, unsigned char *signature, unsigned int sigLen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result;

    if (!ctx) handleErrors();

    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) handleErrors();
    if (EVP_VerifyUpdate(ctx, message, strlen(message)) != 1) handleErrors();
    result = EVP_VerifyFinal(ctx, signature, sigLen, pkey);

    EVP_MD_CTX_free(ctx);
    return result; // 1 for valid, 0 for invalid
}

int main() {
    // 生成 RSA 密钥对
    EVP_PKEY *pkey = generateRSAKeyPair();

    // 签名消息
    const char *message = "Hello, this is a signed message.";
    unsigned int sigLen;
    unsigned char *signature = signMessage(pkey, message, &sigLen);

    // 验证签名
    int verifyResult = verifySignature(pkey, message, signature, sigLen);
    if (verifyResult == 1) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }

    // 清理
    free(signature);
    EVP_PKEY_free(pkey); // 释放 EVP_PKEY
    return 0;
}

