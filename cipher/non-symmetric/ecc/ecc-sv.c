#include "ecc-sv.h"
#include <openssl/err.h>
#include <openssl/ec.h>

// 生成 ECC 密钥对
ECCKeyPair *ecc_generate_keypair() {
    ECCKeyPair *keypair = malloc(sizeof(ECCKeyPair));
    if (!keypair) return NULL;

    // 创建上下文
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        free(keypair);
        return NULL;
    }

    // 生成密钥
    if (EVP_PKEY_keygen(ctx, &keypair->private_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(keypair);
        return NULL;
    }

    // 获取公钥
    keypair->public_key = EVP_PKEY_dup(keypair->private_key);

    EVP_PKEY_CTX_free(ctx);
    return keypair;
}

// 释放密钥对
void ecc_free_keypair(ECCKeyPair *keypair) {
    if (keypair) {
        EVP_PKEY_free(keypair->private_key);
        EVP_PKEY_free(keypair->public_key);
        free(keypair);
    }
}

// 签名
unsigned char *ecc_sign(ECCKeyPair *keypair, const unsigned char *data, size_t data_len, unsigned int *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *sig = NULL;

    if (EVP_SignInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_SignUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    sig = malloc(EVP_PKEY_size(keypair->private_key));
    if (!sig) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (EVP_SignFinal(ctx, sig, sig_len, keypair->private_key) != 1) {
        free(sig);
        sig = NULL;
    }

    EVP_MD_CTX_free(ctx);
    return sig;
}

// 验证签名
int ecc_verify(ECCKeyPair *keypair, const unsigned char *data, size_t data_len, const unsigned char *sig, unsigned int sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result;

    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_VerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1; // Error
    }

    result = EVP_VerifyFinal(ctx, sig, sig_len, keypair->public_key);
    EVP_MD_CTX_free(ctx);

    return (result == 1) ? 0 : 1; // 0 for success, 1 for failure
}
