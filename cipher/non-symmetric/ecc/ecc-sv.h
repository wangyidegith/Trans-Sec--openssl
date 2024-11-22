#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include <openssl/evp.h>

typedef struct {
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
} ECCKeyPair;

// 函数原型
ECCKeyPair *ecc_generate_keypair();
void ecc_free_keypair(ECCKeyPair *keypair);
unsigned char *ecc_sign(ECCKeyPair *keypair, const unsigned char *data, size_t data_len, unsigned int *sig_len);
int ecc_verify(ECCKeyPair *keypair, const unsigned char *data, size_t data_len, const unsigned char *sig, unsigned int sig_len);

#endif // ECC_SIGN_H
