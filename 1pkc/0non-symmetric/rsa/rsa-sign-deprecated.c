#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA* generateRSAKey(int bits) {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    bne = BN_new();
    if (BN_set_word(bne, e) != 1) handleErrors();

    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1) handleErrors();

    BN_free(bne);
    return rsa;
}

void saveKeyToFile(RSA *rsa, const char *pubFilename, const char *privFilename) {
    FILE *pubFile = fopen(pubFilename, "wb");
    FILE *privFile = fopen(privFilename, "wb");
    if (!pubFile || !privFile) handleErrors();

    PEM_write_RSAPublicKey(pubFile, rsa);
    PEM_write_RSAPrivateKey(privFile, rsa, NULL, NULL, 0, NULL, NULL);
    
    fclose(pubFile);
    fclose(privFile);
}

unsigned char* signMessage(RSA *rsa, const char *message, unsigned int *signatureLen) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *signature = malloc(RSA_size(rsa));   // TODO: modify this to out-arg
    
    SHA256((unsigned char*)message, strlen(message), hash);
    
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signatureLen, rsa) != 1) {
        handleErrors();
    }
    
    return signature;
}

int verifySignature(RSA *rsa, const char *message, unsigned char *signature, unsigned int signatureLen) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    
    return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signatureLen, rsa);
}

int main() {
    int bits = 2048;
    RSA *rsa = generateRSAKey(bits);
    
    saveKeyToFile(rsa, "public.pem", "private.pem");

    const char *message = "This is a message to be signed.";
    unsigned int signatureLen;
    
    unsigned char *signature = signMessage(rsa, message, &signatureLen);
    printf("Signature generated successfully.\n");

    if (verifySignature(rsa, message, signature, signatureLen) == 1) {   // TODO: due to test, so here use a RSA obj include private-key, but in actual case, this is impossible, then actual case is : prover send its public-key to verifier, and verifier recv prover's public-key, then make this public-key to RSA obj for RSA_verify
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }

    free(signature);
    RSA_free(rsa);
    return 0;
}

