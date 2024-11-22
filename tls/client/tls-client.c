#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433
#define BUFFER_SIZE 1024

void init_openssl() {
    // old 3 of then
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    // 0 pre version
    const SSL_METHOD *method = TLS_method();
    // 1 create ssl context
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_NEW");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    // 2 limit version to high-sec
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    /*
    const STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        printf("Supported cipher: %s\n", SSL_CIPHER_get_name(cipher));
    }
    */

    // 3 enable cret verify 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // 4 load server-cert
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) != 1) {
        perror("SSL_CTX_load_verify_locations");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 5 use cert to let server verify client
    SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "client-private.key", SSL_FILETYPE_PEM);

    return ctx;
}

int main() {
    // 0 pre
    // (0) init openssl
    init_openssl();
    // (1) create ssl context
    SSL_CTX *ctx = create_context();
    // (2) create connect socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "101.133.228.115", &server_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 1 establish contact in ssl-obj and socket-fd
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 2 four handshake
    SSL_connect(ssl);

    // 3 data-process imitate
    const char *msg = "Hello from client!";
    SSL_write(ssl, msg, strlen(msg));
    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    buffer[bytes] = '\0';
    printf("Received: %s\n", buffer);

    // 4 free resource
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

