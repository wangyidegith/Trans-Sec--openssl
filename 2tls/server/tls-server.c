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
    // old three of them
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    // 0 pre version
    const SSL_METHOD *method;
    method = TLS_method();
    // 1 create ssl context
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_new");
        ERR_print_errors_fp(stderr);
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

    // 3 load cert and sk
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

    // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);   // dont verify client, surely it is unneccesary, because it was originally non-verify except you use SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL) explicitly.

    // 4 enable cret verify 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // 5 load client-cert
    if (SSL_CTX_load_verify_locations(ctx, "client.crt", NULL) != 1) {
        perror("SSL_CTX_load_verify_locations");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

int create_listener() {   // please use yours
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int main() {
    // 0 pre
    // (0) init openssl
    init_openssl();
    // (1) create ssl context
    SSL_CTX* ctx = create_context();
    // (2) create listen socket
    int sockfd = create_listener();

    printf("Waiting for connections...\n");

    // 1 main-while
    int client_sock;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;
    while (1) {
        // (1) accept
        client_sock = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        // (2) establish contact between ssl and socket
        // a create ssl object accoiding to ctx
        ssl = SSL_new(ctx);
        // b establish contact
        SSL_set_fd(ssl, client_sock);

        // (3) four handshake
        char buffer[BUFFER_SIZE];
        int bytes;
        if (SSL_accept(ssl) < 0) {
            perror("SSL_accept");
            ERR_print_errors_fp(stderr);
        } else {
            // data-process imitate
            bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes < 0) {
                perror("SSL_read");
                ERR_print_errors_fp(stderr);
            } else if (bytes == 0) {
                printf("peer closed.\n");
            } else {
                buffer[bytes] = '\0';
                printf("Received: %s\n", buffer);
                const char *reply = "Hello from server!";
                SSL_write(ssl, reply, strlen(reply));
            }
        }

        // (4) due to arch
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    // 2 free resource corresponding to "0 pre"
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}

