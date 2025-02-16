#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433
#define SERVER_IP "127.0.0.1"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // 加载CA证书（如果需要验证服务器证书）
    // SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // 初始化OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    // 创建套接字
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 将IPv4地址从点分十进制转换为二进制形式
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return -1;
    }

    char *hello = "Hello from client";
    SSL_write(ssl, hello, strlen(hello));
    printf("Hello message sent\n");

    char buffer[1024] = {0};
    int valread = SSL_read(ssl, buffer, 1024);
    if (valread > 0) {
        printf("Received from server: %s\n", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    close(sock);
    return 0;
}