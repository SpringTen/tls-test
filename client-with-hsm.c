#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#define PORT 4433
#define BUFFER_SIZE 1024

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    ENGINE_cleanup();
    EVP_cleanup();
}

SSL_CTX* create_client_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* 信任服务器证书 */
    // SSL_CTX_load_verify_locations(ctx, "new_device.crt", NULL);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    ENGINE *engine = ENGINE_by_id("pkcs11");
    if (!engine) {
        fprintf(stderr, "PKCS#11 engine load failed\n");
        exit(EXIT_FAILURE);
    }

    /* 配置引擎 */
    ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", "/usr/lib64/pkcs11/libsofthsm2.so", 0);
    ENGINE_ctrl_cmd_string(engine, "PIN", "12345678", 0);
    ENGINE_ctrl_cmd_string(engine, "VERBOSE", NULL, 0);  // 启用详细输出
    ENGINE_ctrl_cmd_string(engine, "DEBUG", "7", 0);     // 最高调试级别
    
    if (!ENGINE_init(engine)) {
        fprintf(stderr, "Engine init failed\n");
        exit(EXIT_FAILURE);
    }

    /* 设置默认引擎 */
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
}

int main() {
    int sock;
    struct sockaddr_in addr;
    
    init_openssl();
    SSL_CTX *ctx = create_client_context();
    configure_client_context(ctx);

    /* 创建 socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    /* 连接服务器 */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    /* 创建 SSL 对象 */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    /* TLS 握手 */
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Client Hello", 12);
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received: %s\n", buf);
    }

    /* 清理 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}