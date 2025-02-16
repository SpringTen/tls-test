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

SSL_CTX* create_server_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 强制使用引擎 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    ENGINE *engine = ENGINE_by_id("pkcs11");
    if (!engine) {
        fprintf(stderr, "PKCS#11 engine load failed\n");
        exit(EXIT_FAILURE);
    }

    /* 配置引擎参数 */
    ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", "/usr/lib64/pkcs11/libsofthsm2.so", 0);
    ENGINE_ctrl_cmd_string(engine, "PIN", "12345678", 0);
    ENGINE_ctrl_cmd_string(engine, "VERBOSE", NULL, 0);  // 启用详细输出
    ENGINE_ctrl_cmd_string(engine, "DEBUG", "7", 0);     // 最高调试级别
    
    if (!ENGINE_init(engine)) {
        fprintf(stderr, "Engine init failed\n");
        exit(EXIT_FAILURE);
    }

    /* 设置为默认引擎 */
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);

    /* 加载证书链 */
    if (SSL_CTX_use_certificate_file(ctx, "new_device.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 绑定 HSM 中的私钥 */
    EVP_PKEY *pkey = ENGINE_load_private_key(engine, "pkcs11:token=MyToken;object=MyKey;type=private", NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "HSM private key bind failed\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 验证密钥匹配 */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Certificate-key mismatch\n");
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sock, client;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    init_openssl();
    SSL_CTX *ctx = create_server_context();
    configure_server_context(ctx);

    /* 创建 socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* 绑定和监听 */
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    listen(sock, 5);
    printf("Server listening on port %d\n", PORT);

    /* 接受连接 */
    if ((client = accept(sock, (struct sockaddr*)&addr, &addr_len)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    /* 创建 SSL 对象 */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    /* TLS 握手 */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received: %s\n", buf);
        SSL_write(ssl, "Server Response", 15);
    }

    /* 清理 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}