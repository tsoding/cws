#define _POSIX_C_SOURCE 200112L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "./sv.h"

#define CWS_IMPLEMENTATION
#include "./cws.h"

static_assert(sizeof(size_t) == sizeof(uint64_t),
              "Please compile this on 64 bit machine");

// https://www.websocket.org/echo.html
#define HOST "echo.websocket.org"
// #define HOST "irc-ws.chat.twitch.tv"
// #define SERVICE "80"
#define SERVICE "443"

char *slurp_file(const char *file_path)
{
    FILE *f = NULL;
    char *buffer = NULL;

    f = fopen(file_path, "r");
    if (f == NULL) {
        goto error;
    }

    if (fseek(f, 0, SEEK_END) < 0) {
        goto error;
    }

    long m = ftell(f);
    if (m < 0) {
        goto error;
    }

    buffer = malloc((size_t) m + 1);
    if (buffer == NULL) {
        goto error;
    }

    if (fseek(f, 0, SEEK_SET) < 0) {
        goto error;
    }

    fread(buffer, 1, (size_t) m, f);
    if (ferror(f)) {
        goto error;
    }
    buffer[m] = '\0';

// ok:
    fclose(f);

    return buffer;

error:
    if (f) {
        fclose(f);
    }

    if (buffer) {
        free(buffer);
    }

    return NULL;
}

char *shift(int *argc, char ***argv)
{
    assert(*argc > 0);
    char *result = **argv;
    *argv += 1;
    *argc -= 1;
    return result;
}

#define RAW_LOG

void log_frame(FILE *stream, Cws_Frame *frame)
{
    fprintf(stream, "opcode:      %s\n", opcode_name(frame->opcode).cstr);
    fprintf(stream, "payload_len: %"PRIu64"\n", frame->payload_len);
    fprintf(stream, "payload:     ");
#ifdef RAW_LOG
    fwrite(frame->payload, 1, frame->payload_len, stream);
#else
    for (uint64_t i = 0; i < frame->payload_len; ++i) {
        fprintf(stream, "0x%02X ", frame->payload[i]);
    }
#endif
    fprintf(stream, "\n");
}

void log_message(FILE *stream, Cws_Message message)
{
    fprintf(stream, "message kind: %s\n", opcode_name((Cws_Opcode) message.kind).cstr);
    for (Cws_Message_Chunk *iter = message.chunks;
            iter != NULL;
            iter = iter->next) {
        fprintf(stream, "chunk_payload_len: %"PRIu64"\n", iter->payload_len);
#ifdef RAW_LOG
        fwrite(iter->payload, 1, iter->payload_len, stream);
#else
        for (uint64_t i = 0; i < iter->payload_len; ++i) {
            fprintf(stream, "0x%02X ", iter->payload[i]);
        }
#endif
        fprintf(stream, "\n");
    }
    printf("------------------------------\n");
}

ssize_t cws_ssl_read(void *socket, void *buf, size_t count)
{
    return SSL_read((SSL*) socket, buf, count);
}

ssize_t cws_ssl_write(void *socket, const void *buf, size_t count)
{
    return SSL_write((SSL*) socket, buf, count);
}

void *cws_malloc(void *ator, size_t size)
{
    (void) ator;
    return malloc(size);
}

void cws_free(void *ator, void *data, size_t size)
{
    (void) ator;
    (void) size;
    free(data);
}

int main(void)
{
    // Resources to destroy at the end of the function
    int sd = -1;
    struct addrinfo *addrs = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    // Establish plain connection
    {
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(HOST, SERVICE, &hints, &addrs) < 0) {
            fprintf(stderr, "ERROR: Could not resolved address of `"HOST"`\n");
            goto error;
        }

        for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next) {
            sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

            if (sd == -1) {
                break;
            }

            if (connect(sd, addr->ai_addr, addr->ai_addrlen) == 0) {
                break;
            }

            close(sd);
            sd = -1;
        }

        if (sd == -1) {
            fprintf(stderr, "Could not connect to %s:%s: %s",
                    HOST, SERVICE, strerror(errno));
            goto error;
        }
    }

    // Initialize SSL
    {
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            fprintf(stderr, "ERROR: could not initialize SSL context\n");
            ERR_print_errors_fp(stderr);
            goto error;
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "ERROR: could not create SSL connection\n");
            ERR_print_errors_fp(stderr);
            goto error;
        }

        if (!SSL_set_fd(ssl, sd)) {
            fprintf(stderr, "ERROR: could not setup SSL connection\n");
            ERR_print_errors_fp(stderr);
            goto error;
        }

        if (SSL_connect(ssl) <= 0) {
            fprintf(stderr, "ERROR: could not establish SSL connection\n");
            ERR_print_errors_fp(stderr);
            goto error;
        }
    }

    Cws cws = {
        .socket = ssl,
        .read = cws_ssl_read,
        .write = cws_ssl_write,
        .alloc = cws_malloc,
        .free = cws_free,
    };

    // WebSocket handshake with the server
    if (cws_handshake(&cws, HOST) < 0) {
        fprintf(stderr, "ERROR: Server response is sus ngl\n");
        goto error;
    }

    // Receiving frames
    {
        const char *hello = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        cws_send_message(&cws, CWS_MESSAGE_BIN, (uint8_t*)hello, strlen(hello), 100);
        Cws_Message message = {0};
        int ret = cws_read_message(&cws, &message);
        while (ret == 0) {
            log_message(stdout, message);
            cws_free_message(&cws, &message);
            sleep(1);
            cws_send_message(&cws, CWS_MESSAGE_BIN, (uint8_t*)hello, strlen(hello), 100);
            ret = cws_read_message(&cws, &message);
        }
    }

    freeaddrinfo(addrs);
    close(sd);
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
error:
    if (addrs != NULL) {
        freeaddrinfo(addrs);
    }
    if (sd != -1) {
        close(sd);
    }
    if (ssl != NULL) {
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    return -1;
}
// TODO: Autobahn test suite
// https://crossbar.io/docs/WebSocket-Compliance-Testing/
