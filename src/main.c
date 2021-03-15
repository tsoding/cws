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

static_assert(sizeof(size_t) == sizeof(uint64_t),
              "Please compile this on 64 bit machine");

// https://www.websocket.org/echo.html
#define HOST "irc-ws.chat.twitch.tv"
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

typedef enum {
    WS_OPCODE_CONT  = 0x0,
    WS_OPCODE_TEXT  = 0x1,
    WS_OPCODE_BIN   = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING  = 0x9,
    WS_OPCODE_PONG  = 0xA,
} Ws_Opcode;

const char *opcode_as_cstr(Ws_Opcode opcode)
{
    switch (opcode) {
    case WS_OPCODE_CONT:
        return "CONT";
    case WS_OPCODE_TEXT:
        return "TEXT";
    case WS_OPCODE_BIN:
        return "BIN";
    case WS_OPCODE_CLOSE:
        return "CLOSE";
    case WS_OPCODE_PING:
        return "PING";
    case WS_OPCODE_PONG:
        return "PONG";
    default:
        return NULL;
    }
}

typedef struct {
    // TODO: no support for CONT frames
    // Ws_Frame *next;
    bool fin;
    Ws_Opcode opcode;
    uint64_t payload_len;
    uint8_t payload[];
} Ws_Frame;

void log_frame(FILE *stream, Ws_Frame *frame)
{
    fprintf(stream, "opcode:      %s\n", opcode_as_cstr(frame->opcode));
    fprintf(stream, "payload_len: %"PRIu64"\n", frame->payload_len);
    fprintf(stream, "payload:     ");
#define RAW_LOG_FRAME
#ifdef RAW_LOG_FRAME
    fwrite(frame->payload, 1, frame->payload_len, stream);
#else
    for (uint64_t i = 0; i < frame->payload_len; ++i) {
        fprintf(stream, "0x%02X ", frame->payload[i]);
    }
#endif
    fprintf(stream, "\n");
}

// TODO: test all executing paths in send_frame
int send_frame(SSL *ssl, Ws_Opcode opcode, const uint8_t *payload, uint64_t payload_len)
{
    // Send FIN and OPCODE
    {
        // NOTE: FIN is always set
        uint8_t data = (1 << 7) | opcode;
        if (SSL_write(ssl, &data, 1) < 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    // Send masked and payload length
    {
        // NOTE: client frames are always masked
        if (payload_len < 126) {
            uint8_t data = (1 << 7) | payload_len;

            if (SSL_write(ssl, &data, sizeof(data)) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        } else if (payload_len <= UINT16_MAX) {
            uint8_t data = (1 << 7) | 126;
            uint8_t len[2] = {
                (payload_len >> 8) & 0xFF,
                payload_len & 0xFF
            };

            if (SSL_write(ssl, &data, sizeof(data)) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            if (SSL_write(ssl, &len, sizeof(len)) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        } else if (payload_len > UINT16_MAX) {
            // TODO: reverse the bytes of 64 bit extended length in read_frame
            uint8_t data = (1 << 7) | 127;

            if (SSL_write(ssl, &data, sizeof(data)) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            if (SSL_write(ssl, &payload_len, sizeof(payload_len)) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
    }

    uint8_t mask[4] = {0};

    // Generate and send mask
    {
        for (size_t i = 0; i < 4; ++i) {
            mask[i] = rand() % 256;
        }

        if (SSL_write(ssl, mask, sizeof(mask)) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

    }

    // Mask the payload and send it
    {
        uint64_t i = 0;
        while (i < payload_len) {
            uint8_t chunk[1024];
            uint64_t chunk_size = 0;
            while (i < payload_len && chunk_size < sizeof(chunk)) {
                chunk[chunk_size] = payload[i] ^ mask[i % 4];
                chunk_size += 1;
                i += 1;
            }
            if (SSL_write(ssl, chunk, chunk_size) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
    }

    return 0;
}

// TODO: test all executing paths in read_frame
Ws_Frame *read_frame(SSL *ssl)
{
#define FIN(header)         ((header)[0] >> 7)
#define OPCODE(header)      ((header)[0] & 0xF)
#define MASK(header)        ((header)[1] >> 7)
#define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

    Ws_Frame *frame = NULL;

    uint8_t header[2] = {0};

    // Read the header
    if (SSL_read(ssl, header, sizeof(header)) <= 0) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    uint64_t payload_len = 0;

    // Parse the payload length
    {
        uint8_t len = PAYLOAD_LEN(header);
        switch (len) {
        case 126: {
            uint8_t ext_len[2] = {0};
            if (SSL_read(ssl, &ext_len, sizeof(ext_len)) <= 0) {
                ERR_print_errors_fp(stderr);
                goto error;
            }
            payload_len = (ext_len[0] << 8) | ext_len[1];
        }
        break;
        case 127: {
            // TODO: reverse the bytes of 64 bit extended length in read_frame
            uint64_t ext_len = 0;
            if (SSL_read(ssl, &ext_len, sizeof(ext_len)) <= 0) {
                ERR_print_errors_fp(stderr);
                goto error;
            }
            payload_len = ext_len;
        }
        break;
        default:
            payload_len = len;
        }
    }

    // Read the mask
    // TODO: the server may not send masked frames
    {
        uint32_t mask = 0;
        bool masked = MASK(header);

        if (masked) {
            if (SSL_read(ssl, &mask, sizeof(mask)) <= 0) {
                ERR_print_errors_fp(stderr);
                goto error;
            }
        }
    }

    // Read the payload
    {
        frame = malloc(sizeof(Ws_Frame) + payload_len);
        if (!frame) {
            fprintf(stderr, "ERROR: Could not allocate memory for such a big frame gachiHYPER\n");
            goto error;
        }

        frame->fin = FIN(header);
        frame->opcode = OPCODE(header);
        frame->payload_len = payload_len;

        if (SSL_read(ssl, frame->payload, frame->payload_len) <= 0) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
    }

    return frame;
error:
    if (frame) {
        free(frame);
    }
    return NULL;
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
            // TODO: don't recreate socket on each attempt
            // Just create a single socket with the appropriate family and type
            // and keep using it.
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

    // WebSocket handshake with the server
    {
        const char *handshake =
            "GET / HTTP/1.1\r\n"
            "Host: "HOST"\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            // TODO: custom WebSocket key
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";
        const size_t handshake_size = strlen(handshake);
        SSL_write(ssl, handshake, handshake_size);

        // TODO: the server handshake is literally ignored
        // Right now we are making this assumptions:
        // 1. The server sent the successful handshake
        // 2. Nothing is sent after the handshake so we can distinguish the frames
        // 3. The handshake fits into sizeof(buffer)
        char buffer[1024];
        ssize_t buffer_size = SSL_read(ssl, buffer, sizeof(buffer));
        fwrite(buffer, 1, buffer_size, stdout);
        printf("------------------------------\n");
        if (buffer_size < 2 ||
                buffer[buffer_size - 2] != '\r' ||
                buffer[buffer_size - 1] != '\n') {
            fprintf(stderr, "ERROR: Server response is sus ngl\n");
            goto error;
        }
    }

    // Receiving frames
    {
        Ws_Frame *frame = read_frame(ssl);
        while (frame != NULL) {
            log_frame(stdout, frame);
            if (frame->opcode == WS_OPCODE_PING) {
                send_frame(ssl,
                           WS_OPCODE_PONG,
                           frame->payload,
                           frame->payload_len);
            }
            free(frame);
            frame = read_frame(ssl);
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

// TODO: successfully send and recieve messages using Discord API
// TODO: Socket-like API
// TODO: Turn this code into STB-style library
