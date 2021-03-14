#define _POSIX_C_SOURCE 200112L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

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
// #define HOST "echo.websocket.org"
#define SERVICE "80"

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
    fprintf(stream, "opcode:  %s\n", opcode_as_cstr(frame->opcode));
    fprintf(stream, "payload: ");
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


int send_frame(int sd, Ws_Opcode opcode, const uint8_t *payload, uint64_t payload_len)
{
    // Send FIN and OPCODE
    {
        // NOTE: FIN is always set
        uint8_t data = (1 << 7) | opcode;
        if (write(sd, &data, 1) < 0) {
            fprintf(stderr, "ERROR: could not send frame: %s\n",
                    strerror(errno));
            return -1;
        }
    }

    // Send masked and payload length
    {
        // NOTE: client frames are always masked
        if (payload_len < 126) {
            uint8_t data = (1 << 7) | payload_len;

            if (write(sd, &data, sizeof(data)) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
                return -1;
            }
        } else if (payload_len <= UINT16_MAX) {
            uint8_t data = (1 << 7) | 126;
            uint16_t len = payload_len;

            if (write(sd, &data, sizeof(data)) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
                return -1;
            }

            if (write(sd, &len, sizeof(len)) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
                return -1;
            }
        } else if (payload_len > UINT16_MAX) {
            uint8_t data = (1 << 7) | 127;

            if (write(sd, &data, sizeof(data)) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
                return -1;
            }

            if (write(sd, &payload_len, sizeof(payload_len)) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
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

        if (write(sd, mask, sizeof(mask)) < 0) {
            fprintf(stderr, "ERROR: could not send frame: %s\n",
                    strerror(errno));
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
            if (write(sd, chunk, chunk_size) < 0) {
                fprintf(stderr, "ERROR: could not send frame: %s\n",
                        strerror(errno));
                return -1;
            }
        }
    }

    return 0;
}

Ws_Frame *read_frame(int sd)
{
#define FIN(header)         ((header)[0] >> 7)
#define OPCODE(header)      ((header)[0] & 0xF)
#define MASK(header)        ((header)[1] >> 7)
#define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

    Ws_Frame *frame = NULL;

    uint8_t header[2] = {0};

    // Read the header
    if (read(sd, header, sizeof(header)) < 0) {
        fprintf(stderr, "ERROR: could not read frame: %s\n",
                strerror(errno));
        goto error;
    }

    uint64_t payload_len = 0;

    // Parse the payload length
    {
        uint8_t len = PAYLOAD_LEN(header);
        switch (len) {
        case 126: {
            uint16_t ext_len = 0;
            if (read(sd, &ext_len, sizeof(ext_len)) < 0) {
                fprintf(stderr, "ERROR: could not read frame: %s\n",
                        strerror(errno));
                goto error;
            }
            payload_len = ext_len;
        }
        break;
        case 127: {
            uint64_t ext_len = 0;
            if (read(sd, &ext_len, sizeof(ext_len)) < 0) {
                fprintf(stderr, "ERROR: could not read frame: %s\n",
                        strerror(errno));
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
            if (read(sd, &mask, sizeof(mask)) < 0) {
                fprintf(stderr, "ERROR: could not read frame: %s\n",
                        strerror(errno));
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

        if (read(sd, frame->payload, frame->payload_len) < 0) {
            fprintf(stderr, "ERROR: could not read frame: %s\n",
                    strerror(errno));
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

int main()
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int sd = -1;
    struct addrinfo *addrs = NULL;

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

    // TODO: no support for wss

    // Sending client handshake to the server
    {
        const char *handshake =
            "GET / HTTP/1.1\r\n"
            "Host: "HOST"\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";
        const size_t handshake_size = strlen(handshake);
        write(sd, handshake, handshake_size);
    }

    // Handling handshake from the server
    {
        // TODO: the server handshake is literally ignored
        // Right now we are making this assumptions:
        // 1. The server sent the successful handshake
        // 2. Nothing is sent after the handshake so we can distinguish the frames
        char buffer[1024];
        ssize_t buffer_size = read(sd, buffer, sizeof(buffer));
        fwrite(buffer, 1, buffer_size, stdout);
        printf("------------------------------\n");
        if (buffer_size < 2 ||
                buffer[buffer_size - 2] != '\r' ||
                buffer[buffer_size - 1] != '\n') {
            fprintf(stderr, "ERROR: Server response is sus ngl\n");
            goto error;
        }
    }

    char payload[] = "khello";

    send_frame(sd, WS_OPCODE_PING, (uint8_t *)payload, strlen(payload));

    // Receiving frames
    {
        Ws_Frame *frame = read_frame(sd);
        while (frame != NULL) {
            log_frame(stdout, frame);
            if (frame->opcode == WS_OPCODE_PING) {
                send_frame(sd,
                           WS_OPCODE_PONG,
                           frame->payload,
                           frame->payload_len);
            }
            free(frame);

            sleep(1);
            send_frame(sd, WS_OPCODE_PING, (uint8_t*) payload, strlen(payload));
            frame = read_frame(sd);
        }
    }

    freeaddrinfo(addrs);
    close(sd);
    return 0;
error:
    if (addrs != NULL) {
        freeaddrinfo(addrs);
    }
    if (sd != -1) {
        close(sd);
    }
    return -1;
}
