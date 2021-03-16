#ifndef CWS_H_
#define CWS_H_

typedef enum {
    CWS_OPCODE_CONT  = 0x0,
    CWS_OPCODE_TEXT  = 0x1,
    CWS_OPCODE_BIN   = 0x2,
    CWS_OPCODE_CLOSE = 0x8,
    CWS_OPCODE_PING  = 0x9,
    CWS_OPCODE_PONG  = 0xA,
} Cws_Opcode;

typedef struct {
    char cstr[16];
} Cws_Opcode_Name;

Cws_Opcode_Name opcode_name(Cws_Opcode opcode);
bool is_control(Cws_Opcode opcode);

typedef struct {
    // TODO: no support for CONT frames
    // Cws_Frame *next;
    bool fin;
    Cws_Opcode opcode;
    uint64_t payload_len;
    uint8_t *payload;
} Cws_Frame;

typedef struct Cws_Message_Chunk Cws_Message_Chunk;

typedef enum {
    CWS_MESSAGE_TEXT = CWS_OPCODE_TEXT,
    CWS_MESSAGE_BIN = CWS_OPCODE_BIN,
} Cws_Message_Kind;

typedef struct {
    Cws_Message_Kind kind;
    Cws_Message_Chunk *chunks;
} Cws_Message;

struct Cws_Message_Chunk {
    Cws_Message_Chunk *next;
    uint64_t payload_len;
    uint8_t *payload;
};

typedef void* Cws_Socket;
typedef void* Cws_Allocator;

typedef struct {
    Cws_Socket socket;
    ssize_t (*read)(Cws_Socket socket, void *buf, size_t count);
    ssize_t (*write)(Cws_Socket socket, const void *buf, size_t count);

    Cws_Allocator ator;
    void *(*alloc)(Cws_Allocator ator, size_t size);
    void (*free)(Cws_Allocator ator, void *data, size_t size);
} Cws;

int cws_handshake(Cws *cws, const char *host);

int cws_send_message(Cws *cws, Cws_Message_Kind kind, const uint8_t *payload, uint64_t payload_len, uint64_t chunk_len);
int cws_read_message(Cws *cws, Cws_Message *message);
void cws_free_message(Cws *cws, Cws_Message *message);

int cws_send_frame(Cws *cws, bool fin, Cws_Opcode opcode, const uint8_t *payload, uint64_t payload_len);
int cws_read_frame(Cws *cws, Cws_Frame *frame);
void cws_free_frame(Cws *cws, Cws_Frame *frame);

#endif // CWS_H_

#ifdef CWS_IMPLEMENTATION

int cws_handshake(Cws *cws, const char *host)
{
    char handshake[1024] = {0};

    snprintf(handshake, sizeof(handshake),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             // TODO: custom WebSocket key
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n",
             host);
    const size_t handshake_size = strlen(handshake);
    cws->write(cws->socket, handshake, handshake_size);

    // TODO: the server handshake is literally ignored
    // Right now we are making this assumptions:
    // 1. The server sent the successful handshake
    // 2. Nothing is sent after the handshake so we can distinguish the frames
    // 3. The handshake fits into sizeof(buffer)
    char buffer[1024];
    ssize_t buffer_size = cws->read(cws->socket, buffer, sizeof(buffer));
    fwrite(buffer, 1, buffer_size, stdout);
    printf("------------------------------\n");
    if (buffer_size < 2 ||
            buffer[buffer_size - 2] != '\r' ||
            buffer[buffer_size - 1] != '\n') {
        goto error;
    }
    return 0;
error:
    return -1;
}


bool is_control(Cws_Opcode opcode)
{
    return 0x8 <= opcode && opcode <= 0xF;
}

Cws_Opcode_Name opcode_name(Cws_Opcode opcode)
{
    Cws_Opcode_Name result = {0};

    switch (opcode) {
    case CWS_OPCODE_CONT:
        snprintf(result.cstr, sizeof(result.cstr), "CONT");
        break;
    case CWS_OPCODE_TEXT:
        snprintf(result.cstr, sizeof(result.cstr), "TEXT");
        break;
    case CWS_OPCODE_BIN:
        snprintf(result.cstr, sizeof(result.cstr), "BIN");
        break;
    case CWS_OPCODE_CLOSE:
        snprintf(result.cstr, sizeof(result.cstr), "CLOSE");
        break;
    case CWS_OPCODE_PING:
        snprintf(result.cstr, sizeof(result.cstr), "PING");
        break;
    case CWS_OPCODE_PONG:
        snprintf(result.cstr, sizeof(result.cstr), "PONG");
        break;
    default:
        if (0x3 <= opcode && opcode <= 0x7) {
            snprintf(result.cstr, sizeof(result.cstr), "NONCONTROL(0x%X)", opcode & 0xF);
        } else if (0xB <= opcode && opcode <= 0xF) {
            snprintf(result.cstr, sizeof(result.cstr), "CONTROL(0x%X)", opcode & 0xF);
        } else {
            snprintf(result.cstr, sizeof(result.cstr), "INVALID(0x%X)", opcode & 0xF);
        }
    }

    return result;
}

// TODO: test all executing paths in read_frame
int cws_read_frame(Cws *cws, Cws_Frame *frame)
{
    assert(frame);
#define FIN(header)         ((header)[0] >> 7)
#define OPCODE(header)      ((header)[0] & 0xF)
#define MASK(header)        ((header)[1] >> 7)
#define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

    uint8_t header[2] = {0};

    // Read the header
    if (cws->read(cws->socket, header, sizeof(header)) <= 0) {
        goto error;
    }

    uint64_t payload_len = 0;

    // Parse the payload length
    {
        uint8_t len = PAYLOAD_LEN(header);
        switch (len) {
        case 126: {
            uint8_t ext_len[2] = {0};
            if (cws->read(cws->socket, &ext_len, sizeof(ext_len)) <= 0) {
                goto error;
            }
            payload_len = (ext_len[0] << 8) | ext_len[1];
        }
        break;
        case 127: {
            // TODO: reverse the bytes of 64 bit extended length in read_frame
            uint64_t ext_len = 0;
            if (cws->read(cws->socket, &ext_len, sizeof(ext_len)) <= 0) {
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
            if (cws->read(cws->socket, &mask, sizeof(mask)) <= 0) {
                goto error;
            }
        }
    }

    // Read the payload
    {
        frame->fin = FIN(header);
        frame->opcode = OPCODE(header);
        frame->payload_len = payload_len;

        if (frame->payload_len > 0) {
            frame->payload = cws->alloc(cws->ator, payload_len);
            if (frame->payload == NULL) {
                goto error;
            }
            memset(frame->payload, 0, payload_len);

            // TODO: cws_read_frame does not handle when cws->read didn't read the whole payload
            if (cws->read(cws->socket, frame->payload, frame->payload_len) <= 0) {
                goto error;
            }
        }
    }

    return 0;
error:
    if (frame) {
        cws_free_frame(cws, frame);
    }
    return -1;
}

// TODO: test all executing paths in send_frame
int cws_send_frame(Cws *cws, bool fin, Cws_Opcode opcode, const uint8_t *payload, uint64_t payload_len)
{
    // Send FIN and OPCODE
    {
        // NOTE: FIN is always set
        uint8_t data = opcode;
        if (fin) {
            data |= (1 << 7);
        }
        if (cws->write(cws->socket, &data, 1) < 0) {
            return -1;
        }
    }

    // Send masked and payload length
    {
        // NOTE: client frames are always masked
        if (payload_len < 126) {
            uint8_t data = (1 << 7) | payload_len;

            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                return -1;
            }
        } else if (payload_len <= UINT16_MAX) {
            uint8_t data = (1 << 7) | 126;
            uint8_t len[2] = {
                (payload_len >> 8) & 0xFF,
                payload_len & 0xFF
            };

            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                return -1;
            }

            if (cws->write(cws->socket, &len, sizeof(len)) <= 0) {
                return -1;
            }
        } else if (payload_len > UINT16_MAX) {
            // TODO: reverse the bytes of 64 bit extended length in read_frame
            uint8_t data = (1 << 7) | 127;

            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                return -1;
            }

            if (cws->write(cws->socket, &payload_len, sizeof(payload_len)) <= 0) {
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

        if (cws->write(cws->socket, mask, sizeof(mask)) <= 0) {
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
            if (cws->write(cws->socket, chunk, chunk_size) <= 0) {
                return -1;
            }
        }
    }

    return 0;
}

void cws_free_frame(Cws *cws, Cws_Frame *frame)
{
    cws->free(cws->ator, frame->payload, frame->payload_len);
    frame->payload = NULL;
}

int cws_send_message(Cws *cws,
                     Cws_Message_Kind kind,
                     const uint8_t *payload,
                     uint64_t payload_len,
                     uint64_t chunk_len)
{
    bool first = true;
    while (payload_len > 0) {
        uint64_t len = payload_len;
        if (len > chunk_len) {
            len = chunk_len;
        }

        if (cws_send_frame(
                    cws,
                    payload_len - len == 0,
                    first ? (Cws_Opcode) kind : CWS_OPCODE_CONT,
                    payload,
                    len) < 0) {
            goto error;
        }

        payload += len;
        payload_len -= len;
        first = false;
    }

    return 0;
error:
    return -1;
}

int cws_read_message(Cws *cws, Cws_Message *message)
{
    assert(message);
    assert(message->chunks == NULL);

    Cws_Message_Chunk *end = NULL;

    Cws_Frame frame = {0};
    int ret = cws_read_frame(cws, &frame);
    while (ret == 0) {
        if (is_control(frame.opcode)) {
            switch (frame.opcode) {
            case CWS_OPCODE_CLOSE:
                // TODO: cws_read_message does not handle CLOSE opcode properly
                goto error;
                break;
            case CWS_OPCODE_PING:
                cws_send_frame(cws,
                               true,
                               CWS_OPCODE_PONG,
                               frame.payload,
                               frame.payload_len);
                break;
            default: {
            }
            }

            cws_free_frame(cws, &frame);
        } else {
            // TODO: cws_read_message does not verify that the message starts with non CONT frame (does it have to start with non-CONT frame)?
            // TODO: cws_read_message does not verify that any non-fin "continuation" frames have the CONT opcode
            if (end == NULL) {
                end = cws->alloc(cws->ator, sizeof(*end));
                if (end == NULL) {
                    goto error;
                }
                memset(end, 0, sizeof(*end));
                end->payload = frame.payload;
                end->payload_len = frame.payload_len;
                message->chunks = end;
                message->kind = (Cws_Message_Kind) frame.opcode;
            } else {
                end->next = cws->alloc(cws->ator, sizeof(*end->next));
                if (end->next == NULL) {
                    goto error;
                }
                memset(end->next, 0, sizeof(*end->next));
                end->next->payload = frame.payload;
                end->next->payload_len = frame.payload_len;
                end = end->next;
            }

            if (frame.fin) {
                break;
            }
        }

        ret = cws_read_frame(cws, &frame);
    }

    if (ret < 0) {
        goto error;
    }

    return 0;
error:
    cws_free_message(cws, message);
    return -1;
}

void cws_free_message(Cws *cws, Cws_Message *message)
{
    Cws_Message_Chunk *iter = message->chunks;
    while (iter != NULL) {
        cws->free(cws->ator, iter->payload, iter->payload_len);

        Cws_Message_Chunk *remove = iter;
        iter = iter->next;
        cws->free(cws->ator, remove, sizeof(*remove));
    }

    message->chunks = NULL;
}

#endif // CWS_IMPLEMENTATION
