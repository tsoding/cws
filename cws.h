// Copyright 2021 Alexey Kutepov <reximkut@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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

typedef enum {
    // No error has occurred
    CWS_NO_ERROR = 0,
    // cws_client_handshake() has failed
    CWS_CLIENT_HANDSHAKE_ERROR,
    // Cws.read or Cws.write have failed
    CWS_SOCKET_ERROR,
    // Cws.alloc has failed
    CWS_ALLOCATOR_ERROR,
    // Server sent CLOSE frame during cws_read_message()
    CWS_SERVER_CLOSE_ERROR,
} Cws_Error;

typedef void* Cws_Socket;
typedef void* Cws_Allocator;

typedef struct {
    Cws_Error error;

    Cws_Socket socket;
    int (*read)(Cws_Socket socket, void *buf, size_t count);
    int (*write)(Cws_Socket socket, const void *buf, size_t count);

    Cws_Allocator ator;
    void *(*alloc)(Cws_Allocator ator, size_t size);
    void (*free)(Cws_Allocator ator, void *data, size_t size);
} Cws;

int cws_client_handshake(Cws *cws, const char *host);

int cws_send_message(Cws *cws, Cws_Message_Kind kind, const uint8_t *payload, uint64_t payload_len, uint64_t chunk_len);
int cws_read_message(Cws *cws, Cws_Message *message);
void cws_free_message(Cws *cws, Cws_Message *message);

int cws_send_frame(Cws *cws, bool fin, Cws_Opcode opcode, const uint8_t *payload, uint64_t payload_len);
int cws_read_frame(Cws *cws, Cws_Frame *frame);
void cws_free_frame(Cws *cws, Cws_Frame *frame);

#endif // CWS_H_

#ifdef CWS_IMPLEMENTATION

int cws_client_handshake(Cws *cws, const char *host)
{
    cws->error = CWS_NO_ERROR;

    char handshake[1024] = {0};

    snprintf(handshake, sizeof(handshake),
             // TODO: customizable resource path
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
    int buffer_size = cws->read(cws->socket, buffer, sizeof(buffer));
    fwrite(buffer, 1, buffer_size, stdout);
    printf("------------------------------\n");
    if (buffer_size < 2 ||
            buffer[buffer_size - 2] != '\r' ||
            buffer[buffer_size - 1] != '\n') {
        cws->error = CWS_CLIENT_HANDSHAKE_ERROR;
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

int cws_read_frame(Cws *cws, Cws_Frame *frame)
{
    assert(frame->payload == NULL && "You forgot to call cws_free_frame() before calling cws_read_frame()");

    cws->error = CWS_NO_ERROR;

#define FIN(header)         ((header)[0] >> 7)
#define OPCODE(header)      ((header)[0] & 0xF)
#define MASK(header)        ((header)[1] >> 7)
#define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

    uint8_t header[2] = {0};

    // Read the header
    if (cws->read(cws->socket, header, sizeof(header)) <= 0) {
        cws->error = CWS_SOCKET_ERROR;
        goto error;
    }

    uint64_t payload_len = 0;

    // Parse the payload length
    {
        // TODO: do we need to reverse the bytes on a machine with a different endianess than x86?
        uint8_t len = PAYLOAD_LEN(header);
        switch (len) {
        case 126: {
            uint8_t ext_len[2] = {0};
            if (cws->read(cws->socket, &ext_len, sizeof(ext_len)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }

            for (size_t i = 0; i < sizeof(ext_len); ++i) {
                payload_len = (payload_len << 8) | ext_len[i];
            }
        }
        break;
        case 127: {
            uint8_t ext_len[8] = {0};
            if (cws->read(cws->socket, &ext_len, sizeof(ext_len)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }

            for (size_t i = 0; i < sizeof(ext_len); ++i) {
                payload_len = (payload_len << 8) | ext_len[i];
            }
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
                cws->error = CWS_SOCKET_ERROR;
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
                cws->error = CWS_ALLOCATOR_ERROR;
                goto error;
            }
            memset(frame->payload, 0, payload_len);

            // TODO: cws_read_frame does not handle when cws->read didn't read the whole payload
            if (cws->read(cws->socket, frame->payload, frame->payload_len) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
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

int cws_send_frame(Cws *cws, bool fin, Cws_Opcode opcode, const uint8_t *payload, uint64_t payload_len)
{
    cws->error = CWS_NO_ERROR;

    // Send FIN and OPCODE
    {
        // NOTE: FIN is always set
        uint8_t data = opcode;
        if (fin) {
            data |= (1 << 7);
        }
        if (cws->write(cws->socket, &data, 1) < 0) {
            cws->error = CWS_SOCKET_ERROR;
            goto error;
        }
    }

    // Send masked and payload length
    {
        // TODO: do we need to reverse the bytes on a machine with a different endianess than x86?
        // NOTE: client frames are always masked
        if (payload_len < 126) {
            uint8_t data = (1 << 7) | payload_len;

            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }
        } else if (payload_len <= UINT16_MAX) {
            uint8_t data = (1 << 7) | 126;
            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }

            uint8_t len[2] = {
                (payload_len >> (8 * 1)) & 0xFF,
                (payload_len >> (8 * 0)) & 0xFF
            };

            if (cws->write(cws->socket, &len, sizeof(len)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }
        } else if (payload_len > UINT16_MAX) {
            uint8_t data = (1 << 7) | 127;
            uint8_t len[8] = {
                (payload_len >> (8 * 7)) & 0xFF,
                (payload_len >> (8 * 6)) & 0xFF,
                (payload_len >> (8 * 5)) & 0xFF,
                (payload_len >> (8 * 4)) & 0xFF,
                (payload_len >> (8 * 3)) & 0xFF,
                (payload_len >> (8 * 2)) & 0xFF,
                (payload_len >> (8 * 1)) & 0xFF,
                (payload_len >> (8 * 0)) & 0xFF
            };

            if (cws->write(cws->socket, &data, sizeof(data)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }

            if (cws->write(cws->socket, &len, sizeof(len)) <= 0) {
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }
        }
    }

    uint8_t mask[4] = {0};

    // Generate and send mask
    {
        for (size_t i = 0; i < 4; ++i) {
            mask[i] = rand() % 0x100;
        }

        if (cws->write(cws->socket, mask, sizeof(mask)) <= 0) {
            cws->error = CWS_SOCKET_ERROR;
            goto error;
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
                cws->error = CWS_SOCKET_ERROR;
                goto error;
            }
        }
    }

    return 0;
error:
    return -1;
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
    cws->error = CWS_NO_ERROR;

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
    assert(message->chunks == NULL && "You forgot to call cws_free_message() before calling cws_read_message()");

    cws->error = CWS_NO_ERROR;

    Cws_Message_Chunk *end = NULL;

    Cws_Frame frame = {0};
    int ret = cws_read_frame(cws, &frame);
    while (ret == 0) {
        if (is_control(frame.opcode)) {
            switch (frame.opcode) {
            case CWS_OPCODE_CLOSE: {
                cws->error = CWS_SERVER_CLOSE_ERROR;
                goto error;
            }
            break;
            case CWS_OPCODE_PING:
                if (cws_send_frame(
                            cws,
                            true,
                            CWS_OPCODE_PONG,
                            frame.payload,
                            frame.payload_len) < 0) {
                    goto error;
                }
                break;
            default: {
                // Ignore any other control frames for now
            }
            }

            cws_free_frame(cws, &frame);
        } else {
            // TODO: cws_read_message does not verify that the message starts with non CONT frame (does it have to start with non-CONT frame)?
            // TODO: cws_read_message does not verify that any non-fin "continuation" frames have the CONT opcode
            if (end == NULL) {
                end = cws->alloc(cws->ator, sizeof(*end));
                if (end == NULL) {
                    cws->error = CWS_ALLOCATOR_ERROR;
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
                    cws->error = CWS_ALLOCATOR_ERROR;
                    goto error;
                }
                memset(end->next, 0, sizeof(*end->next));
                end->next->payload = frame.payload;
                end->next->payload_len = frame.payload_len;
                end = end->next;
            }

            // The frame's payload has been moved to the message chunk (moved as in C++ moved,
            // the ownership of the payload belongs to message now)
            frame.payload = NULL;
            frame.payload_len = 0;

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
    if (frame.payload) {
        cws_free_frame(cws, &frame);
    }
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
// TODO: Test with Autobahn test suite
// https://crossbar.io/docs/WebSocket-Compliance-Testing/
