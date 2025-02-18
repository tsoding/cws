#ifndef CWS_H_
#define CWS_H_

#include <stdlib.h>
#include <stdbool.h>
#include "arena.h"

typedef enum {
    CWS_SHUTDOWN_READ,
    CWS_SHUTDOWN_WRITE,
    CWS_SHUTDOWN_BOTH,
} Cws_Shutdown_How;

// The errors are returned as negative values from cws_* functions
typedef enum {
    CWS_OK                                =  0,
    CWS_ERROR_CONNECTION_CLOSED           = -1,
    CWS_CONTROL_FRAME_TOO_BIG             = -2,
    CWS_RESERVED_BITS_NOT_NEGOTIATED      = -3,
    CWS_CLOSE_FRAME_SENT                  = -4,
    CWS_UNEXPECTED_OPCODE                 = -5,
    CWS_SHORT_UTF8                        = -6,
    CWS_INVALID_UTF8                      = -7,
    CWS_SERVER_HANDSHAKE_DUPLICATE_KEY    = -8,
    CWS_SERVER_HANDSHAKE_NO_KEY           = -9,
    CWS_CLIENT_HANDSHAKE_BAD_ACCEPT       = -10,
    CWS_CLIENT_HANDSHAKE_DUPLICATE_ACCEPT = -11,
    CWS_CLIENT_HANDSHAKE_NO_ACCEPT        = -12,
    CWS_ERRNO                             = -13, // TODO: set CWS_ERRNO to -1
    CWS_SSL_ERROR                         = -14,
} Cws_Error;

// NOTE: read, write, and peek must never return 0. On internally returning 0 they must return CWS_ERROR_CONNECTION_CLOSED
typedef struct {
    void *data;
    int (*read)(void *data, void *buffer, size_t len);
    // peek: like read, but does not remove data from the buffer
    // Usually implemented via MSG_PEEK flag of recv
    int (*peek)(void *data, void *buffer, size_t len);
    int (*write)(void *data, const void *buffer, size_t len);
    int (*shutdown)(void *data, Cws_Shutdown_How how);
    int (*close)(void *data);
} Cws_Socket;

typedef struct {
    Cws_Socket socket;
    Arena arena;
    bool debug; // Enable debug logging
    bool client;
} Cws;

typedef enum {
    CWS_OPCODE_CONT  = 0x0,
    CWS_OPCODE_TEXT  = 0x1,
    CWS_OPCODE_BIN   = 0x2,
    CWS_OPCODE_CLOSE = 0x8,
    CWS_OPCODE_PING  = 0x9,
    CWS_OPCODE_PONG  = 0xA,
} Cws_Opcode;

typedef enum {
    CWS_MESSAGE_TEXT = CWS_OPCODE_TEXT,
    CWS_MESSAGE_BIN  = CWS_OPCODE_BIN,
} Cws_Message_Kind;

typedef struct {
    Cws_Message_Kind kind;
    unsigned char *payload;
    size_t payload_len;
} Cws_Message;

const char *cws_opcode_name(Cws *cws, Cws_Opcode opcode);
bool cws_opcode_is_control(Cws_Opcode opcode);
int cws_server_handshake(Cws *cws);
int cws_client_handshake(Cws *cws, const char *host, const char *endpoint);
int cws_send_frame(Cws *cws, bool fin, Cws_Opcode opcode, unsigned char *payload, size_t payload_len);
int cws_send_message(Cws *cws, Cws_Message_Kind kind, unsigned char *payload, size_t payload_len);
int cws_read_message(Cws *cws, Cws_Message *message);
void cws_close(Cws *cws);

#endif // CWS_H_
