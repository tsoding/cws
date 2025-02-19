// C3 bindings for cws
module cws;
import arena;

distinct CwsShutdownHow = int;
const CwsShutdownHow SHUTDOWN_READ  = 0;
const CwsShutdownHow SHUTDOWN_WRITE = 1;
const CwsShutdownHow SHUTDOWN_BOTH  = 2;

distinct CwsError = int;
const CwsError OK                                =  0;
const CwsError ERROR_CONNECTION_CLOSED           = -1;
const CwsError CONTROL_FRAME_TOO_BIG             = -2;
const CwsError RESERVED_BITS_NOT_NEGOTIATED      = -3;
const CwsError CLOSE_FRAME_SENT                  = -4;
const CwsError UNEXPECTED_OPCODE                 = -5;
const CwsError SHORT_UTF8                        = -6;
const CwsError INVALID_UTF8                      = -7;
const CwsError SERVER_HANDSHAKE_DUPLICATE_KEY    = -8;
const CwsError SERVER_HANDSHAKE_NO_KEY           = -9;
const CwsError CLIENT_HANDSHAKE_BAD_ACCEPT       = -10;
const CwsError CLIENT_HANDSHAKE_DUPLICATE_ACCEPT = -11;
const CwsError CLIENT_HANDSHAKE_NO_ACCEPT        = -12;
const CwsError ERRNO                             = -13;
const CwsError SSL_ERROR                         = -14;

def CwsSocketReadFn = fn int(void* data, void* buffer, usz len);
def CwsSocketWriteFn = fn int(void* data, void* buffer, usz len);
def CwsSocketPeekFn = fn int(void* data, void* buffer, usz len);
def CwsSocketShutdownFn = fn int(void* data, CwsShutdownHow how);
def CwsSocketCloseFn = fn int(void *data);

struct CwsSocket {
    void* data;
    CwsSocketReadFn read;
    CwsSocketWriteFn write;
    CwsSocketPeekFn peek;
    CwsSocketShutdownFn shutdown;
    CwsSocketCloseFn close;
}

distinct CwsMessageKind = int;
const CwsMessageKind MESSAGE_TEXT = 0x1;
const CwsMessageKind MESSAGE_BIN  = 0x2;

struct CwsMessage {
    CwsMessageKind kind;
    char *payload;
    usz payload_len;
}

struct Cws {
    CwsSocket socket;
    Arena arena;
    bool debug; // Enable debug logging
    bool client;
}

extern fn ZString message_kind_name(Cws *cws, CwsMessageKind kind) @extern("cws_message_kind_name");
extern fn int server_handshake(Cws *cws) @extern("cws_server_handshake");
extern fn int client_handshake(Cws *cws, ZString host, ZString endpoint) @extern("cws_client_handshake");
extern fn int send_message(Cws *cws, CwsMessageKind kind, char *payload, usz payload_len) @extern("cws_send_message");
extern fn int read_message(Cws *cws, CwsMessage *message) @extern("cws_read_message");
extern fn void close(Cws *cws) @extern("cws_close");

module arena;

struct Arena {
    void*[2] opaque;
}

extern fn void reset(Arena *a) @extern("arena_reset");
