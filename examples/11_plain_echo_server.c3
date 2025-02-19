module main;

import std::io;
import std::net::tcp, std::net::os;
import libc;
import cws;
import arena;

fn int cws_socket_read(void* data, void* buffer, usz len)
{
    isz n = libc::read((int)(iptr)data, buffer, len);
    if (n < 0) return (int)cws::ERROR_ERRNO;
    if (n == 0) return (int)cws::ERROR_CONNECTION_CLOSED;
    return (int)n;
}

// peek: like read, but does not remove data from the buffer
// Usually implemented via MSG_PEEK flag of recv
fn int cws_socket_peek(void* data, void* buffer, usz len)
{
    const int MSG_PEEK = 2;
    isz n = libc::recv((int)(iptr)data, buffer, len, MSG_PEEK);
    if (n < 0)  return (int)cws::ERROR_ERRNO;
    if (n == 0) return (int)cws::ERROR_CONNECTION_CLOSED;
    return (int)n;
}

fn int cws_socket_write(void* data, void* buffer, usz len)
{
    isz n = libc::write((int)(iptr)data, buffer, len);
    if (n < 0)  return (int)cws::ERROR_ERRNO;
    if (n == 0) return (int)cws::ERROR_CONNECTION_CLOSED;
    return (int)n;
}

fn int cws_socket_shutdown(void* data, CwsShutdownHow how)
{
    if (libc::shutdown((int)(iptr)data, (int)how) < 0) return (int)cws::ERROR_ERRNO;
    return 0;
}

fn int cws_socket_close(void *data)
{
    if (libc::close((int)(iptr)data) < 0) return (int)cws::ERROR_ERRNO;
    return 0;
}

fn CwsSocket cws_socket_from_fd(int fd)
{
    return CwsSocket {
        .data     = (void*)(iptr)fd,
        .read     = &cws_socket_read,
        .peek     = &cws_socket_write,
        .write    = &cws_socket_peek,
        .shutdown = &cws_socket_shutdown,
        .close    = &cws_socket_close,
    };
}

fn int main() {
    const String HOST = "127.0.0.1";
    const ushort PORT = 9001;
    TcpServerSocket server = tcp::listen(HOST, PORT, 10, REUSEADDR)!!;
    io::printfn("Listening to %s:%d", HOST, PORT);
    while ACCEPT: (true) {
        TcpSocket client = tcp::accept(&server)!!;

        Cws cws = {
            .socket = cws_socket_from_fd(client.sock),
            .debug = true,
        };
        defer arena::free(&cws.arena);

        int err = cws::server_handshake(&cws);
        if (err < 0) {
            io::eprintf("ERROR: server_handshake: %s\n", cws::error_message(&cws, (CwsError)err));
            return 1;
        }

        io::eprintf("INFO: client connected\n");
        for (int i = 0; ; ++i) {
            CwsMessage message;
            err = cws::read_message(&cws, &message);
            if (err < 0) {
                if (err == (int)cws::ERROR_FRAME_CLOSE_SENT) {
                    io::printf("INFO: client closed connection\n");
                } else {
                    io::eprintf("ERROR: client connection failed: %s\n", cws::error_message(&cws, (CwsError)err));
                }

                cws::close(&cws);
                break;
            }
            io::printf("INFO: %d: client sent %zu bytes of %s message\n", i, message.payload_len, cws::message_kind_name(&cws, message.kind));
            cws::send_message(&cws, message.kind, message.payload, message.payload_len);
            arena::reset(&cws.arena);
        }
    }
}
