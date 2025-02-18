#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "cws.h"

#define HOST_IP "127.0.0.1"
#define PORT 9001

int cws_socket_read(void *data, void *buffer, size_t len)
{
    int n = read((long int)data, buffer, len);
    if (n < 0) return CWS_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

// peek: like read, but does not remove data from the buffer
// Usually implemented via MSG_PEEK flag of recv
int cws_socket_peek(void *data, void *buffer, size_t len)
{
    int n = recv((long int)data, buffer, len, MSG_PEEK);
    if (n < 0)  return CWS_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

int cws_socket_write(void *data, const void *buffer, size_t len)
{
    int n = write((long int)data, buffer, len);
    if (n < 0)  return CWS_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

int cws_socket_shutdown(void *data, Cws_Shutdown_How how)
{
    if (shutdown((long int)data, how) < 0) return CWS_ERRNO;
    return 0;
}

int cws_socket_close(void *data)
{
    if (close((long int)data) < 0) return CWS_ERRNO;
    return 0;
}

Cws_Socket cws_socket_from_fd(int fd)
{
    return (Cws_Socket) {
        .data     = (void*)(long int)fd,
        .read     = cws_socket_read,
        .peek     = cws_socket_peek,
        .write    = cws_socket_write,
        .shutdown = cws_socket_shutdown,
        .close    = cws_socket_close,
    };
}

int main(void)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "ERROR: could not create server socket: %s\n", strerror(errno));
        return 1;
    }

    int yes = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "ERROR: could not configure server socket: %s\n", strerror(errno));
        return 1;
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "ERROR: could not configure server socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(HOST_IP);
    if (bind(server_fd, (void*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "ERROR: could not bind server socket: %s\n", strerror(errno));
        return 1;
    }

    if (listen(server_fd, 69) < 0) {
        fprintf(stderr, "ERROR: could not listen to server socket: %s\n", strerror(errno));
        return 1;
    }

    printf("INFO: listening to %s:%d\n", HOST_IP, PORT);

    while (true) {
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (void*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            fprintf(stderr, "ERROR: could not accept connection from client: %s\n", strerror(errno));
            return 1;
        }

        Cws cws = {
            .socket = cws_socket_from_fd(client_fd),
            .debug = true,
        };

        int err = cws_server_handshake(&cws);
        if (err < 0) {
            fprintf(stderr, "%s:%d: CWS ERROR: %d\n", __FILE__, __LINE__, err);
            return 1;
        }

        printf("INFO: client connected\n");
        for (int i = 0; ; ++i) {
            Cws_Message message = {0};
            err = cws_read_message(&cws, &message);
            if (err < 0) {
                if (err == CWS_CLOSE_FRAME_SENT) {
                    printf("INFO: client closed connection\n");
                } else {
                    printf("ERROR: client connection failed: %d\n", err);
                }

                // TODO: tuck sending closing frame under cws_close()
                cws_send_frame(&cws, true, CWS_OPCODE_CLOSE, NULL, 0);
                cws_close(&cws);
                break;
            }
            printf("INFO: %d: client sent %zu bytes of %s message\n", i, message.payload_len, cws_opcode_name(&cws, (Cws_Opcode)message.kind));
            cws_send_message(&cws, message.kind, message.payload, message.payload_len);
            arena_reset(&cws.arena);
        }
    }

    return 0;
}
