#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "cws.h"
#include "coroutine.h"

#define HOST_IP "127.0.0.1"
#define PORT 9001

int cws_async_socket_read(void *data, void *buffer, size_t len)
{
    int sockfd = (long int)data;
    coroutine_sleep_read(sockfd);
    int n = read(sockfd, buffer, len);
    if (n < 0) return CWS_ERROR_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

// peek: like read, but does not remove data from the buffer
// Usually implemented via MSG_PEEK flag of recv
int cws_async_socket_peek(void *data, void *buffer, size_t len)
{
    int sockfd = (long int)data;
    coroutine_sleep_read(sockfd);
    int n = recv(sockfd, buffer, len, MSG_PEEK);
    if (n < 0)  return CWS_ERROR_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

int cws_async_socket_write(void *data, const void *buffer, size_t len)
{
    int sockfd = (long int)data;
    coroutine_sleep_write(sockfd);
    int n = write((long int)data, buffer, len);
    if (n < 0)  return CWS_ERROR_ERRNO;
    if (n == 0) return CWS_ERROR_CONNECTION_CLOSED;
    return n;
}

int cws_async_socket_shutdown(void *data, Cws_Shutdown_How how)
{
    if (shutdown((long int)data, how) < 0) return CWS_ERROR_ERRNO;
    return 0;
}

int cws_async_socket_close(void *data)
{
    if (close((long int)data) < 0) return CWS_ERROR_ERRNO;
    return 0;
}

Cws_Socket cws_async_socket_from_fd(int fd)
{
    return (Cws_Socket) {
        .data     = (void*)(long int)fd,
        .read     = cws_async_socket_read,
        .peek     = cws_async_socket_peek,
        .write    = cws_async_socket_write,
        .shutdown = cws_async_socket_shutdown,
        .close    = cws_async_socket_close,
    };
}

int set_non_blocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

void echo_client(void *data)
{
    int client_fd = (long int) data;

    Cws cws = {
        .socket = cws_async_socket_from_fd(client_fd),
        .debug = true,
    };

    int err = cws_server_handshake(&cws);
    if (err < 0) {
        fprintf(stderr, "ERROR: %s\n", cws_error_message(&cws, err));
        abort();
    }

    printf("INFO: client connected\n");
    for (int i = 0; ; ++i) {
        Cws_Message message = {0};
        err = cws_read_message(&cws, &message);
        if (err < 0) {
            if (err == CWS_ERROR_FRAME_CLOSE_SENT) {
                printf("INFO: client closed connection\n");
            } else {
                printf("ERROR: client connection failed: %s\n", cws_error_message(&cws, err));
            }

            cws_close(&cws);
            break;
        }
        printf("INFO: %d: client sent %zu bytes of %s message\n", i, message.payload_len, cws_message_kind_name(&cws, message.kind));
        cws_send_message(&cws, message.kind, message.payload, message.payload_len);
        arena_reset(&cws.arena);
    }

    arena_free(&cws.arena);
}

int main(void)
{
    coroutine_init();

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

    if (set_non_blocking(server_fd) < 0) {
        fprintf(stderr, "ERROR: could not set server socket non-blocking: %s\n", strerror(errno));
        return 1;
    }

    printf("INFO: listening to %s:%d\n", HOST_IP, PORT);

    while (true) {
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_len = sizeof(client_addr);
        coroutine_sleep_read(server_fd);
        int client_fd = accept(server_fd, (void*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            fprintf(stderr, "ERROR: could not accept connection from client: %s\n", strerror(errno));
            return 1;
        }
        if (set_non_blocking(client_fd) < 0) {
            fprintf(stderr, "ERROR: could not set client socket non-blocking: %s\n", strerror(errno));
            return 1;
        }

        coroutine_go(echo_client, (void*)(long int)client_fd);
    }

    return 0;
}
