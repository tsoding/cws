# C WebSockets

> [!WARNING]
> The library is not in production ready state yet

Custom WebSocket implementation in C for educational and recreational purposes.

## Quick Start

```console
$ cc -o nob nob.c
$ ./nob
$ ./build/02_plain_async_echo_server
$ firefox ./tools/send_client.html
```

The Echo Servers in the examples are also testable with [Autobahn Test Suite](https://github.com/crossbario/autobahn-testsuite).

```
$ ./build/02_plain_async_echo_server
$ wstest --mode fuzzingclient
```

## References

- https://tools.ietf.org/html/rfc6455
- https://www.websocket.org/echo.html
