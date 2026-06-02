/**
 * @file bench/native_load.c
 * @brief TCP write-load generator used for LLPS Docker throughput checks.
 *
 * @details
 * The tool keeps a bounded set of nonblocking client sockets writable and
 * reports aggregate bytes submitted to the proxy or direct backend path.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NATIVE_LOAD_MAX_CLIENTS 4096
#define NATIVE_LOAD_DEFAULT_PAYLOAD 65536

typedef enum {
    CLIENT_CONNECTING = 0,
    CLIENT_CONNECTED = 1,
    CLIENT_CLOSED = 2
} client_state_t;

typedef struct {
    int fd;
    client_state_t state;
} client_t;

static double now_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int start_connect(const char *host, int port) {
    char port_text[16];
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *it = NULL;
    int fd = -1;

    (void)snprintf(port_text, sizeof(port_text), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_text, &hints, &result) != 0) {
        return -1;
    }

    for (it = result; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (set_nonblocking(fd) != 0) {
            (void)close(fd);
            fd = -1;
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) != 0) {
            if (errno != EINPROGRESS) {
                (void)close(fd);
                fd = -1;
                continue;
            }
        }
        break;
    }

    freeaddrinfo(result);
    return fd;
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const int port = (argc > 2) ? atoi(argv[2]) : 25565;
    const int clients_requested = (argc > 3) ? atoi(argv[3]) : 200;
    const double duration = (argc > 4) ? atof(argv[4]) : 5.0;
    const size_t payload_size =
        (argc > 5) ? (size_t)strtoul(argv[5], NULL, 10) :
                     (size_t)NATIVE_LOAD_DEFAULT_PAYLOAD;
    client_t clients[NATIVE_LOAD_MAX_CLIENTS];
    struct pollfd fds[NATIVE_LOAD_MAX_CLIENTS];
    unsigned char *payload = NULL;
    int clients_count = clients_requested;
    uint64_t total_bytes = 0;
    uint64_t writes = 0;
    uint64_t errors = 0;
    uint64_t connected = 0;
    uint64_t closed = 0;
    double start;
    double deadline;

    if (clients_count > NATIVE_LOAD_MAX_CLIENTS) {
        clients_count = NATIVE_LOAD_MAX_CLIENTS;
    }
    if ((clients_count <= 0) || (payload_size == 0u)) {
        fprintf(stderr, "usage: native_load host port clients duration payload_bytes\n");
        return 2;
    }

    payload = (unsigned char *)malloc(payload_size);
    if (payload == NULL) {
        perror("malloc");
        return 1;
    }
    memset(payload, 0x5a, payload_size);
    memset(clients, 0, sizeof(clients));

    for (int i = 0; i < clients_count; ++i) {
        clients[i].fd = start_connect(host, port);
        if (clients[i].fd < 0) {
            clients[i].state = CLIENT_CLOSED;
            ++errors;
        } else {
            clients[i].state = CLIENT_CONNECTING;
        }
    }

    start = now_seconds();
    deadline = start + duration;
    while (now_seconds() < deadline) {
        nfds_t nfds = 0;
        for (int i = 0; i < clients_count; ++i) {
            if (clients[i].state == CLIENT_CLOSED) {
                continue;
            }
            fds[nfds].fd = clients[i].fd;
            fds[nfds].events = POLLOUT;
            fds[nfds].revents = 0;
            ++nfds;
        }
        if (nfds == 0u) {
            break;
        }
        int pr = poll(fds, nfds, 10);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        nfds_t pf = 0;
        for (int i = 0; i < clients_count; ++i) {
            if (clients[i].state == CLIENT_CLOSED) {
                continue;
            }
            const short revents = fds[pf].revents;
            ++pf;
            if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                ++errors;
                ++closed;
                (void)close(clients[i].fd);
                clients[i].state = CLIENT_CLOSED;
                continue;
            }
            if ((revents & POLLOUT) == 0) {
                continue;
            }
            if (clients[i].state == CLIENT_CONNECTING) {
                int so_error = 0;
                socklen_t so_error_len = sizeof(so_error);
                if ((getsockopt(clients[i].fd,
                                SOL_SOCKET,
                                SO_ERROR,
                                &so_error,
                                &so_error_len) != 0) ||
                    (so_error != 0)) {
                    ++errors;
                    ++closed;
                    (void)close(clients[i].fd);
                    clients[i].state = CLIENT_CLOSED;
                    continue;
                }
                clients[i].state = CLIENT_CONNECTED;
                ++connected;
            }
            for (;;) {
                ssize_t n = send(clients[i].fd, payload, payload_size, 0);
                if (n > 0) {
                    total_bytes += (uint64_t)n;
                    ++writes;
                    if ((size_t)n < payload_size) {
                        break;
                    }
                    continue;
                }
                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                    break;
                }
                ++errors;
                ++closed;
                (void)close(clients[i].fd);
                clients[i].state = CLIENT_CLOSED;
                break;
            }
        }
    }

    for (int i = 0; i < clients_count; ++i) {
        if (clients[i].state != CLIENT_CLOSED) {
            (void)close(clients[i].fd);
        }
    }
    free(payload);

    const double elapsed = now_seconds() - start;
    const double mib = (double)total_bytes / (1024.0 * 1024.0);
    printf("native_load host=%s port=%d clients=%d duration=%.3f connected=%llu errors=%llu closed=%llu writes=%llu bytes=%llu mib=%.2f mib_per_sec=%.2f\n",
           host,
           port,
           clients_count,
           elapsed,
           (unsigned long long)connected,
           (unsigned long long)errors,
           (unsigned long long)closed,
           (unsigned long long)writes,
           (unsigned long long)total_bytes,
           mib,
           mib / elapsed);
    return 0;
}
