/**
 * @file bench/native_sink.c
 * @brief Nonblocking TCP sink used for LLPS Docker throughput checks.
 *
 * @details
 * The sink accepts many client sockets, drains inbound bytes, and reports the
 * backend-observed throughput used as the authoritative proxy benchmark value.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NATIVE_SINK_MAX_FDS 4096
#define NATIVE_SINK_BUF_SIZE 65536

static volatile sig_atomic_t g_stop_requested = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

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

static int open_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int one = 1;

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        (void)close(fd);
        return -1;
    }
    if (listen(fd, 1024) != 0) {
        (void)close(fd);
        return -1;
    }
    if (set_nonblocking(fd) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    const int port = (argc > 1) ? atoi(argv[1]) : 25566;
    const double duration = (argc > 2) ? atof(argv[2]) : 8.0;
    struct pollfd fds[NATIVE_SINK_MAX_FDS];
    unsigned char buf[NATIVE_SINK_BUF_SIZE];
    int listen_fd;
    nfds_t nfds = 1;
    uint64_t total_bytes = 0;
    uint64_t accepted = 0;
    uint64_t closed = 0;
    uint64_t errors = 0;
    const double start = now_seconds();
    const double deadline = start + duration;
    double first_byte_at = 0.0;
    double last_byte_at = 0.0;

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    listen_fd = open_listener(port);
    if (listen_fd < 0) {
        perror("native_sink listen");
        return 1;
    }
    fds[0].fd = listen_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while (!g_stop_requested && (now_seconds() < deadline)) {
        int pr = poll(fds, nfds, 50);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("native_sink poll");
            break;
        }
        if ((fds[0].revents & POLLIN) != 0) {
            for (;;) {
                int cfd = accept(listen_fd, NULL, NULL);
                if (cfd < 0) {
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                        break;
                    }
                    ++errors;
                    break;
                }
                if ((nfds >= NATIVE_SINK_MAX_FDS) ||
                    (set_nonblocking(cfd) != 0)) {
                    (void)close(cfd);
                    ++errors;
                    continue;
                }
                fds[nfds].fd = cfd;
                fds[nfds].events = POLLIN;
                fds[nfds].revents = 0;
                ++nfds;
                ++accepted;
            }
        }
        for (nfds_t i = 1; i < nfds;) {
            bool remove_fd = false;
            if ((fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                remove_fd = true;
            }
            if ((fds[i].revents & POLLIN) != 0) {
                for (;;) {
                    ssize_t n = recv(fds[i].fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        const double sample_time = now_seconds();
                        if (first_byte_at == 0.0) {
                            first_byte_at = sample_time;
                        }
                        last_byte_at = sample_time;
                        total_bytes += (uint64_t)n;
                        continue;
                    }
                    if (n == 0) {
                        remove_fd = true;
                        break;
                    }
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                        break;
                    }
                    ++errors;
                    remove_fd = true;
                    break;
                }
            }
            if (remove_fd) {
                (void)close(fds[i].fd);
                ++closed;
                fds[i] = fds[nfds - 1u];
                --nfds;
            } else {
                ++i;
            }
        }
    }

    for (nfds_t i = 0; i < nfds; ++i) {
        (void)close(fds[i].fd);
    }

    const double elapsed = now_seconds() - start;
    const double mib = (double)total_bytes / (1024.0 * 1024.0);
    const double active_elapsed =
        ((total_bytes > 0u) && (last_byte_at > first_byte_at)) ?
            (last_byte_at - first_byte_at) :
            0.0;
    const double active_mib_per_sec =
        (active_elapsed > 0.0) ? (mib / active_elapsed) : 0.0;
    printf("native_sink port=%d duration=%.3f accepted=%llu closed=%llu errors=%llu bytes=%llu mib=%.2f mib_per_sec=%.2f active_sec=%.3f active_mib_per_sec=%.2f\n",
           port,
           elapsed,
           (unsigned long long)accepted,
           (unsigned long long)closed,
           (unsigned long long)errors,
           (unsigned long long)total_bytes,
           mib,
           mib / elapsed,
           active_elapsed,
           active_mib_per_sec);
    return 0;
}
