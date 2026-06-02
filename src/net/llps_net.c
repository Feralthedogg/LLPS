/**
 * @file src/net/llps_net.c
 * @brief Socket and TCP helper routines used by the proxy core.
 *
 * @details
 * Network helpers wrap platform socket behavior behind explicit LLPS status
 * results.
 */

#include "llps_net.h"

#include "llps_config.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

bool llps_fd_is_valid(const int fd) {
    return fd >= 0;
}

/*
 * Close a connected socket: shutdown(SHUT_RDWR) then close().
 * Used for client and backend fds where graceful TCP teardown is desired.
 */
int llps_close_connected_fd(int * const fd_ref) {
    int rc = 0;

    if (fd_ref == NULL) {
        return -1;
    }

    if (llps_fd_is_valid(*fd_ref)) {
        (void)shutdown(*fd_ref, SHUT_RDWR);
        rc = close(*fd_ref);
        *fd_ref = LLPS_INVALID_FD;
    }

    return rc;
}

llps_status_t llps_set_nonblocking(const int fd) {
    int flags = 0;

    if (!llps_fd_is_valid(fd)) {
        return LLPS_E_RANGE;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return LLPS_E_SOCKET;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return LLPS_E_SOCKET;
    }

    return LLPS_OK;
}

bool llps_fd_is_nonblocking(const int fd) {
    int flags = 0;

    if (!llps_fd_is_valid(fd)) {
        return false;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    return (flags & O_NONBLOCK) != 0;
}

llps_status_t llps_set_close_on_exec(const int fd) {
    int flags = 0;

    if (!llps_fd_is_valid(fd)) {
        return LLPS_E_RANGE;
    }

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        return LLPS_E_SOCKET;
    }

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return LLPS_E_SOCKET;
    }

    return LLPS_OK;
}

llps_status_t llps_set_no_sigpipe(const int fd) {
#if defined(SO_NOSIGPIPE)
    int opt = 1;
#endif

    if (!llps_fd_is_valid(fd)) {
        return LLPS_E_RANGE;
    }

#if defined(SO_NOSIGPIPE)
    if (setsockopt(fd,
                   SOL_SOCKET,
                   SO_NOSIGPIPE,
                   &opt,
                   (socklen_t)sizeof(opt)) != 0) {
        return LLPS_E_SOCKET;
    }
#endif

    return LLPS_OK;
}

llps_status_t llps_set_tcp_nodelay(const int fd) {
    int opt = 1;

    if (!llps_fd_is_valid(fd)) {
        return LLPS_E_RANGE;
    }

    if (setsockopt(fd,
                   IPPROTO_TCP,
                   TCP_NODELAY,
                   &opt,
                   (socklen_t)sizeof(opt)) != 0) {
        return LLPS_E_SOCKET;
    }

    return LLPS_OK;
}

ssize_t llps_send_no_sigpipe(const int fd,
                             const void * const buf,
                             const size_t len) {
#if defined(MSG_NOSIGNAL)
    return send(fd, buf, len, MSG_NOSIGNAL);
#else
    return send(fd, buf, len, 0);
#endif
}

llps_status_t llps_sockaddr_ipv4_text(const struct sockaddr * const addr,
                                      char * const out_ip,
                                      const size_t out_ip_cap,
                                      uint16_t * const out_port) {
    return llps_sockaddr_ipv4_text_len(addr,
                                       (socklen_t)sizeof(struct sockaddr_in),
                                       out_ip,
                                       out_ip_cap,
                                       out_port);
}

llps_status_t llps_sockaddr_ipv4_text_len(const struct sockaddr * const addr,
                                          const socklen_t addr_len,
                                          char * const out_ip,
                                          const size_t out_ip_cap,
                                          uint16_t * const out_port) {
    struct sockaddr_in addr_in;

    if ((addr == NULL) || (out_ip == NULL) || (out_port == NULL)) {
        return LLPS_E_NULL;
    }

    if (out_ip_cap < LLPS_IPV4_TEXT_LEN) {
        return LLPS_E_RANGE;
    }

    if (addr_len < (socklen_t)sizeof(addr_in)) {
        return LLPS_E_RANGE;
    }

    if (addr->sa_family != AF_INET) {
        return LLPS_E_SOCKET;
    }

    (void)memset(&addr_in, 0, sizeof(addr_in));
    (void)memcpy(&addr_in, addr, sizeof(addr_in));
    if (inet_ntop(AF_INET,
                  &addr_in.sin_addr,
                  out_ip,
                  (socklen_t)out_ip_cap) == NULL) {
        return LLPS_E_SOCKET;
    }

    *out_port = ntohs(addr_in.sin_port);
    return LLPS_OK;
}

static bool llps_resolve_ipv4_literal(const char * const host,
                                      const uint16_t port,
                                      struct sockaddr_in * const addr) {
    struct sockaddr_in resolved;

    if ((host == NULL) || (addr == NULL)) {
        return false;
    }

    (void)memset(&resolved, 0, sizeof(resolved));
    resolved.sin_family = AF_INET;
    resolved.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &resolved.sin_addr) != 1) {
        return false;
    }

    *addr = resolved;
    return true;
}

static llps_status_t llps_resolve_ipv4_service_text(const uint16_t port,
                                                    char * const service,
                                                    const size_t cap) {
    int written = 0;

    if ((service == NULL) || (cap == 0u)) {
        return LLPS_E_NULL;
    }

    written = snprintf(service, cap, "%u", (unsigned)port);
    if ((written <= 0) || ((size_t)written >= cap)) {
        return LLPS_E_RANGE;
    }

    return LLPS_OK;
}

static bool llps_resolve_ipv4_copy_first_result(
    const struct addrinfo * const result,
    const uint16_t port,
    struct sockaddr_in * const addr) {
    struct sockaddr_in resolved;

    if ((result == NULL) || (addr == NULL)) {
        return false;
    }

    for (const struct addrinfo *cursor = result;
         cursor != NULL;
         cursor = cursor->ai_next) {
        if ((cursor->ai_family == AF_INET) &&
            (cursor->ai_addr != NULL) &&
            (cursor->ai_addrlen >= (socklen_t)sizeof(resolved))) {
            (void)memcpy(&resolved, cursor->ai_addr, sizeof(resolved));
            resolved.sin_family = AF_INET;
            resolved.sin_port = htons(port);
            *addr = resolved;
            return true;
        }
    }

    return false;
}

static llps_status_t llps_resolve_ipv4_getaddrinfo(
    const char * const host,
    const uint16_t port,
    const bool passive,
    const char * const service,
    struct sockaddr_in * const addr) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    llps_status_t status = LLPS_E_SOCKET;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = passive ? AI_PASSIVE : 0;

    if (getaddrinfo(host, service, &hints, &result) != 0) {
        return LLPS_E_SOCKET;
    }

    if (llps_resolve_ipv4_copy_first_result(result, port, addr)) {
        status = LLPS_OK;
    }
    freeaddrinfo(result);
    return status;
}

llps_status_t llps_resolve_ipv4_sockaddr(const char * const host,
                                         const uint16_t port,
                                         const bool passive,
                                         struct sockaddr_in * const addr) {
    char service[6];

    if ((host == NULL) || (addr == NULL)) {
        return LLPS_E_NULL;
    }

    if (port == 0u) {
        return LLPS_E_RANGE;
    }

    if (llps_resolve_ipv4_literal(host, port, addr)) {
        return LLPS_OK;
    }

    const llps_status_t service_status =
        llps_resolve_ipv4_service_text(port, service, sizeof(service));
    if (service_status != LLPS_OK) {
        return service_status;
    }

    return llps_resolve_ipv4_getaddrinfo(host,
                                         port,
                                         passive,
                                         service,
                                         addr);
}

llps_status_t llps_close_listen_socket(int * const listen_fd_ref) {
    if (listen_fd_ref == NULL) {
        return LLPS_E_NULL;
    }

    if (*listen_fd_ref != LLPS_INVALID_FD) {
        if (close(*listen_fd_ref) != 0) {
            *listen_fd_ref = LLPS_INVALID_FD;
            return LLPS_E_SOCKET;
        }

        *listen_fd_ref = LLPS_INVALID_FD;
    }

    return LLPS_OK;
}

llps_status_t llps_open_listen_socket(const llps_yml_config_t * const cfg,
                                      int * const listen_fd_ref) {
    struct sockaddr_in saddr;
    int opt = 1;
    int fd = LLPS_INVALID_FD;

    if ((listen_fd_ref == NULL) || (cfg == NULL)) {
        return LLPS_E_NULL;
    }

    *listen_fd_ref = LLPS_INVALID_FD;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!llps_fd_is_valid(fd)) {
        return LLPS_E_SOCKET;
    }

    if (llps_set_close_on_exec(fd) != LLPS_OK) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    if (setsockopt(fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &opt,
                   (socklen_t)sizeof(opt)) != 0) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    if (llps_resolve_ipv4_sockaddr(cfg->listen_host,
                                   cfg->listen_port,
                                   true,
                                   &saddr) != LLPS_OK) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    if (bind(fd,
             (const struct sockaddr *)&saddr,
             (socklen_t)sizeof(saddr)) != 0) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    if (listen(fd, (int)cfg->listen_backlog) != 0) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    if (llps_set_nonblocking(fd) != LLPS_OK) {
        (void)close(fd);
        return LLPS_E_SOCKET;
    }

    *listen_fd_ref = fd;
    return LLPS_OK;
}
