/**
 * @file src/internal/llps_net.h
 * @brief Socket and TCP helper routines used by the proxy core.
 *
 * @details
 * Network helpers wrap platform socket behavior behind explicit LLPS status
 * results.
 */

#ifndef LLPS_NET_H
#define LLPS_NET_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/** @brief Maximum IPv4 text length including the terminating NUL. */
#define LLPS_IPV4_TEXT_LEN (16u)

/** @brief Return true when @p fd is not ::LLPS_INVALID_FD. */
bool llps_fd_is_valid(int fd);

/**
 * @brief Close a connected socket and invalidate its owner slot.
 *
 * @return 0 when the descriptor was invalid or closed successfully; otherwise
 *         the platform close error.
 */
int llps_close_connected_fd(int *fd_ref);

/** @brief Mark a descriptor close-on-exec where the platform supports it. */
llps_status_t llps_set_close_on_exec(int fd);

/** @brief Mark a descriptor nonblocking. */
llps_status_t llps_set_nonblocking(int fd);
/** @brief Return true when a descriptor is currently nonblocking. */
bool llps_fd_is_nonblocking(int fd);

/** @brief Disable SIGPIPE-style process termination for writes when available. */
llps_status_t llps_set_no_sigpipe(int fd);

/** @brief Enable TCP_NODELAY on a connected TCP socket. */
llps_status_t llps_set_tcp_nodelay(int fd);

/** @brief Send bytes while suppressing SIGPIPE on platforms that support it. */
ssize_t llps_send_no_sigpipe(int fd, const void *buf, size_t len);

/**
 * @brief Convert an IPv4 sockaddr into text and port components.
 */
llps_status_t llps_sockaddr_ipv4_text(const struct sockaddr *addr,
                                      char *out_ip,
                                      size_t out_ip_cap,
                                      uint16_t *out_port);

/**
 * @brief Convert a bounded IPv4 sockaddr into text and port components.
 */
llps_status_t llps_sockaddr_ipv4_text_len(const struct sockaddr *addr,
                                          socklen_t addr_len,
                                          char *out_ip,
                                          size_t out_ip_cap,
                                          uint16_t *out_port);

/**
 * @brief Resolve an IPv4 host/port pair into a sockaddr suitable for connect or bind.
 */
llps_status_t llps_resolve_ipv4_sockaddr(const char *host,
                                         uint16_t port,
                                         bool passive,
                                         struct sockaddr_in *addr);

#endif /* LLPS_NET_H */
