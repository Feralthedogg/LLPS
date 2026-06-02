/**
 * @file src/internal/llps_config.h
 * @brief Configuration parsing and validation for LLPS runtime options.
 *
 * @details
 * Configuration code owns text input normalization before values cross into
 * the runtime state.
 */

#ifndef LLPS_CONFIG_H
#define LLPS_CONFIG_H

#include "llps.h"

#include <stdint.h>

/*
 * LLPS bounded-resource configuration.
 *
 * Important safety note:
 * LLPS_MAX_CLIENTS * 2 * LLPS_BUFFER_SIZE is allocated statically.
 * With the default values below this is 2,097,152 bytes for payload
 * buffers alone. The full session table is larger due to metadata,
 * alignment, and platform-specific struct padding.
 *
 * This must be justified against the target memory budget and static
 * RAM map before certification use.
 */
/* Endpoint hosts may be IPv4 literals or DNS names; ports stay numeric. */
#define LLPS_LISTEN_HOST                   "127.0.0.1"
#define LLPS_LISTEN_PORT_U16               (25565u)
#define LLPS_TARGET_IP                     "127.0.0.1"
#define LLPS_TARGET_PORT_U16               (25566u)

/* Bounded accept-loop parameters. */
#define LLPS_LISTEN_BACKLOG                (256u)
#define LLPS_ACCEPT_BATCH_MAX              (32u)

/*
 * Task-count budget for bounded resource analysis.
 *
 * For each active session:
 * - 1 connection owner task
 * - 2 directional pump tasks
 *
 * Required tasks with defaults:
 * - session tasks:             256 * 3 = 768
 * - server task:               1
 * - watchdog task:             1
 * - readiness monitor task:    1
 * - total reserved capacity:   771
 *
 * If LLAM_MAX_TASKS is exposed before this header is included, this file
 * checks it at compile time. Otherwise, validate this budget in the build
 * configuration or runtime integration tests.
 */
#define LLPS_CONNECTION_TASKS_PER_SESSION  (1u)
#define LLPS_PUMPS_PER_SESSION             (2u)
#define LLPS_TASKS_PER_SESSION             \
    (LLPS_CONNECTION_TASKS_PER_SESSION + LLPS_PUMPS_PER_SESSION)

#define LLPS_MAX_SESSION_TASKS             \
    (LLPS_MAX_CLIENTS * LLPS_TASKS_PER_SESSION)

#define LLPS_MAX_SERVER_TASKS              (1u)
#define LLPS_WATCHDOG_TASKS                (1u)
#define LLPS_READINESS_MONITOR_TASKS       (1u)
#define LLPS_MAX_TASKS_REQUIRED            \
    (LLPS_MAX_SESSION_TASKS + \
     LLPS_MAX_SERVER_TASKS + \
     LLPS_WATCHDOG_TASKS + \
     LLPS_READINESS_MONITOR_TASKS)

/*
 * Runtime safety budgets.
 *
 * Watchdog timeout is intentionally finite: silent client/backend stalls are
 * treated as failed sessions and are forced into teardown instead of consuming
 * a static session slot forever.
 */
#define LLPS_NSEC_PER_SEC                  (1000000000ULL)
#define LLPS_NSEC_PER_MSEC                 (1000000ULL)
#define LLPS_WATCHDOG_SCAN_INTERVAL_NS     (1ULL * LLPS_NSEC_PER_SEC)
#define LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT (30000u)
#define LLPS_SESSION_IDLE_TIMEOUT_MS_MIN   (2000u)
#define LLPS_SESSION_IDLE_TIMEOUT_MS_MAX   (600000u)
#define LLPS_SESSION_IDLE_TIMEOUT_NS \
    ((uint64_t)LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT * LLPS_NSEC_PER_MSEC)
#define LLPS_CLIENT_IP_RATE_LIMIT_MAX      (100000u)
#define LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT (1000u)
#define LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN  (100u)
#define LLPS_CLIENT_IP_RATE_WINDOW_MS_MAX  (600000u)
#define LLPS_CLIENT_IP_RATE_BUCKET_COUNT   LLPS_MAX_CLIENTS
#define LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_FREE   (0xA11F4EEDu)
#define LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_ACTIVE (0xA11FCAFEu)
#define LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT  (0u)
#define LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN      (100u)
#define LLPS_CLIENT_PREFACE_TIMEOUT_MS_MAX      (600000u)
#define LLPS_CLIENT_PREFACE_POLL_TIMEOUT_MS     (10)
#define LLPS_PROTOCOL_HANDSHAKE_GATE_DEFAULT  (0u)
#define LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX (255u)
#define LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX (1024u)

/* LLPS free-list/session tables are intentionally protected by scheduler
 * configuration rather than internal mutexes. The executable verifies the
 * matching LLAM runtime worker/node contract again at startup. */
#ifndef LLPS_REQUIRE_SINGLE_LLAM_WORKER
#define LLPS_REQUIRE_SINGLE_LLAM_WORKER    (1u)
#endif

/*
 * Per-read write retry budget. This prevents a single pump from staying inside
 * one write-drain decision forever when the peer never becomes writable.
 */
#define LLPS_IO_RETRY_BUDGET               (1024u)

/*
 * File descriptor budget:
 * - one client fd per active session
 * - one backend fd per active session
 * - one listen fd
 */
#define LLPS_FDS_PER_SESSION               (2u)
#define LLPS_MAX_LISTEN_FDS                (1u)
#define LLPS_MAX_FDS_REQUIRED              \
    ((LLPS_MAX_CLIENTS * LLPS_FDS_PER_SESSION) + LLPS_MAX_LISTEN_FDS)

#ifdef LLAM_MAX_TASKS
_Static_assert(LLAM_MAX_TASKS >= LLPS_MAX_TASKS_REQUIRED,
               "LLAM task capacity too small for LLPS");
#endif

/* File descriptor sentinel. */
#define LLPS_INVALID_FD                    (-1)

/* Basic resource bounds. */
_Static_assert(LLPS_MAX_CLIENTS > 0u,
               "LLPS_MAX_CLIENTS must be positive");
_Static_assert(LLPS_BUFFER_SIZE > 0u,
               "LLPS_BUFFER_SIZE must be positive");
_Static_assert(LLPS_BUFFER_SIZE <= 65536u,
               "LLPS_BUFFER_SIZE should remain analysis-friendly");
_Static_assert(LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX <= LLPS_BUFFER_SIZE,
               "Protocol handshake gate requires a buffer-sized packet cap");
_Static_assert(LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX <
               LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX,
               "Protocol handshake address cap must fit packet cap");

/* Endpoint sanity. */
_Static_assert(sizeof(LLPS_LISTEN_HOST) > 1u,
               "listen host must not be empty");
_Static_assert(sizeof(LLPS_TARGET_IP) > 1u,
               "target host must not be empty");
_Static_assert((LLPS_LISTEN_PORT_U16 > 0u) && (LLPS_LISTEN_PORT_U16 <= 65535u),
               "listen port must be in 1..65535");
_Static_assert((LLPS_TARGET_PORT_U16 > 0u) && (LLPS_TARGET_PORT_U16 <= 65535u),
               "target port must be in 1..65535");

/* Accept-loop sanity. */
_Static_assert(LLPS_ACCEPT_BATCH_MAX > 0u,
               "accept batch must be positive");
_Static_assert(LLPS_ACCEPT_BATCH_MAX <= LLPS_MAX_CLIENTS,
               "accept batch cannot exceed session count");
_Static_assert((LLPS_LISTEN_BACKLOG > 0u) && (LLPS_LISTEN_BACKLOG <= 32767u),
               "listen backlog must remain safely castable to int");
_Static_assert(LLPS_LISTEN_BACKLOG >= LLPS_ACCEPT_BATCH_MAX,
               "listen backlog should cover one accept batch");

/* Task/Fd budget arithmetic sanity. */
_Static_assert(LLPS_CONNECTION_TASKS_PER_SESSION == 1u,
               "connection task budget must match implementation");
_Static_assert(LLPS_PUMPS_PER_SESSION == 2u,
               "pump task budget must match implementation");
_Static_assert(LLPS_TASKS_PER_SESSION == 3u,
               "tasks per session must match implementation");
_Static_assert(LLPS_MAX_SERVER_TASKS == 1u,
               "server task budget must match implementation");
_Static_assert(LLPS_WATCHDOG_TASKS == 1u,
               "watchdog task budget must match implementation");
_Static_assert(LLPS_READINESS_MONITOR_TASKS == 1u,
               "readiness monitor task budget must match implementation");
_Static_assert(LLPS_SESSION_TMR_BANK_COUNT == 3u,
               "TMR requires exactly three metadata banks");
_Static_assert(LLPS_REQUIRE_SINGLE_LLAM_WORKER == 1u,
               "LLPS free-list assumes exactly one LLAM worker/node");
_Static_assert(LLPS_MAX_CLIENTS <= UINT32_MAX,
               "session count must fit uint32_t session indexes");
_Static_assert(LLPS_SESSION_IDLE_TIMEOUT_NS > LLPS_WATCHDOG_SCAN_INTERVAL_NS,
               "watchdog timeout must exceed scan interval");
_Static_assert(LLPS_SESSION_IDLE_TIMEOUT_MS_MIN > 0u,
               "minimum idle timeout must be positive");
_Static_assert(LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT >=
                   LLPS_SESSION_IDLE_TIMEOUT_MS_MIN,
               "default idle timeout must satisfy minimum");
_Static_assert(LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT <=
                   LLPS_SESSION_IDLE_TIMEOUT_MS_MAX,
               "default idle timeout must satisfy maximum");
_Static_assert(LLPS_CLIENT_IP_RATE_LIMIT_MAX >= LLPS_MAX_CLIENTS,
               "rate limit maximum must cover the session pool");
_Static_assert(LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN > 0u,
               "rate-limit window minimum must be nonzero");
_Static_assert(LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT >=
                   LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN,
               "default rate-limit window must satisfy minimum");
_Static_assert(LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT <=
                   LLPS_CLIENT_IP_RATE_WINDOW_MS_MAX,
               "default rate-limit window must satisfy maximum");
_Static_assert(LLPS_CLIENT_IP_RATE_BUCKET_COUNT >= LLPS_MAX_CLIENTS,
               "rate bucket table must cover maximum active clients");
_Static_assert(LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN > 0u,
               "preface timeout minimum must be nonzero");
_Static_assert(LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT == 0u,
               "preface timeout default must keep compatibility");
_Static_assert(LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN <=
                   LLPS_CLIENT_PREFACE_TIMEOUT_MS_MAX,
               "preface timeout range must be ordered");
_Static_assert(LLPS_CLIENT_PREFACE_POLL_TIMEOUT_MS > 0,
               "preface poll timeout must be positive");
_Static_assert(LLPS_IO_RETRY_BUDGET > 0u,
               "I/O retry budget must be positive");

/* Static payload memory budget. */
#define LLPS_PAYLOAD_BUFFER_BYTES \
    ((uint64_t)LLPS_MAX_CLIENTS * 2ULL * (uint64_t)LLPS_BUFFER_SIZE)

_Static_assert(LLPS_PAYLOAD_BUFFER_BYTES <= (8ULL * 1024ULL * 1024ULL),
               "payload buffer budget exceeded");

#endif /* LLPS_CONFIG_H */
