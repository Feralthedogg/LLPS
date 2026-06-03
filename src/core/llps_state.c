/**
 * @file src/core/llps_state.c
 * @brief Core LLPS session lifecycle, proxy tasks, and watchdog orchestration.
 *
 * @details
 * The core layer coordinates LLAM tasks and delegates platform, session,
 * and audit details to narrower modules.
 */

#include "llps.h"
#include "llps_config_validate.h"
#include "llps_control_flag.h"
#include "llps_crc.h"
#include "llps_domain.h"
#include "llps_edac.h"
#include "llps_evidence.h"
#include "llps_free_list_tmr.h"
#include "llps_guard.h"
#include "llps_internal.h"
#include "llps_config.h"
#include "llps_llam_contract.h"
#include "llps_log.h"
#include "llps_memory.h"
#include "llps_memory_report.h"
#include "llps_net.h"
#include "llps_ip_audit.h"
#include "llps_numa.h"
#include "llps_platform.h"
#include "llps_platform_evidence_runtime.h"
#include "llps_readiness.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_runtime_latches.h"
#include "llps_safety_counters.h"
#include "llps_secded.h"
#include "llps_session_integrity.h"
#include "llps_session_tmr.h"
#include "llps_software_evidence.h"
#include "llps_readiness_config.h"
#include "llps_readiness_monitor_worker.h"
#include "llps_readiness_runtime_failures.h"
#include "llps_tmr_layout.h"
#include "llps_tmr_memory_prep.h"
#include "llps_tmr_observer.h"
#include "llps_tmr_platform.h"

#include "llam/runtime.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LLPS_READINESS_RUNTIME_MONITOR_WORKER_TIMEOUT_NS \
    (LLPS_WATCHDOG_SCAN_INTERVAL_NS * 3ULL)
#define LLPS_ACCEPT_POLL_TIMEOUT_MS        (100)
#define LLPS_ACCEPT_IDLE_BACKOFF_MS        (1)
#define LLPS_ACCEPT_ERROR_BACKOFF_MS       (5)
#define LLPS_BACKEND_CONNECT_POLL_TIMEOUT_MS (10)
#define LLPS_BACKEND_CONNECT_POLL_ATTEMPTS (500u)
#define LLPS_PUMP_YIELD_AFTER_BYTES        (64u * 1024u)
#define LLPS_PUMP_INTEGRITY_CHECK_AFTER_BYTES (1024u * 1024u)
#define LLPS_SOCKET_IO_STEP_MAX            (LLPS_BUFFER_SIZE + \
                                            LLPS_IO_RETRY_BUDGET)
#define LLPS_LLAM_SLEEP_MS_TO_NS           ((uint64_t)1000000u)
#ifndef LLAM_PREEMPT_POLL_EVERY
#define LLAM_PREEMPT_POLL_EVERY(counter, interval) \
    do { \
        (void)(counter); \
        (void)(interval); \
    } while (0)
#endif
static llps_yml_config_t g_runtime_cfg;
static struct sockaddr_in g_backend_addr;
static bool g_backend_addr_valid = false;
#if !defined(LLPS_TEST_HOOKS)
static int g_watchdog_sleep_pipe[2] = { LLPS_INVALID_FD, LLPS_INVALID_FD };
#endif
static llps_session_t g_sessions[LLPS_MAX_CLIENTS];
static const char *g_edac_sysfs_root = LLPS_EDAC_SYSFS_ROOT;
static const char *g_boot_id_path = LLPS_BOOT_ID_PATH;
static const char *g_platform_id_path = LLPS_PLATFORM_ID_PATH;
static const char *g_executable_image_path = NULL;
static const char *g_numa_sysfs_root = LLPS_NUMA_SYSFS_ROOT;
typedef struct {
    uint32_t magic_start;
    char client_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint64_t window_start_ns;
    uint64_t window_start_ns_inverse;
    uint32_t count;
    uint32_t count_inverse;
    uint32_t crc;
    uint32_t crc_inverse;
    uint32_t magic_end;
} llps_client_ip_rate_bucket_t;

typedef struct {
    bool domains_observed;
    uint32_t fingerprint;
    uint32_t topology_coverage;
    uint32_t observed_count;
    uint64_t memtotal_kib;
    uint64_t distance_entries;
    uint64_t distance_sum;
    uint32_t distance_pair_coverage;
    uint64_t distance_01;
    uint64_t distance_02;
    uint64_t distance_12;
} llps_synthetic_numa_observation_t;

typedef struct {
    llps_client_ip_rate_bucket_t *matching_bucket;
    llps_client_ip_rate_bucket_t *free_bucket;
    bool integrity_fault;
} llps_client_ip_rate_bucket_search_t;

typedef struct {
    llps_pump_args_t *pump;
    llps_session_t *sess;
    uint8_t *payload_ecc;
    uint32_t session_id;
    bool payload_ecc_enabled;
    llps_close_reason_t close_reason;
} llps_pump_context_t;

typedef struct {
    llam_fd_t client_fd;
    char client_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint16_t client_port;
    uint64_t request_no;
} llps_accept_client_t;

static llps_client_ip_rate_bucket_t
    g_client_ip_rate_buckets[LLPS_CLIENT_IP_RATE_BUCKET_COUNT];
/*
 * O(1) Free-list stack for session allocation.
 * Contains indices [0, LLPS_MAX_CLIENTS-1].
 *
 * Concurrency assumption:
 * LLAM tasks must run cooperatively on one runtime worker and one I/O node. The executable
 * initializes LLAM with deterministic worker policy and refuses startup if the
 * runtime stats report worker/node fanout or experimental worker queues. If that
 * contract changes, session allocation/free must grow a mutex or atomic
 * protocol before LLPS_REQUIRE_SINGLE_LLAM_WORKER may be relaxed.
 */
static uint32_t g_free_sessions[LLPS_MAX_CLIENTS];
static uint32_t g_free_sessions_count = 0u;
static uint64_t g_request_no = 0u;
static uint64_t g_request_no_inverse = UINT64_MAX;

static void llps_request_counter_reset(void) {
    g_request_no = 0u;
    g_request_no_inverse = UINT64_MAX;
}

static bool llps_request_counter_is_valid(void) {
    return g_request_no_inverse == ~g_request_no;
}

static bool llps_next_request_no(uint64_t * const out_request_no) {
    if (out_request_no == NULL) {
        return false;
    }

    if (!llps_request_counter_is_valid() || (g_request_no == UINT64_MAX)) {
        return false;
    }

    ++g_request_no;
    g_request_no_inverse = ~g_request_no;
    *out_request_no = g_request_no;
    return true;
}

static bool llps_state_copy_text(char * const dst,
                                 const size_t dst_cap,
                                 const char * const src) {
    size_t i = 0u;

    if ((dst == NULL) || (src == NULL) || (dst_cap == 0u)) {
        return false;
    }

    for (i = 0u; i < dst_cap; ++i) {
        dst[i] = src[i];
        if (src[i] == '\0') {
            return true;
        }
    }

    dst[dst_cap - 1u] = '\0';
    return false;
}

static uint32_t llps_client_ip_rate_bucket_compute_crc(
    const llps_client_ip_rate_bucket_t * const bucket) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (bucket == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, bucket->magic_start);
    for (size_t i = 0u; i < sizeof(bucket->client_ip); ++i) {
        crc = llps_crc32_update_byte(crc, (uint8_t)bucket->client_ip[i]);
    }
    crc = llps_crc32_update_u64(crc, bucket->window_start_ns);
    crc = llps_crc32_update_u64(crc, bucket->window_start_ns_inverse);
    crc = llps_crc32_update_u32(crc, bucket->count);
    crc = llps_crc32_update_u32(crc, bucket->count_inverse);
    crc = llps_crc32_update_u32(crc, bucket->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static bool llps_client_ip_rate_bucket_magic_is_valid(
    const uint32_t magic) {
    return (magic == LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_FREE) ||
           (magic == LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_ACTIVE);
}

static bool llps_client_ip_rate_bucket_is_valid(
    const llps_client_ip_rate_bucket_t * const bucket) {
    if (bucket == NULL) {
        return false;
    }

    return (bucket->magic_start == bucket->magic_end) &&
           llps_client_ip_rate_bucket_magic_is_valid(bucket->magic_start) &&
           (bucket->window_start_ns_inverse == ~bucket->window_start_ns) &&
           (bucket->count_inverse == ~bucket->count) &&
           (bucket->crc_inverse == ~bucket->crc) &&
           (bucket->crc == llps_client_ip_rate_bucket_compute_crc(bucket));
}

static bool llps_client_ip_rate_bucket_is_active(
    const llps_client_ip_rate_bucket_t * const bucket) {
    return (bucket != NULL) &&
           (bucket->magic_start ==
            LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_ACTIVE);
}

static void llps_client_ip_rate_bucket_refresh_crc(
    llps_client_ip_rate_bucket_t * const bucket) {
    if (bucket != NULL) {
        bucket->crc = llps_client_ip_rate_bucket_compute_crc(bucket);
        bucket->crc_inverse = ~bucket->crc;
    }
}

static void llps_client_ip_rate_bucket_reset(
    llps_client_ip_rate_bucket_t * const bucket) {
    if (bucket != NULL) {
        bucket->magic_start = LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_FREE;
        (void)memset(bucket->client_ip, 0, sizeof(bucket->client_ip));
        bucket->window_start_ns = 0u;
        bucket->window_start_ns_inverse = UINT64_MAX;
        bucket->count = 0u;
        bucket->count_inverse = UINT32_MAX;
        bucket->magic_end = LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_FREE;
        llps_client_ip_rate_bucket_refresh_crc(bucket);
    }
}

static bool llps_client_ip_rate_bucket_write(
    llps_client_ip_rate_bucket_t * const bucket,
    const char * const client_ip,
    const uint64_t window_start_ns,
    const uint32_t count) {
    if ((bucket == NULL) || (client_ip == NULL)) {
        return false;
    }

    bucket->magic_start = LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_ACTIVE;
    if (!llps_state_copy_text(bucket->client_ip,
                              sizeof(bucket->client_ip),
                              client_ip)) {
        llps_client_ip_rate_bucket_reset(bucket);
        return false;
    }
    bucket->window_start_ns = window_start_ns;
    bucket->window_start_ns_inverse = ~window_start_ns;
    bucket->count = count;
    bucket->count_inverse = ~count;
    bucket->magic_end = LLPS_CLIENT_IP_RATE_BUCKET_MAGIC_ACTIVE;
    llps_client_ip_rate_bucket_refresh_crc(bucket);

    return true;
}

static void llps_client_ip_rate_buckets_reset(void) {
    for (uint32_t i = 0u; i < LLPS_CLIENT_IP_RATE_BUCKET_COUNT; ++i) {
        llps_client_ip_rate_bucket_reset(&g_client_ip_rate_buckets[i]);
    }
}

static void llps_llam_contract_failure(const char * const operation) {
    llps_logf("llam_contract_failure operation=%s",
              (operation != NULL) ? operation : "unknown");
#if !defined(LLPS_TEST_HOOKS)
    llam_dump_runtime_state(STDERR_FILENO);
#else
    (void)operation;
#endif
}

static bool llps_llam_spawn_opts_prepare(llam_spawn_opts_t * const opts,
                                         const uint32_t task_class,
                                         const uint32_t flags) {
    if (opts == NULL) {
        LLPS_EXPECT(false,
                    llps_llam_contract_failure("spawn_opts_prepare_args"));
        return false;
    }

    if (llam_spawn_opts_init(opts, LLAM_SPAWN_OPTS_CURRENT_SIZE) != 0) {
        LLPS_EXPECT(false, llps_llam_contract_failure("spawn_opts_init"));
        return false;
    }

    opts->task_class = task_class;
    opts->stack_class = LLAM_STACK_CLASS_DEFAULT;
    opts->flags |= flags;
    return true;
}

static int llps_llam_poll_fd_checked(const int fd,
                                     const short events,
                                     const int timeout_ms,
                                     short * const revents,
                                     const char * const operation) {
    int poll_rc = -1;

    if (!llps_fd_is_valid(fd) ||
        (events == 0) ||
        (timeout_ms < -1) ||
        (revents == NULL) ||
        (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return -1;
    }

    poll_rc = llam_poll_fd(fd, events, timeout_ms, revents);

    if ((poll_rc < 0) && !llps_control_shutdown_is_requested()) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return poll_rc;
}

static ssize_t llps_llam_read_when_ready_checked(
    const int fd,
    void * const buf,
    const size_t count,
    const int timeout_ms,
    const char * const operation) {
    ssize_t read_rc = -1;

    if (!llps_fd_is_valid(fd) ||
        (buf == NULL) ||
        (count == 0u) ||
        (count > (size_t)SSIZE_MAX) ||
        (timeout_ms < -1) ||
        (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return -1;
    }

    read_rc = llam_read_when_ready(fd, buf, count, timeout_ms);

    if ((read_rc < 0) &&
        (errno != ETIMEDOUT) &&
        !llps_control_shutdown_is_requested()) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return read_rc;
}

static void llps_llam_yield_checked(const char * const operation) {
    LLPS_EXPECT(operation != NULL,
                llps_llam_contract_failure("yield_operation"));
    llam_yield();
}

static bool llps_llam_sleep_ms_checked(const int sleep_ms,
                                       const char * const operation) {
    uint64_t sleep_ns = 0u;

    if (operation == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure("sleep_operation"));
        return false;
    }

    if (sleep_ms <= 0) {
        llps_llam_yield_checked(operation);
        return true;
    }

    sleep_ns = (uint64_t)sleep_ms * LLPS_LLAM_SLEEP_MS_TO_NS;
    if ((llam_sleep_ns(sleep_ns) != 0) && !llps_control_shutdown_is_requested()) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    return true;
}

static llam_task_t *llps_llam_spawn_checked(llam_task_fn fn,
                                            void * const arg,
                                            const llam_spawn_opts_t * const opts,
                                            const char * const operation) {
    llam_task_t *task = NULL;

    if ((fn == NULL) || (opts == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return NULL;
    }

    task = llam_spawn(fn, arg, opts);

    if (task == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return task;
}

static bool llps_llam_detach_checked(llam_task_t * const task,
                                     const char * const operation) {
    if ((task == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    if (llam_detach(task) != 0) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    return true;
}

static llam_task_group_t *llps_llam_task_group_create_checked(
    const char * const operation) {
    llam_task_group_t *group = NULL;

    if (operation == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure("task_group_create"));
        return NULL;
    }

    group = llam_task_group_create();

    if (group == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return group;
}

static bool llps_llam_task_group_join_checked(
    llam_task_group_t * const group,
    const char * const operation) {
    if ((group == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    if (llam_task_group_join(group) != 0) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    return true;
}

static llam_task_t *llps_llam_task_group_spawn_checked(
    llam_task_group_t * const group,
    llam_task_fn fn,
    void * const arg,
    const llam_spawn_opts_t * const opts,
    const char * const operation) {
    llam_task_t *task = NULL;

    if ((group == NULL) || (fn == NULL) || (opts == NULL) ||
        (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return NULL;
    }

    task = llam_task_group_spawn(group, fn, arg, opts);

    if (task == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return task;
}

static bool llps_llam_task_group_destroy_checked(
    llam_task_group_t * const group,
    const char * const operation) {
    if ((group == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    if (llam_task_group_destroy(group) != 0) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
        return false;
    }

    return true;
}

static uint64_t llps_llam_now_ns_checked(const char * const operation) {
    const uint64_t now_ns = llam_now_ns();

    if (operation == NULL) {
        LLPS_EXPECT(false, llps_llam_contract_failure("now_operation"));
    }

    if (now_ns == 0u) {
        LLPS_EXPECT(false, llps_llam_contract_failure(operation));
    }

    return now_ns;
}

#if !defined(LLPS_TEST_HOOKS)
static bool llps_llam_runtime_contract_check(void) {
    llam_runtime_stats_t stats;

    (void)memset(&stats, 0, sizeof(stats));
    if (llam_runtime_collect_stats_ex(&stats,
                                      LLAM_RUNTIME_STATS_CURRENT_SIZE) != 0) {
        LLPS_EXPECT(false, llps_llam_contract_failure("runtime_stats"));
        return false;
    }

    if (!llps_llam_runtime_stats_satisfy_single_worker_contract(&stats)) {
        LLPS_EXPECT(false, llps_llam_contract_failure("runtime_worker_policy"));
        return false;
    }
    return true;
}
#endif

static bool llps_free_list_scheduler_contract_is_valid(void) {
#if !defined(LLPS_TEST_HOOKS)
    return llps_llam_runtime_contract_check();
#else
    return true;
#endif
}

#if !defined(LLPS_TEST_HOOKS)
static void llps_watchdog_sleep_pipe_close(void) {
    if (llps_fd_is_valid(g_watchdog_sleep_pipe[0])) {
        (void)close(g_watchdog_sleep_pipe[0]);
        g_watchdog_sleep_pipe[0] = LLPS_INVALID_FD;
    }

    if (llps_fd_is_valid(g_watchdog_sleep_pipe[1])) {
        (void)close(g_watchdog_sleep_pipe[1]);
        g_watchdog_sleep_pipe[1] = LLPS_INVALID_FD;
    }
}

static void llps_watchdog_sleep_pipe_init(void) {
    int fds[2] = { LLPS_INVALID_FD, LLPS_INVALID_FD };

    llps_watchdog_sleep_pipe_close();

    if (pipe(fds) != 0) {
        return;
    }

    if ((llps_set_nonblocking(fds[0]) != LLPS_OK) ||
        (llps_set_nonblocking(fds[1]) != LLPS_OK)) {
        if (llps_fd_is_valid(fds[0])) {
            (void)close(fds[0]);
        }
        if (llps_fd_is_valid(fds[1])) {
            (void)close(fds[1]);
        }
        return;
    }

    g_watchdog_sleep_pipe[0] = fds[0];
    g_watchdog_sleep_pipe[1] = fds[1];
}

static void llps_watchdog_sleep_ms(const int sleep_ms) {
    short dummy_revents = 0;

    if (llps_fd_is_valid(g_watchdog_sleep_pipe[0])) {
        (void)llps_llam_poll_fd_checked(g_watchdog_sleep_pipe[0],
                                        POLLIN,
                                        sleep_ms,
                                        &dummy_revents,
                                        "watchdog_sleep_poll");
        return;
    }

    (void)llps_llam_sleep_ms_checked(sleep_ms, "watchdog_sleep");
}
#else
static void llps_watchdog_sleep_pipe_init(void) {
}

static void llps_watchdog_sleep_pipe_close(void) {
}

static void llps_watchdog_sleep_ms(const int sleep_ms) {
    (void)llps_llam_sleep_ms_checked(sleep_ms, "watchdog_sleep_test");
}
#endif

static bool llps_accept_errno_is_retryable(const int err) {
    bool retryable = (err == EAGAIN) ||
                     (err == EWOULDBLOCK) ||
                     (err == EINTR) ||
                     (err == ECONNABORTED);

#ifdef ENETDOWN
    retryable = retryable || (err == ENETDOWN);
#endif
#ifdef EPROTO
    retryable = retryable || (err == EPROTO);
#endif
#ifdef ENOPROTOOPT
    retryable = retryable || (err == ENOPROTOOPT);
#endif
#ifdef EHOSTDOWN
    retryable = retryable || (err == EHOSTDOWN);
#endif
#ifdef ENONET
    retryable = retryable || (err == ENONET);
#endif
#ifdef EHOSTUNREACH
    retryable = retryable || (err == EHOSTUNREACH);
#endif
#ifdef EOPNOTSUPP
    retryable = retryable || (err == EOPNOTSUPP);
#endif
#ifdef ENETUNREACH
    retryable = retryable || (err == ENETUNREACH);
#endif

    return retryable;
}

static bool llps_accept_errno_is_resource_pressure(const int err) {
    bool resource_pressure = (err == EMFILE) ||
                             (err == ENFILE) ||
                             (err == ENOMEM);

#ifdef ENOBUFS
    resource_pressure = resource_pressure || (err == ENOBUFS);
#endif

    return resource_pressure;
}

static bool llps_accept_errno_is_listener_fault(const int err) {
    return (err == EBADF) ||
           (err == EINVAL) ||
           (err == ENOTSOCK);
}

static bool llps_handle_accept_error(const int accept_err) {
    const int err = (accept_err != 0) ? accept_err : EIO;

    if (llps_accept_errno_is_retryable(err)) {
        llps_logf("accept_retryable errno=%d", err);
        return true;
    }

    if (llps_accept_errno_is_resource_pressure(err)) {
        llps_logf("accept_backoff reason=resource_pressure errno=%d backoff_ms=%d",
                  err,
                  LLPS_ACCEPT_ERROR_BACKOFF_MS);
        llps_watchdog_sleep_ms(LLPS_ACCEPT_ERROR_BACKOFF_MS);
        return true;
    }

    if (llps_accept_errno_is_listener_fault(err)) {
        llps_logf("accept_fatal reason=listener_fault errno=%d", err);
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    llps_logf("accept_backoff reason=unexpected errno=%d backoff_ms=%d",
              err,
              LLPS_ACCEPT_ERROR_BACKOFF_MS);
    llps_watchdog_sleep_ms(LLPS_ACCEPT_ERROR_BACKOFF_MS);
    return true;
}

/* --------------------------------------------------------------------
 * Contract and integrity helpers
 * -------------------------------------------------------------------- */

void llps_contract_violation(const char *file,
                             const int line,
                             const char *condition) {
    LLPS_MEMORY_SAFETY_COUNTER_INC(contract_violations);
    (void)fprintf(stderr,
                  "[CRITICAL] LLPS contract violated at %s:%d: %s\n",
                  (file != NULL) ? file : "<unknown>",
                  line,
                  (condition != NULL) ? condition : "<unknown>");
    (void)fflush(stderr);
}

static bool llps_session_index_from_ptr(const llps_session_t * const sess,
                                        uint32_t * const out_index) {
    ptrdiff_t diff = 0;

    if ((sess == NULL) || (out_index == NULL)) {
        return false;
    }

    if ((sess < &g_sessions[0]) || (sess >= &g_sessions[LLPS_MAX_CLIENTS])) {
        return false;
    }

    diff = sess - &g_sessions[0];
    if ((uint32_t)diff >= LLPS_MAX_CLIENTS) {
        return false;
    }

    *out_index = (uint32_t)diff;
    return true;
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_get_memory_safety_report(llps_memory_safety_report_t * const out_report) {
    return llps_build_memory_safety_report(&g_runtime_cfg,
                                           g_free_sessions,
                                           &g_free_sessions_count,
                                           out_report);
}

static llps_platform_evidence_context_t llps_platform_evidence_context(void) {
    llps_platform_evidence_context_t context;

    context.edac_sysfs_root = g_edac_sysfs_root;
    context.boot_id_path = g_boot_id_path;
    context.platform_id_path = g_platform_id_path;
    context.executable_image_path = g_executable_image_path;
    context.numa_sysfs_root = g_numa_sysfs_root;
    context.configured_platform_safety_flags =
        g_runtime_cfg.platform_safety_flags;
    context.configured_platform_safety_evidence_id =
        g_runtime_cfg.platform_safety_evidence_id;
    context.configured_platform_attestation_fingerprint =
        g_runtime_cfg.platform_attestation_fingerprint;
    context.configured_platform_observation_digest =
        g_runtime_cfg.platform_observation_digest;
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        context.configured_physical_memory_domain_ids[i] =
            g_runtime_cfg.platform_physical_memory_domains[i];
        context.configured_hardware_tmr_domain_ids[i] =
            g_runtime_cfg.platform_hardware_tmr_domains[i];
    }
    context.configured_hardware_tmr_voter_domain_id =
        g_runtime_cfg.platform_hardware_tmr_voter_domain;
    context.platform_evidence_mode = g_runtime_cfg.platform_evidence_mode;
    context.payload_ecc_enabled = g_runtime_cfg.payload_ecc_enabled != 0u;
    context.software_ecc_enabled = g_runtime_cfg.software_ecc_enabled != 0u;
    context.software_ecc_controller_count =
        g_runtime_cfg.software_ecc_controller_count;
    context.software_ecc_dimm_count = g_runtime_cfg.software_ecc_dimm_count;
    context.software_ecc_scrub_rate = g_runtime_cfg.software_ecc_scrub_rate;
    context.software_ecc_controller_corrected_error_count =
        g_runtime_cfg.software_ecc_controller_corrected_error_count;
    context.software_ecc_controller_uncorrected_error_count =
        g_runtime_cfg.software_ecc_controller_uncorrected_error_count;
    context.software_ecc_dimm_corrected_error_count =
        g_runtime_cfg.software_ecc_dimm_corrected_error_count;
    context.software_ecc_dimm_uncorrected_error_count =
        g_runtime_cfg.software_ecc_dimm_uncorrected_error_count;
    context.software_numa_enabled = g_runtime_cfg.software_numa_enabled != 0u;
    context.software_numa_memtotal_kib =
        g_runtime_cfg.software_numa_memtotal_kib;
    context.software_numa_local_distance =
        g_runtime_cfg.software_numa_local_distance;
    context.software_numa_remote_distance =
        g_runtime_cfg.software_numa_remote_distance;
    context.software_fault_injection_mode =
        g_runtime_cfg.software_fault_injection_mode;
    context.evidence_mac_enabled = g_runtime_cfg.evidence_mac_enabled != 0u;
    context.evidence_mac_key_path = g_runtime_cfg.evidence_mac_key_path;

    return context;
}

#if defined(LLPS_TEST_HOOKS)
static llps_status_t llps_make_platform_safety_evidence_raw(
    const uint32_t flags,
    const uint32_t observed_flags,
    const uint32_t attested_flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const llps_platform_evidence_context_t context =
        llps_platform_evidence_context();

    return llps_make_platform_safety_evidence_raw_in_context(
        &context,
        flags,
        observed_flags,
        attested_flags,
        evidence_id,
        physical_memory_domain_ids,
        hardware_tmr_domain_ids,
        hardware_tmr_voter_domain_id,
        out_evidence);
}
#endif

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_make_platform_safety_evidence(
    const uint32_t flags,
    const uint64_t evidence_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const llps_platform_evidence_context_t context =
        llps_platform_evidence_context();

    return llps_make_platform_safety_evidence_in_context(&context,
                                                         flags,
                                                         evidence_id,
                                                         out_evidence);
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_make_platform_safety_evidence_ex(
    const uint32_t flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const llps_platform_evidence_context_t context =
        llps_platform_evidence_context();

    return llps_make_platform_safety_evidence_ex_in_context(
        &context,
        flags,
        evidence_id,
        physical_memory_domain_ids,
        hardware_tmr_domain_ids,
        hardware_tmr_voter_domain_id,
        out_evidence);
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_collect_platform_safety_evidence(
    const uint32_t requested_flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const llps_platform_evidence_context_t context =
        llps_platform_evidence_context();

    return llps_collect_platform_safety_evidence_in_context(
        &context,
        requested_flags,
        evidence_id,
        physical_memory_domain_ids,
        hardware_tmr_domain_ids,
        hardware_tmr_voter_domain_id,
        out_evidence);
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_get_readiness_report(
    const llps_platform_safety_evidence_t * const evidence,
    llps_readiness_report_t * const out_report) {
    llps_memory_safety_report_t memory_report;
    const llps_platform_evidence_context_t context =
        llps_platform_evidence_context();
    llps_status_t status = LLPS_OK;

    if (out_report == NULL) {
        return LLPS_E_NULL;
    }

    (void)memset(out_report, 0, sizeof(*out_report));

    status = llps_get_memory_safety_report(&memory_report);
    if (status != LLPS_OK) {
        return status;
    }

    return llps_build_readiness_report_in_context(&context,
                                                       &memory_report,
                                                       evidence,
                                                       out_report);
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_require_readiness(
    const llps_platform_safety_evidence_t * const evidence) {
    llps_readiness_report_t report;
    const llps_status_t status =
        llps_get_readiness_report(evidence, &report);

    if (status != LLPS_OK) {
        return status;
    }

    if (!report.gate_passed) {
        return LLPS_E_STATE;
    }

    return LLPS_OK;
}

static bool llps_tmr_startup_self_test(void) {
    const llps_memory_safety_counters_t saved_counters =
        g_memory_safety_counters;
    uint32_t coverage = 0u;
    bool passed = false;

    llps_tmr_startup_self_test_set_coverage(0u);

    passed =
        llps_session_tmr_startup_self_test(g_runtime_cfg.max_clients,
                                           &coverage) &&
        llps_runtime_cfg_tmr_startup_self_test(&g_runtime_cfg, &coverage) &&
        llps_free_list_tmr_startup_self_test(g_free_sessions,
                                             &g_free_sessions_count,
                                             &g_runtime_cfg,
                                             &coverage) &&
        llps_control_flag_tmr_startup_self_test(&coverage) &&
        ((coverage & LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE) ==
         LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);

    llps_tmr_startup_self_test_set_coverage(coverage);
    g_memory_safety_counters = saved_counters;
    llps_memory_safety_counters_seal();
    return passed;
}

static bool llps_session_tmr_snapshot_from_session(
    const llps_session_t * const sess,
    llps_session_tmr_snapshot_t * const out_snapshot) {
    if ((sess == NULL) || (out_snapshot == NULL)) {
        return false;
    }

    out_snapshot->session_id = sess->session_id;
    out_snapshot->state = sess->state;
    out_snapshot->last_activity_ns = sess->last_activity_ns;
    out_snapshot->request_no = sess->request_no;
    out_snapshot->client_fd = sess->client_fd;
    out_snapshot->backend_fd = sess->backend_fd;
    out_snapshot->close_reason = sess->close_reason;
    (void)memcpy(out_snapshot->client_ip,
                 sess->client_ip,
                 sizeof(out_snapshot->client_ip));
    out_snapshot->client_port = sess->client_port;
    out_snapshot->c2s_payload_ecc_len = sess->c2s_payload_ecc_len;
    out_snapshot->s2c_payload_ecc_len = sess->s2c_payload_ecc_len;
    out_snapshot->session_crc = sess->integrity_crc;
    return true;
}

static void llps_session_tmr_write_all_from_session(
    const llps_session_t * const sess) {
    llps_session_tmr_snapshot_t snapshot;

    if (!llps_session_tmr_snapshot_from_session(sess, &snapshot)) {
        LLPS_EXPECT(false, return);
    }

    llps_session_tmr_write_all(&snapshot);
}

static void llps_session_refresh_crc(llps_session_t * const sess) {
    if (sess != NULL) {
        llps_session_refresh_secded(sess);
        sess->integrity_crc = llps_session_compute_crc(sess);
        sess->integrity_crc_inverse = ~sess->integrity_crc;
        llps_session_tmr_write_all_from_session(sess);
    }
}

static void llps_session_apply_tmr_snapshot(
    llps_session_t * const sess,
    const llps_session_tmr_snapshot_t * const snapshot) {
    if ((sess != NULL) && (snapshot != NULL)) {
        sess->session_id = snapshot->session_id;
        sess->state = snapshot->state;
        sess->state_inverse = llps_state_inverse_value(snapshot->state);
        sess->last_activity_ns = snapshot->last_activity_ns;
        sess->request_no = snapshot->request_no;
        sess->request_no_inverse = ~snapshot->request_no;
        sess->close_reason = snapshot->close_reason;
        sess->close_reason_inverse = ~snapshot->close_reason;
        sess->client_fd = snapshot->client_fd;
        sess->backend_fd = snapshot->backend_fd;
        (void)memcpy(sess->client_ip,
                     snapshot->client_ip,
                     sizeof(sess->client_ip));
        sess->client_port = snapshot->client_port;
        sess->client_port_inverse = ~((uint32_t)snapshot->client_port);
        sess->c2s_payload_ecc_len = snapshot->c2s_payload_ecc_len;
        sess->c2s_payload_ecc_len_inverse = ~snapshot->c2s_payload_ecc_len;
        sess->s2c_payload_ecc_len = snapshot->s2c_payload_ecc_len;
        sess->s2c_payload_ecc_len_inverse = ~snapshot->s2c_payload_ecc_len;
        sess->magic_start = llps_magic_for_state(snapshot->state);
        sess->magic_end = llps_magic_for_state(snapshot->state);
    }
}

static bool llps_session_snapshot_differs(
    const llps_session_t * const sess,
    const llps_session_tmr_snapshot_t * const snapshot,
    const bool local_secded_ok) {
    if ((sess == NULL) || (snapshot == NULL) || !local_secded_ok) {
        return true;
    }

    return (sess->session_id != snapshot->session_id) ||
           (sess->state != snapshot->state) ||
           (sess->state_inverse != llps_state_inverse_value(snapshot->state)) ||
           (sess->last_activity_ns != snapshot->last_activity_ns) ||
           (sess->request_no != snapshot->request_no) ||
           (sess->request_no_inverse != ~snapshot->request_no) ||
           (sess->close_reason != snapshot->close_reason) ||
           (sess->close_reason_inverse != ~snapshot->close_reason) ||
           (sess->client_fd != snapshot->client_fd) ||
           (sess->backend_fd != snapshot->backend_fd) ||
           (memcmp(sess->client_ip,
                   snapshot->client_ip,
                   sizeof(sess->client_ip)) != 0) ||
           (sess->client_port != snapshot->client_port) ||
           (sess->client_port_inverse != ~((uint32_t)snapshot->client_port)) ||
           (sess->c2s_payload_ecc_len != snapshot->c2s_payload_ecc_len) ||
           (sess->c2s_payload_ecc_len_inverse !=
            ~snapshot->c2s_payload_ecc_len) ||
           (sess->s2c_payload_ecc_len != snapshot->s2c_payload_ecc_len) ||
           (sess->s2c_payload_ecc_len_inverse !=
            ~snapshot->s2c_payload_ecc_len) ||
           (sess->magic_start != llps_magic_for_state(snapshot->state)) ||
           (sess->magic_end != llps_magic_for_state(snapshot->state));
}

static bool llps_session_reconcile_integrity(llps_session_t * const sess,
                                             llps_session_tmr_snapshot_t * const out_snapshot) {
    uint32_t session_index = 0u;
    llps_session_tmr_snapshot_t snapshot;
    uint32_t computed_crc = 0u;
    bool local_secded_ok = false;

    if ((sess == NULL) ||
        !llps_runtime_cfg_reconcile(&g_runtime_cfg) ||
        !llps_session_index_from_ptr(sess, &session_index) ||
        !llps_session_tmr_vote(session_index, g_runtime_cfg.max_clients, &snapshot)) {
        return false;
    }

    local_secded_ok = llps_session_repair_secded(sess);

    if (llps_session_snapshot_differs(sess, &snapshot, local_secded_ok)) {
        llps_session_apply_tmr_snapshot(sess, &snapshot);
    }

    llps_session_refresh_secded(sess);
    computed_crc = llps_session_compute_crc(sess);
    if (computed_crc != snapshot.session_crc) {
        return false;
    }

    sess->integrity_crc = computed_crc;
    sess->integrity_crc_inverse = ~computed_crc;
    if (!llps_session_local_integrity_is_valid(sess)) {
        return false;
    }

    if (out_snapshot != NULL) {
        *out_snapshot = snapshot;
    }

    return true;
}

static bool llps_session_is_active(llps_session_t * const sess) {
    llps_session_tmr_snapshot_t snapshot;

    if (!llps_session_reconcile_integrity(sess, &snapshot)) {
        return false;
    }

    return snapshot.state == ST_ACTIVE;
}

static bool llps_session_hot_path_is_active(
    const llps_session_t * const sess) {
    return (sess != NULL) &&
           (sess->magic_start == LLPS_SESSION_MAGIC_ACTIVE) &&
           (sess->magic_end == LLPS_SESSION_MAGIC_ACTIVE) &&
           (sess->state == ST_ACTIVE) &&
           (sess->state_inverse == llps_state_inverse_value(ST_ACTIVE)) &&
           (sess->request_no_inverse == ~sess->request_no) &&
           (sess->close_reason_inverse == ~sess->close_reason) &&
           llps_close_reason_is_valid(sess->close_reason) &&
           (sess->client_port_inverse == ~((uint32_t)sess->client_port));
}

static size_t llps_payload_ecc_word_count_for_len(const size_t len) {
    return (len + (LLPS_PAYLOAD_ECC_WORD_BYTES - 1u)) /
           LLPS_PAYLOAD_ECC_WORD_BYTES;
}

static size_t llps_payload_ecc_protected_len_for_len(const size_t len,
                                                     const size_t cap) {
    size_t protected_len =
        llps_payload_ecc_word_count_for_len(len) *
        LLPS_PAYLOAD_ECC_WORD_BYTES;

    if (protected_len > cap) {
        protected_len = cap;
    }

    return protected_len;
}

static uint64_t llps_payload_ecc_load_word(const uint8_t * const buf,
                                           const size_t len,
                                           const size_t word_index) {
    uint64_t word = 0u;
    const size_t base = word_index * LLPS_PAYLOAD_ECC_WORD_BYTES;

    if (buf == NULL) {
        return 0u;
    }

    for (size_t i = 0u; i < LLPS_PAYLOAD_ECC_WORD_BYTES; ++i) {
        const size_t pos = base + i;

        if (pos >= len) {
            break;
        }
        word |= ((uint64_t)buf[pos]) << (8u * i);
    }

    return word;
}

static void llps_payload_ecc_store_word(uint8_t * const buf,
                                        const size_t len,
                                        const size_t word_index,
                                        const uint64_t word) {
    const size_t base = word_index * LLPS_PAYLOAD_ECC_WORD_BYTES;

    if (buf == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_PAYLOAD_ECC_WORD_BYTES; ++i) {
        const size_t pos = base + i;

        if (pos >= len) {
            break;
        }
        buf[pos] = (uint8_t)((word >> (8u * i)) & UINT64_C(0xff));
    }
}

static bool llps_payload_ecc_zero_padding(uint8_t * const buf,
                                          const size_t len,
                                          const size_t cap) {
    size_t padded_len = 0u;

    if ((buf == NULL) || (len > cap) || (cap > LLPS_BUFFER_SIZE)) {
        return false;
    }

    padded_len = llps_payload_ecc_protected_len_for_len(len, cap);

    for (size_t i = len; i < padded_len; ++i) {
        buf[i] = 0u;
    }

    return true;
}

/* cppcheck-suppress constParameterPointer -- returns mutable shadow ECC. */
static uint8_t *llps_payload_ecc_for_pump(llps_session_t * const sess,
                                          const llps_pump_args_t * const pump) {
    if ((sess == NULL) || (pump == NULL)) {
        return NULL;
    }

    if ((pump->direction == LLPS_DIR_C2S) && (pump->buf == sess->c2s_buf)) {
        return sess->c2s_payload_ecc;
    }

    if ((pump->direction == LLPS_DIR_S2C) && (pump->buf == sess->s2c_buf)) {
        return sess->s2c_payload_ecc;
    }

    return NULL;
}

static bool llps_payload_ecc_set_len_for_pump(
    llps_session_t * const sess,
    const llps_pump_args_t * const pump,
    const size_t len) {
    uint32_t bounded_len = 0u;

    if ((sess == NULL) || (pump == NULL) || (len > LLPS_BUFFER_SIZE)) {
        return false;
    }

    bounded_len = (uint32_t)len;
    if ((pump->direction == LLPS_DIR_C2S) && (pump->buf == sess->c2s_buf)) {
        if ((sess->c2s_payload_ecc_len == bounded_len) &&
            (sess->c2s_payload_ecc_len_inverse == ~bounded_len)) {
            return true;
        }
        sess->c2s_payload_ecc_len = bounded_len;
        sess->c2s_payload_ecc_len_inverse = ~bounded_len;
        llps_session_refresh_crc(sess);
        return true;
    }

    if ((pump->direction == LLPS_DIR_S2C) && (pump->buf == sess->s2c_buf)) {
        if ((sess->s2c_payload_ecc_len == bounded_len) &&
            (sess->s2c_payload_ecc_len_inverse == ~bounded_len)) {
            return true;
        }
        sess->s2c_payload_ecc_len = bounded_len;
        sess->s2c_payload_ecc_len_inverse = ~bounded_len;
        llps_session_refresh_crc(sess);
        return true;
    }

    return false;
}

static bool llps_payload_ecc_seal(uint8_t * const buf,
                                  const size_t len,
                                  const size_t cap,
                                  uint8_t * const ecc,
                                  const size_t ecc_cap) {
    const size_t word_count = llps_payload_ecc_word_count_for_len(len);
    const size_t protected_len = llps_payload_ecc_protected_len_for_len(len,
                                                                       cap);

    if ((buf == NULL) || (ecc == NULL) || (len > cap) ||
        (word_count > ecc_cap) || (ecc_cap > LLPS_PAYLOAD_ECC_WORD_COUNT) ||
        !llps_payload_ecc_zero_padding(buf, len, cap)) {
        return false;
    }

    for (size_t i = 0u; i < word_count; ++i) {
        const uint64_t word =
            llps_payload_ecc_load_word(buf, protected_len, i);

        ecc[i] = llps_secded_encode_u64(word, 64u);
    }
    for (size_t i = word_count; i < ecc_cap; ++i) {
        ecc[i] = 0u;
    }

    return true;
}

static bool llps_payload_ecc_repair(uint8_t * const buf,
                                    const size_t len,
                                    const size_t cap,
                                    uint8_t * const ecc,
                                    const size_t ecc_cap) {
    const size_t word_count = llps_payload_ecc_word_count_for_len(len);
    const size_t protected_len = llps_payload_ecc_protected_len_for_len(len,
                                                                       cap);

    if ((buf == NULL) || (ecc == NULL) || (len > cap) ||
        (cap > LLPS_BUFFER_SIZE) || (word_count > ecc_cap) ||
        (ecc_cap > LLPS_PAYLOAD_ECC_WORD_COUNT)) {
        return false;
    }

    for (size_t i = 0u; i < word_count; ++i) {
        uint64_t word = llps_payload_ecc_load_word(buf, protected_len, i);
        const llps_secded_status_t status =
            llps_secded_repair_u64(&word, 64u, &ecc[i]);

        if (status == LLPS_SECDED_CORRECTED) {
            LLPS_MEMORY_SAFETY_COUNTER_INC(secded_single_bit_repairs);
            llps_payload_ecc_store_word(buf, protected_len, i, word);
        } else if (status == LLPS_SECDED_UNCORRECTABLE) {
            LLPS_MEMORY_SAFETY_COUNTER_INC(secded_double_bit_failures);
            LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
            return false;
        }
    }

    return true;
}

static bool llps_session_is_free(llps_session_t * const sess) {
    llps_session_tmr_snapshot_t snapshot;

    if (!llps_session_reconcile_integrity(sess, &snapshot)) {
        return false;
    }

    return snapshot.state == ST_FREE;
}

static void llps_session_reset_free(llps_session_t * const sess,
                                    const uint32_t session_id) {
    if (sess != NULL) {
        sess->session_id = session_id;
        sess->last_activity_ns = 0u;
        sess->request_no = 0u;
        sess->request_no_inverse = UINT64_MAX;
        sess->close_reason = (uint32_t)LLPS_CLOSE_REASON_NORMAL;
        sess->close_reason_inverse = ~sess->close_reason;
        sess->client_fd = LLPS_INVALID_FD;
        sess->backend_fd = LLPS_INVALID_FD;
        (void)memset(sess->client_ip, 0, sizeof(sess->client_ip));
        sess->client_port = 0u;
        sess->client_port_inverse = ~((uint32_t)0u);
        llps_reset_pump_args(&sess->pump_c2s);
        llps_reset_pump_args(&sess->pump_s2c);
        llps_secure_bzero(sess->c2s_buf, sizeof(sess->c2s_buf));
        llps_secure_bzero(sess->s2c_buf, sizeof(sess->s2c_buf));
        llps_secure_bzero(sess->c2s_payload_ecc,
                          sizeof(sess->c2s_payload_ecc));
        llps_secure_bzero(sess->s2c_payload_ecc,
                          sizeof(sess->s2c_payload_ecc));
        sess->c2s_payload_ecc_len = 0u;
        sess->c2s_payload_ecc_len_inverse = UINT32_MAX;
        sess->s2c_payload_ecc_len = 0u;
        sess->s2c_payload_ecc_len_inverse = UINT32_MAX;
        llps_session_set_state_fields(sess, ST_FREE);
        llps_session_refresh_crc(sess);
    }
}

static void llps_session_prepare_active_with_peer(
    llps_session_t * const sess,
    const uint32_t session_id,
    const int client_fd,
    const char * const client_ip,
    const uint16_t client_port,
    const uint64_t request_no) {
    if (sess != NULL) {
        sess->session_id = session_id;
        sess->client_fd = client_fd;
        sess->backend_fd = LLPS_INVALID_FD;
        (void)memset(sess->client_ip, 0, sizeof(sess->client_ip));
        (void)llps_state_copy_text(sess->client_ip,
                                   sizeof(sess->client_ip),
                                   (client_ip != NULL) ?
                                       client_ip : "0.0.0.0");
        sess->client_port = client_port;
        sess->client_port_inverse = ~((uint32_t)client_port);
        sess->request_no = request_no;
        sess->request_no_inverse = ~request_no;
        sess->close_reason = (uint32_t)LLPS_CLOSE_REASON_NORMAL;
        sess->close_reason_inverse = ~sess->close_reason;
        sess->last_activity_ns =
            llps_llam_now_ns_checked("session_prepare_now");
        llps_reset_pump_args(&sess->pump_c2s);
        llps_reset_pump_args(&sess->pump_s2c);
        llps_secure_bzero(sess->c2s_buf, sizeof(sess->c2s_buf));
        llps_secure_bzero(sess->s2c_buf, sizeof(sess->s2c_buf));
        llps_secure_bzero(sess->c2s_payload_ecc,
                          sizeof(sess->c2s_payload_ecc));
        llps_secure_bzero(sess->s2c_payload_ecc,
                          sizeof(sess->s2c_payload_ecc));
        sess->c2s_payload_ecc_len = 0u;
        sess->c2s_payload_ecc_len_inverse = UINT32_MAX;
        sess->s2c_payload_ecc_len = 0u;
        sess->s2c_payload_ecc_len_inverse = UINT32_MAX;
        llps_session_set_state_fields(sess, ST_ACTIVE);
        llps_session_refresh_crc(sess);
    }
}

#if defined(LLPS_TEST_HOOKS)
static void llps_session_prepare_active(llps_session_t * const sess,
                                        const uint32_t session_id,
                                        const int client_fd) {
    llps_session_prepare_active_with_peer(sess,
                                          session_id,
                                          client_fd,
                                          "0.0.0.0",
                                          0u,
                                          0u);
}
#endif

static void llps_session_touch(llps_session_t * const sess) {
    if (sess != NULL) {
        const uint64_t now = llps_llam_now_ns_checked("session_touch_now");
        /* Throttle TMR updates to once per second to avoid CRC overhead under load */
        if ((sess->last_activity_ns == 0u) ||
            ((now > sess->last_activity_ns) &&
             ((now - sess->last_activity_ns) > LLPS_NSEC_PER_SEC))) {
            sess->last_activity_ns = now;
            llps_session_refresh_crc(sess);
        }
    }
}

static bool llps_client_ip_text_matches(const char * const lhs,
                                        const char * const rhs) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_CLIENT_IP_TEXT_LEN; ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
        if (lhs[i] == '\0') {
            return true;
        }
    }

    return false;
}

static bool llps_client_ip_session_limit_exceeded(
    const char * const client_ip,
    uint32_t * const out_active,
    uint32_t * const out_limit) {
    uint32_t active = 0u;
    uint32_t limit = 0u;

    if (out_active != NULL) {
        *out_active = 0u;
    }
    if (out_limit != NULL) {
        *out_limit = 0u;
    }

    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        LLPS_EXPECT(false, llps_control_request_shutdown());
        return true;
    }

    limit = g_runtime_cfg.max_sessions_per_client_ip;
    if (out_limit != NULL) {
        *out_limit = limit;
    }

    if ((limit == 0u) || (client_ip == NULL) || (client_ip[0] == '\0')) {
        return false;
    }

    for (uint32_t i = 0u; i < g_runtime_cfg.max_clients; ++i) {
        llps_session_t * const sess = &g_sessions[i];
        if (llps_session_is_active(sess) &&
            llps_client_ip_text_matches(sess->client_ip, client_ip)) {
            ++active;
        }
    }

    if (out_active != NULL) {
        *out_active = active;
    }

    return active >= limit;
}

static void llps_client_ip_rate_outputs_init(
    uint32_t * const out_count,
    uint32_t * const out_limit,
    uint32_t * const out_window_ms,
    const char ** const out_reason) {
    if (out_count != NULL) {
        *out_count = 0u;
    }
    if (out_limit != NULL) {
        *out_limit = 0u;
    }
    if (out_window_ms != NULL) {
        *out_window_ms = 0u;
    }
    if (out_reason != NULL) {
        *out_reason = "client_ip_rate_limit";
    }
}

static bool llps_client_ip_rate_load_config(
    uint32_t * const out_limit,
    uint32_t * const out_window_ms,
    const char ** const out_reason) {
    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        LLPS_EXPECT(false, llps_control_request_shutdown());
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_config_fault";
        }
        return false;
    }

    if (out_limit != NULL) {
        *out_limit = g_runtime_cfg.max_new_sessions_per_client_ip_per_window;
    }
    if (out_window_ms != NULL) {
        *out_window_ms = g_runtime_cfg.client_ip_rate_window_ms;
    }

    return true;
}

static bool llps_client_ip_rate_bucket_is_expired(
    const llps_client_ip_rate_bucket_t * const bucket,
    const uint64_t now_ns,
    const uint64_t window_ns) {
    return (bucket != NULL) &&
           (now_ns >= bucket->window_start_ns) &&
           ((now_ns - bucket->window_start_ns) >= window_ns);
}

static llps_client_ip_rate_bucket_search_t llps_client_ip_rate_find_bucket(
    const char * const client_ip,
    const uint64_t now_ns,
    const uint64_t window_ns) {
    llps_client_ip_rate_bucket_search_t search = { NULL, NULL, false };

    for (uint32_t i = 0u; i < LLPS_CLIENT_IP_RATE_BUCKET_COUNT; ++i) {
        llps_client_ip_rate_bucket_t * const bucket =
            &g_client_ip_rate_buckets[i];

        if (!llps_client_ip_rate_bucket_is_valid(bucket)) {
            LLPS_EXPECT(false, llps_control_request_shutdown());
            search.integrity_fault = true;
            return search;
        }

        if (llps_client_ip_rate_bucket_is_active(bucket)) {
            if (llps_client_ip_text_matches(bucket->client_ip, client_ip)) {
                search.matching_bucket = bucket;
                return search;
            }
            if ((search.free_bucket == NULL) &&
                llps_client_ip_rate_bucket_is_expired(bucket, now_ns, window_ns)) {
                llps_client_ip_rate_bucket_reset(bucket);
                search.free_bucket = bucket;
            }
        } else if (search.free_bucket == NULL) {
            search.free_bucket = bucket;
        }
    }

    return search;
}

static bool llps_client_ip_rate_consume_existing(
    llps_client_ip_rate_bucket_t * const bucket,
    const char * const client_ip,
    const uint64_t now_ns,
    const uint64_t window_ns,
    const uint32_t limit,
    uint32_t * const out_count,
    const char ** const out_reason) {
    uint32_t count = bucket->count;

    if (!llps_client_ip_rate_bucket_is_expired(bucket, now_ns, window_ns) &&
        (now_ns >= bucket->window_start_ns)) {
        if (out_count != NULL) {
            *out_count = count;
        }
    } else {
        count = 0u;
        if (!llps_client_ip_rate_bucket_write(bucket, client_ip, now_ns, 0u)) {
            if (out_reason != NULL) {
                *out_reason = "client_ip_rate_integrity";
            }
            return true;
        }
    }

    if (count >= limit) {
        return true;
    }

    ++count;
    if (!llps_client_ip_rate_bucket_write(bucket,
                                          client_ip,
                                          bucket->window_start_ns,
                                          count)) {
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_integrity";
        }
        return true;
    }
    if (out_count != NULL) {
        *out_count = count;
    }
    return false;
}

static bool llps_client_ip_rate_consume_new(
    llps_client_ip_rate_bucket_t * const bucket,
    const char * const client_ip,
    const uint64_t now_ns,
    uint32_t * const out_count,
    const char ** const out_reason) {
    if (bucket == NULL) {
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_table_full";
        }
        return true;
    }

    if (!llps_client_ip_rate_bucket_write(bucket, client_ip, now_ns, 1u)) {
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_integrity";
        }
        return true;
    }
    if (out_count != NULL) {
        *out_count = 1u;
    }

    return false;
}

static bool llps_client_ip_rate_consume_search(
    const llps_client_ip_rate_bucket_search_t * const search,
    const char * const client_ip,
    const uint64_t now_ns,
    const uint64_t window_ns,
    const uint32_t limit,
    uint32_t * const out_count,
    const char ** const out_reason) {
    if ((search == NULL) || search->integrity_fault) {
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_integrity";
        }
        return true;
    }

    if (search->matching_bucket != NULL) {
        return llps_client_ip_rate_consume_existing(search->matching_bucket,
                                                    client_ip,
                                                    now_ns,
                                                    window_ns,
                                                    limit,
                                                    out_count,
                                                    out_reason);
    }

    return llps_client_ip_rate_consume_new(search->free_bucket,
                                           client_ip,
                                           now_ns,
                                           out_count,
                                           out_reason);
}

static bool llps_client_ip_rate_limit_exceeded(
    const char * const client_ip,
    uint32_t * const out_count,
    uint32_t * const out_limit,
    uint32_t * const out_window_ms,
    const char ** const out_reason) {
    llps_client_ip_rate_bucket_search_t search;
    uint32_t limit = 0u;
    uint32_t window_ms = 0u;
    uint64_t now_ns = 0u;
    uint64_t window_ns = 0u;

    llps_client_ip_rate_outputs_init(out_count,
                                     out_limit,
                                     out_window_ms,
                                     out_reason);
    if (!llps_client_ip_rate_load_config(&limit, &window_ms, out_reason)) {
        return true;
    }
    if (out_limit != NULL) {
        *out_limit = limit;
    }
    if (out_window_ms != NULL) {
        *out_window_ms = window_ms;
    }

    if ((limit == 0u) || (client_ip == NULL) || (client_ip[0] == '\0')) {
        return false;
    }

    now_ns = llps_llam_now_ns_checked("client_ip_rate_now");
    if (now_ns == 0u) {
        if (out_reason != NULL) {
            *out_reason = "client_ip_rate_time_fault";
        }
        return true;
    }
    window_ns = (uint64_t)window_ms * LLPS_NSEC_PER_MSEC;
    search = llps_client_ip_rate_find_bucket(client_ip, now_ns, window_ns);

    return llps_client_ip_rate_consume_search(&search,
                                              client_ip,
                                              now_ns,
                                              window_ns,
                                              limit,
                                              out_count,
                                              out_reason);
}

static bool llps_free_list_contains(const uint32_t session_id) {
    if (!llps_free_list_scheduler_contract_is_valid()) {
        return false;
    }

    if (!llps_free_list_reconcile(g_free_sessions, &g_free_sessions_count, &g_runtime_cfg)) {
        LLPS_EXPECT(false, return false);
    }

    for (uint32_t i = 0u; i < g_free_sessions_count; ++i) {
        if (g_free_sessions[i] == session_id) {
            return true;
        }
    }

    return false;
}

static void llps_return_session_to_freelist(const uint32_t session_id) {
    if (!llps_free_list_scheduler_contract_is_valid()) {
        return;
    }

    if (!llps_free_list_reconcile(g_free_sessions, &g_free_sessions_count, &g_runtime_cfg)) {
        LLPS_EXPECT(false, return);
    }

    if (session_id >= g_runtime_cfg.max_clients) {
        LLPS_EXPECT(false, return);
    }

    if (llps_free_list_contains(session_id)) {
        LLPS_EXPECT(false, return);
    }

    if (g_free_sessions_count >= g_runtime_cfg.max_clients) {
        LLPS_EXPECT(false, return);
    }

    g_free_sessions[g_free_sessions_count++] = session_id;
    llps_free_list_write_all_from_canonical(g_free_sessions, g_free_sessions_count);
}

static void llps_session_mark_close_reason(llps_session_t *sess,
                                           llps_close_reason_t reason);

static void llps_force_shutdown_session_fds(const llps_session_t * const sess) {
    if (sess != NULL) {
        if (llps_fd_is_valid(sess->client_fd)) {
            (void)shutdown(sess->client_fd, SHUT_RDWR);
        }
        if (llps_fd_is_valid(sess->backend_fd)) {
            (void)shutdown(sess->backend_fd, SHUT_RDWR);
        }
    }
}

static bool llps_payload_ecc_scrub_session(llps_session_t * const sess) {
    const uint32_t cap = g_runtime_cfg.buffer_size;

    if (sess == NULL) {
        return false;
    }

    if (g_runtime_cfg.payload_ecc_enabled == 0u) {
        return true;
    }

    if ((cap == 0u) || (cap > LLPS_BUFFER_SIZE) ||
        (sess->c2s_payload_ecc_len > cap) ||
        (sess->s2c_payload_ecc_len > cap) ||
        (sess->c2s_payload_ecc_len_inverse !=
         ~sess->c2s_payload_ecc_len) ||
        (sess->s2c_payload_ecc_len_inverse !=
         ~sess->s2c_payload_ecc_len)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
        return false;
    }

    if (!llps_payload_ecc_repair(sess->c2s_buf,
                                 sess->c2s_payload_ecc_len,
                                 cap,
                                 sess->c2s_payload_ecc,
                                 LLPS_PAYLOAD_ECC_WORD_COUNT)) {
        return false;
    }

    if (!llps_payload_ecc_repair(sess->s2c_buf,
                                 sess->s2c_payload_ecc_len,
                                 cap,
                                 sess->s2c_payload_ecc,
                                 LLPS_PAYLOAD_ECC_WORD_COUNT)) {
        return false;
    }

    return true;
}

static bool llps_payload_ecc_scrub_all(void) {
    bool scrub_ok = true;

    if (g_runtime_cfg.payload_ecc_enabled == 0u) {
        return true;
    }

    for (uint32_t i = 0u; i < g_runtime_cfg.max_clients; ++i) {
        llps_session_t * const sess = &g_sessions[i];

        LLAM_PREEMPT_POLL_EVERY(i, 16u);
        if (llps_session_is_active(sess)) {
            LLPS_MEMORY_SAFETY_COUNTER_INC(payload_ecc_scrub_sessions_checked);
            if (!llps_payload_ecc_scrub_session(sess)) {
                scrub_ok = false;
                LLPS_MEMORY_SAFETY_COUNTER_INC(
                    payload_ecc_scrub_fail_closed_sessions);
                llps_logf("payload_ecc_scrub_fail_closed session=%u",
                          (unsigned)i);
                llps_session_mark_close_reason(
                    sess,
                    LLPS_CLOSE_REASON_PAYLOAD_ECC);
                llps_force_shutdown_session_fds(sess);
            }
        } else if (!llps_session_is_free(sess)) {
            LLPS_EXPECT(false, llps_force_shutdown_session_fds(sess));
        }
    }

    if (scrub_ok) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(payload_ecc_scrub_passes);
    }

    return scrub_ok;
}

static bool llps_record_ip_audit_event(
    const llps_ip_audit_event_type_t type,
    const uint32_t session_id,
    const uint64_t request_no,
    const char * const client_ip,
    const uint16_t client_port,
    const char * const reason) {
    llps_ip_audit_event_t event;

    if (!llps_ip_audit_enabled()) {
        return true;
    }

    (void)memset(&event, 0, sizeof(event));
    event.type = type;
    event.request_no = request_no;
    event.time_ns = llps_llam_now_ns_checked("ip_audit_event_now");
    event.session_id = session_id;
    event.client_port = client_port;

    if (!llps_state_copy_text(event.client_ip,
                              sizeof(event.client_ip),
                              (client_ip != NULL) ?
                                  client_ip : "0.0.0.0") ||
        !llps_state_copy_text(event.reason,
                              sizeof(event.reason),
                              (reason != NULL) ? reason : "ok")) {
        llps_control_request_shutdown();
        return false;
    }

    if (!llps_ip_audit_record(&event)) {
        llps_logf("ip_audit_write_failed event=%u request=%llu session=%u",
                  (unsigned)type,
                  (unsigned long long)request_no,
                  (unsigned)session_id);
        llps_control_request_shutdown();
        return false;
    }

    return true;
}

static void llps_readiness_evidence_event_fill_counters(
    llps_ip_audit_evidence_event_t * const event) {
    if (event != NULL) {
        event->monitor_passes =
            g_memory_safety_counters.readiness_runtime_monitor_passes;
        event->software_evidence_patrol_passes =
            g_memory_safety_counters
                .readiness_runtime_software_evidence_patrol_passes;
        event->synthetic_ecc_topology_patrol_passes =
            g_memory_safety_counters
                .readiness_runtime_synthetic_ecc_topology_patrol_passes;
        event->synthetic_ecc_topology_patrol_failures =
            g_memory_safety_counters
                .readiness_runtime_synthetic_ecc_topology_patrol_failures;
        event->synthetic_fault_patrol_passes =
            g_memory_safety_counters
                .readiness_runtime_synthetic_fault_patrol_passes;
        event->synthetic_fault_patrol_failures =
            g_memory_safety_counters
                .readiness_runtime_synthetic_fault_patrol_failures;
        event->synthetic_numa_patrol_passes =
            g_memory_safety_counters
                .readiness_runtime_synthetic_numa_patrol_passes;
        event->synthetic_numa_patrol_failures =
            g_memory_safety_counters
                .readiness_runtime_synthetic_numa_patrol_failures;
    }
}

static void llps_readiness_evidence_event_fill_config(
    llps_ip_audit_evidence_event_t * const event,
    const llps_yml_config_t * const cfg) {
    if ((event != NULL) && (cfg != NULL)) {
        event->require_readiness = cfg->require_readiness;
        event->platform_evidence_mode = cfg->platform_evidence_mode;
        event->software_ecc_enabled = cfg->software_ecc_enabled;
        event->software_numa_enabled = cfg->software_numa_enabled;
        event->software_fault_injection_mode =
            cfg->software_fault_injection_mode;
    }
}

static bool llps_record_readiness_evidence_event(
    const char * const event_name,
    const llps_status_t status,
    const uint32_t failure_mask,
    const llps_yml_config_t * const cfg) {
    llps_ip_audit_evidence_event_t event;

    if (!llps_ip_audit_enabled()) {
        return true;
    }

    (void)memset(&event, 0, sizeof(event));
    if (!llps_state_copy_text(event.event,
                              sizeof(event.event),
                              (event_name != NULL) ?
                                  event_name : "readiness_monitor")) {
        llps_control_request_shutdown();
        return false;
    }

    event.time_ns = llps_llam_now_ns_checked("ip_audit_evidence_now");
    event.status = (uint32_t)status;
    event.failure_mask = failure_mask;
    llps_readiness_evidence_event_fill_counters(&event);
    llps_readiness_evidence_event_fill_config(&event, cfg);

    if (!llps_ip_audit_record_evidence(&event)) {
        llps_logf("ip_audit_evidence_write_failed event=%s status=%u failure_mask=0x%08x",
                  event.event,
                  (unsigned)event.status,
                  (unsigned)event.failure_mask);
        llps_control_request_shutdown();
        return false;
    }

    return true;
}

static void llps_peer_text_from_sockaddr(const struct sockaddr * const addr,
                                         const socklen_t addr_len,
                                         char * const out_ip,
                                         const size_t out_ip_cap,
                                         uint16_t * const out_port) {
    if ((out_ip == NULL) || (out_port == NULL)) {
        return;
    }

    (void)memset(out_ip, 0, out_ip_cap);
    (void)llps_state_copy_text(out_ip, out_ip_cap, "0.0.0.0");
    *out_port = 0u;

    if (addr != NULL) {
        (void)llps_sockaddr_ipv4_text_len(addr,
                                          addr_len,
                                          out_ip,
                                          out_ip_cap,
                                          out_port);
    }
}

static bool llps_tmr_metadata_scrub_all(void) {
    bool shutdown_requested = false;

    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
        return false;
    }

    if (!llps_free_list_reconcile(g_free_sessions, &g_free_sessions_count, &g_runtime_cfg)) {
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
        return false;
    }

    if (!llps_control_flag_reconcile(&shutdown_requested)) {
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
        return false;
    }

    if (shutdown_requested) {
        llps_shutdown_all_sessions();
        return false;
    }

    return true;
}

static bool llps_session_tmr_scrub_all(void) {
    bool scrub_ok = true;

    if (!llps_tmr_metadata_scrub_all()) {
        return false;
    }

    for (uint32_t i = 0u; i < g_runtime_cfg.max_clients; ++i) {
        llps_session_tmr_snapshot_t snapshot;

        LLAM_PREEMPT_POLL_EVERY(i, 16u);
        if (!llps_session_tmr_vote(i, g_runtime_cfg.max_clients, &snapshot)) {
            scrub_ok = false;
            LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_scrub_fail_closed_sessions);
            llps_session_mark_close_reason(
                &g_sessions[i],
                LLPS_CLOSE_REASON_METADATA_FAULT);
            llps_force_shutdown_session_fds(&g_sessions[i]);
        } else {
            LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_scrub_sessions_checked);
        }
    }

    if (!scrub_ok) {
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
        return false;
    }

    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_scrub_passes);
    return true;
}

static uint64_t llps_session_idle_timeout_ns(void) {
    uint32_t timeout_ms = g_runtime_cfg.session_idle_timeout_ms;

    if (timeout_ms == 0u) {
        timeout_ms = LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT;
    }

    return (uint64_t)timeout_ms * LLPS_NSEC_PER_MSEC;
}

static void llps_session_mark_close_reason(
    llps_session_t * const sess,
    const llps_close_reason_t reason) {
    if (sess != NULL) {
        if (!llps_close_reason_is_valid((uint32_t)reason)) {
            LLPS_EXPECT(false, return);
        }
        sess->close_reason = (uint32_t)reason;
        sess->close_reason_inverse = ~sess->close_reason;
        llps_session_refresh_crc(sess);
    }
}

static void llps_session_mark_close_reason_if_active(
    llps_session_t * const sess,
    const llps_close_reason_t reason) {
    if ((sess != NULL) &&
        (reason != LLPS_CLOSE_REASON_NORMAL) &&
        ((llps_session_hot_path_is_active(sess)) ||
         llps_session_is_active(sess))) {
        llps_session_mark_close_reason(sess, reason);
    }
}

static bool llps_runtime_cfg_uses_software_evidence_patrol(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL) &&
           ((cfg->software_ecc_enabled != 0u) ||
            (cfg->software_numa_enabled != 0u));
}

static bool llps_runtime_cfg_uses_synthetic_fault_patrol(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL) &&
           (cfg->software_ecc_enabled != 0u) &&
           (cfg->software_fault_injection_mode !=
            LLPS_SOFTWARE_FAULT_INJECTION_OFF);
}

static bool llps_runtime_cfg_uses_synthetic_ecc_topology_patrol(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL) &&
           (cfg->software_ecc_enabled != 0u);
}

static bool llps_runtime_cfg_uses_synthetic_numa_patrol(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL) &&
           (cfg->software_numa_enabled != 0u);
}

static bool llps_runtime_synthetic_ecc_observation_matches(
    const llps_yml_config_t * const cfg,
    const llps_edac_observation_t * const observation,
    const bool ecc_present,
    const bool counters_clean,
    const uint32_t fingerprint) {
    const bool clean_required =
        (cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u;
    const uint64_t expected_scrub_rate_sum =
        cfg->software_ecc_scrub_rate *
        (uint64_t)cfg->software_ecc_controller_count;

    return ecc_present &&
           (fingerprint != 0u) &&
           (!clean_required || counters_clean) &&
           (observation->controller_count ==
            cfg->software_ecc_controller_count) &&
           (observation->dimm_count == cfg->software_ecc_dimm_count) &&
           (observation->scrub_rate_count ==
            cfg->software_ecc_controller_count) &&
           (observation->controller_counter_coverage != 0u) &&
           (observation->dimm_mode_coverage != 0u) &&
           (observation->dimm_counter_coverage != 0u) &&
           (observation->scrub_rate_coverage != 0u) &&
           (observation->corrected_error_count ==
            cfg->software_ecc_controller_corrected_error_count) &&
           (observation->uncorrected_error_count ==
            cfg->software_ecc_controller_uncorrected_error_count) &&
           (observation->dimm_corrected_error_count ==
            cfg->software_ecc_dimm_corrected_error_count) &&
           (observation->dimm_uncorrected_error_count ==
            cfg->software_ecc_dimm_uncorrected_error_count) &&
           (observation->scrub_rate_sum == expected_scrub_rate_sum);
}

static void llps_runtime_synthetic_ecc_record_result(const bool ok) {
    if (ok) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_ecc_topology_patrol_passes);
    } else {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_ecc_topology_patrol_failures);
    }
}

static bool llps_runtime_synthetic_ecc_topology_patrol(
    const llps_yml_config_t * const cfg) {
    llps_edac_observation_t observation;
    bool ecc_present = false;
    bool counters_clean = false;
    uint32_t fingerprint = 0u;
    bool ok = false;

    if (!llps_runtime_cfg_uses_synthetic_ecc_topology_patrol(cfg)) {
        return true;
    }

    llps_edac_synthesize_ecc(
        cfg->software_ecc_controller_count,
        cfg->software_ecc_dimm_count,
        cfg->software_ecc_scrub_rate,
        cfg->software_ecc_controller_corrected_error_count,
        cfg->software_ecc_controller_uncorrected_error_count,
        cfg->software_ecc_dimm_corrected_error_count,
        cfg->software_ecc_dimm_uncorrected_error_count,
        &ecc_present,
        &counters_clean,
        &fingerprint,
        &observation);

    ok = llps_runtime_synthetic_ecc_observation_matches(cfg,
                                                        &observation,
                                                        ecc_present,
                                                        counters_clean,
                                                        fingerprint);
    llps_runtime_synthetic_ecc_record_result(ok);

    return ok;
}

static uint64_t llps_runtime_synthetic_fault_seed(
    const llps_yml_config_t * const cfg) {
    return UINT64_C(0xa5d39e3779b97f4a) ^
           ((uint64_t)g_memory_safety_counters.readiness_runtime_monitor_passes
            << 17u) ^
           ((uint64_t)((cfg != NULL) ? cfg->software_ecc_controller_count : 0u)
            << 41u) ^
           ((uint64_t)((cfg != NULL) ? cfg->software_ecc_dimm_count : 0u)
            << 29u) ^
           ((cfg != NULL) ? cfg->software_ecc_scrub_rate : 0u);
}

static bool llps_runtime_synthetic_fault_single_case(const uint64_t seed) {
    uint64_t single_data = seed;
    uint8_t single_ecc = llps_secded_encode_u64(single_data, 64u);
    const uint32_t bit = (uint32_t)((seed >> 3u) & 63u);

    single_data ^= UINT64_C(1) << bit;
    return (llps_secded_repair_u64(&single_data, 64u, &single_ecc) ==
            LLPS_SECDED_CORRECTED) &&
           (single_data == seed) &&
           llps_secded_is_valid_u64(single_data, 64u, single_ecc);
}

static bool llps_runtime_synthetic_fault_double_case(const uint64_t seed) {
    uint64_t double_data = seed ^ UINT64_C(0x5a5a1f2e3d4c8778);
    uint8_t double_ecc = llps_secded_encode_u64(double_data, 64u);
    const uint32_t bit0 = (uint32_t)((seed >> 11u) & 63u);
    const uint32_t bit1 = (bit0 + 19u) & 63u;

    double_data ^= UINT64_C(1) << bit0;
    double_data ^= UINT64_C(1) << bit1;
    return llps_secded_repair_u64(&double_data, 64u, &double_ecc) ==
           LLPS_SECDED_UNCORRECTABLE;
}

static void llps_runtime_synthetic_fault_record_result(const bool ok) {
    if (ok) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_fault_patrol_passes);
    } else {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_fault_patrol_failures);
    }
}

static bool llps_runtime_synthetic_fault_patrol(
    const llps_yml_config_t * const cfg) {
    const uint64_t seed = llps_runtime_synthetic_fault_seed(cfg);
    const uint32_t mode =
        (cfg != NULL) ? cfg->software_fault_injection_mode :
        LLPS_SOFTWARE_FAULT_INJECTION_OFF;
    bool ok = true;

    if (!llps_runtime_cfg_uses_synthetic_fault_patrol(cfg)) {
        return true;
    }
    if (mode > LLPS_SOFTWARE_FAULT_INJECTION_MAX) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_fault_patrol_failures);
        return false;
    }

    if ((mode == LLPS_SOFTWARE_FAULT_INJECTION_SINGLE) ||
        (mode == LLPS_SOFTWARE_FAULT_INJECTION_FULL)) {
        ok = llps_runtime_synthetic_fault_single_case(seed) && ok;
    }

    if ((mode == LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE) ||
        (mode == LLPS_SOFTWARE_FAULT_INJECTION_FULL)) {
        ok = llps_runtime_synthetic_fault_double_case(seed) && ok;
    }

    llps_runtime_synthetic_fault_record_result(ok);
    return ok;
}

static void llps_runtime_synthetic_numa_collect(
    const llps_yml_config_t * const cfg,
    llps_synthetic_numa_observation_t * const obs) {
    if ((cfg != NULL) && (obs != NULL)) {
        llps_numa_synthesize_physical_memory_domains(
            cfg->platform_physical_memory_domains,
            cfg->software_numa_memtotal_kib,
            cfg->software_numa_local_distance,
            cfg->software_numa_remote_distance,
            &obs->domains_observed,
            &obs->fingerprint,
            &obs->topology_coverage,
            &obs->observed_count,
            &obs->memtotal_kib,
            &obs->distance_entries,
            &obs->distance_sum,
            &obs->distance_pair_coverage,
            &obs->distance_01,
            &obs->distance_02,
            &obs->distance_12);
    }
}

static uint64_t llps_runtime_synthetic_numa_expected_distance_sum(
    const uint64_t local_distance,
    const uint64_t remote_distance) {
    return ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT * local_distance) +
           ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT *
            ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT - 1u) *
            remote_distance);
}

static bool llps_runtime_synthetic_numa_observation_matches(
    const llps_yml_config_t * const cfg,
    const llps_synthetic_numa_observation_t * const obs,
    const uint64_t local_distance,
    const uint64_t remote_distance) {
    return (cfg != NULL) &&
           (obs != NULL) &&
           obs->domains_observed &&
           (obs->fingerprint != 0u) &&
           (obs->topology_coverage ==
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) &&
           (obs->observed_count == LLPS_SESSION_TMR_BANK_COUNT) &&
           (cfg->software_numa_memtotal_kib != 0u) &&
           (obs->memtotal_kib ==
            (cfg->software_numa_memtotal_kib *
             (uint64_t)LLPS_SESSION_TMR_BANK_COUNT)) &&
           (obs->distance_entries ==
            LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN) &&
           (obs->distance_sum ==
            llps_runtime_synthetic_numa_expected_distance_sum(
                local_distance,
                remote_distance)) &&
           (obs->distance_pair_coverage ==
            LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL) &&
           (obs->distance_01 == remote_distance) &&
           (obs->distance_02 == remote_distance) &&
           (obs->distance_12 == remote_distance);
}

static void llps_runtime_synthetic_numa_record_result(const bool ok) {
    if (ok) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_numa_patrol_passes);
    } else {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_synthetic_numa_patrol_failures);
    }
}

static bool llps_runtime_synthetic_numa_patrol(
    const llps_yml_config_t * const cfg) {
    llps_synthetic_numa_observation_t obs;
    const uint64_t local_distance =
        (cfg != NULL && cfg->software_numa_local_distance != 0u) ?
        cfg->software_numa_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t remote_distance =
        (cfg != NULL && cfg->software_numa_remote_distance != 0u) ?
        cfg->software_numa_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    bool ok = false;

    if (!llps_runtime_cfg_uses_synthetic_numa_patrol(cfg)) {
        return true;
    }

    (void)memset(&obs, 0, sizeof(obs));
    llps_runtime_synthetic_numa_collect(cfg, &obs);
    ok = llps_runtime_synthetic_numa_observation_matches(cfg,
                                                         &obs,
                                                         local_distance,
                                                         remote_distance);
    llps_runtime_synthetic_numa_record_result(ok);

    return ok;
}

static void llps_readiness_monitor_shutdown_after_failure(void) {
    llps_control_request_shutdown();
    llps_shutdown_all_sessions();
}

static void llps_readiness_monitor_log_failure(const llps_status_t status,
                                               const uint32_t failure_mask) {
    llps_logf("readiness_monitor_fail status=%d failure_mask=0x%08x",
              (int)status,
              (unsigned)failure_mask);
}

static void llps_readiness_monitor_record_failure(
    const char * const event_name,
    const llps_status_t status,
    const uint32_t failure_mask,
    const llps_yml_config_t * const cfg) {
    (void)llps_record_readiness_evidence_event(event_name,
                                               status,
                                               failure_mask,
                                               cfg);
    llps_readiness_monitor_log_failure(status, failure_mask);
    llps_readiness_monitor_shutdown_after_failure();
}

static bool llps_readiness_monitor_load_snapshot(
    llps_yml_config_t * const out_cfg) {
    if ((out_cfg == NULL) || !llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_cfg_failures);
        llps_readiness_monitor_shutdown_after_failure();
        return false;
    }

    *out_cfg = g_runtime_cfg;
    return true;
}

static bool llps_readiness_monitor_fast_software_gate(
    const llps_yml_config_t * const cfg) {
    if (llps_readiness_runtime_fast_software_ready(&g_runtime_cfg,
                                                   g_free_sessions,
                                                   &g_free_sessions_count)) {
        return true;
    }

    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_software_tmr_failures);
    llps_readiness_monitor_record_failure(
        "readiness_software_tmr_fail",
        LLPS_E_STATE,
        LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR,
        cfg);
    return false;
}

static bool llps_readiness_monitor_ecc_topology_gate(
    const llps_yml_config_t * const cfg) {
    if (llps_runtime_synthetic_ecc_topology_patrol(cfg)) {
        return true;
    }

    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
    llps_readiness_monitor_record_failure("readiness_ecc_topology_fail",
                                          LLPS_E_STATE,
                                          LLPS_READINESS_RUNTIME_FAILURE_ECC,
                                          cfg);
    return false;
}

static bool llps_readiness_monitor_fault_patrol_gate(
    const llps_yml_config_t * const cfg) {
    if (llps_runtime_synthetic_fault_patrol(cfg)) {
        return true;
    }

    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
    llps_readiness_monitor_record_failure("readiness_fault_patrol_fail",
                                          LLPS_E_STATE,
                                          LLPS_READINESS_RUNTIME_FAILURE_ECC,
                                          cfg);
    return false;
}

static uint32_t llps_readiness_monitor_numa_failure_mask(void) {
    return LLPS_READINESS_RUNTIME_FAILURE_PHYSICAL_DOMAIN |
           LLPS_READINESS_RUNTIME_FAILURE_TMR_MEMORY_DOMAIN |
           LLPS_READINESS_RUNTIME_DETAIL_TMR_DOMAIN_BIND;
}

static bool llps_readiness_monitor_numa_patrol_gate(
    const llps_yml_config_t * const cfg) {
    if (llps_runtime_synthetic_numa_patrol(cfg)) {
        return true;
    }

    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_physical_domain_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(
        readiness_runtime_tmr_memory_domain_failures);
    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
    llps_readiness_monitor_record_failure("readiness_numa_patrol_fail",
                                          LLPS_E_STATE,
                                          llps_readiness_monitor_numa_failure_mask(),
                                          cfg);
    return false;
}

static bool llps_readiness_monitor_synthetic_gates(
    const llps_yml_config_t * const cfg) {
    return llps_readiness_monitor_ecc_topology_gate(cfg) &&
           llps_readiness_monitor_fault_patrol_gate(cfg) &&
           llps_readiness_monitor_numa_patrol_gate(cfg);
}

static void llps_readiness_monitor_log_pass_counters(void) {
    (void)fprintf(stdout,
                  "readiness_monitor_pass\n"
                  "  total=%llu\n"
                  "  software_evidence_patrol=%llu\n"
                  "  synthetic_ecc_topology_patrol=%llu\n"
                  "  synthetic_ecc_topology_patrol_failures=%llu\n",
                  (unsigned long long)
                      g_memory_safety_counters.readiness_runtime_monitor_passes,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_software_evidence_patrol_passes,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_ecc_topology_patrol_passes,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_ecc_topology_patrol_failures);
    (void)fprintf(stdout,
                  "  synthetic_fault_patrol=%llu\n"
                  "  synthetic_fault_patrol_failures=%llu\n"
                  "  synthetic_numa_patrol=%llu\n"
                  "  synthetic_numa_patrol_failures=%llu\n",
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_fault_patrol_passes,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_fault_patrol_failures,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_numa_patrol_passes,
                  (unsigned long long)g_memory_safety_counters
                      .readiness_runtime_synthetic_numa_patrol_failures);
}

static void llps_readiness_monitor_log_pass_scope(
    const llps_yml_config_t * const cfg) {
    (void)fprintf(stdout,
                  "  require_readiness=%u\n"
                  "  platform_evidence_mode=%u\n"
                  "  platform_evidence_mode_text=%s\n"
                  "  platform_evidence_scope=%s\n"
                  "  synthetic_evidence_active=%u\n"
                  "  software_platform_model_active=%u\n",
                  (unsigned)cfg->require_readiness,
                  (unsigned)cfg->platform_evidence_mode,
                  llps_platform_evidence_mode_text(cfg->platform_evidence_mode),
                  llps_platform_evidence_scope_text(cfg->platform_evidence_mode),
                  llps_platform_evidence_mode_uses_software(
                      cfg->platform_evidence_mode) ? 1u : 0u,
                  llps_platform_evidence_mode_uses_software(
                      cfg->platform_evidence_mode) ? 1u : 0u);
    (void)fprintf(stdout,
                  "  ecc_evidence_scope=%s\n"
                  "  physical_memory_evidence_scope=%s\n"
                  "  independent_tmr_evidence_scope=%s\n",
                  llps_ecc_evidence_scope_text(
                      cfg->platform_evidence_mode,
                      cfg->software_ecc_enabled != 0u),
                  llps_physical_memory_evidence_scope_text(
                      cfg->platform_evidence_mode,
                      cfg->software_numa_enabled != 0u),
                  llps_independent_tmr_evidence_scope_text(
                      cfg->platform_evidence_mode));
}

static void llps_readiness_monitor_log_pass_ecc(
    const llps_yml_config_t * const cfg) {
    (void)fprintf(stdout,
                  "  software_ecc_enabled=%u\n"
                  "  software_ecc_controller_count=%u\n"
                  "  software_ecc_dimm_count=%u\n"
                  "  software_ecc_scrub_rate=%llu\n",
                  (unsigned)cfg->software_ecc_enabled,
                  (unsigned)cfg->software_ecc_controller_count,
                  (unsigned)cfg->software_ecc_dimm_count,
                  (unsigned long long)cfg->software_ecc_scrub_rate);
    (void)fprintf(stdout,
                  "  software_ecc_controller_corrected_error_count=%llu\n"
                  "  software_ecc_controller_uncorrected_error_count=%llu\n"
                  "  software_ecc_dimm_corrected_error_count=%llu\n"
                  "  software_ecc_dimm_uncorrected_error_count=%llu\n",
                  (unsigned long long)
                      cfg->software_ecc_controller_corrected_error_count,
                  (unsigned long long)
                      cfg->software_ecc_controller_uncorrected_error_count,
                  (unsigned long long)
                      cfg->software_ecc_dimm_corrected_error_count,
                  (unsigned long long)
                      cfg->software_ecc_dimm_uncorrected_error_count);
}

static void llps_readiness_monitor_log_pass_numa_fault(
    const llps_yml_config_t * const cfg) {
    (void)fprintf(stdout,
                  "  software_numa_enabled=%u\n"
                  "  software_numa_memtotal_kib=%llu\n"
                  "  software_numa_local_distance=%llu\n"
                  "  software_numa_remote_distance=%llu\n"
                  "  software_fault_injection_mode=%u\n"
                  "  software_fault_injection_mode_text=%s",
                  (unsigned)cfg->software_numa_enabled,
                  (unsigned long long)cfg->software_numa_memtotal_kib,
                  (unsigned long long)cfg->software_numa_local_distance,
                  (unsigned long long)cfg->software_numa_remote_distance,
                  (unsigned)cfg->software_fault_injection_mode,
                  llps_software_fault_injection_mode_text(
                      cfg->software_fault_injection_mode));
}

static void llps_readiness_monitor_log_pass(
    const llps_yml_config_t * const cfg) {
    if ((cfg == NULL) || !llps_log_enabled()) {
        return;
    }

    llps_log_begin();
    llps_readiness_monitor_log_pass_counters();
    llps_readiness_monitor_log_pass_scope(cfg);
    llps_readiness_monitor_log_pass_ecc(cfg);
    llps_readiness_monitor_log_pass_numa_fault(cfg);
    llps_log_end();
}

static void llps_readiness_monitor_record_pass(
    const llps_yml_config_t * const cfg) {
    LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_passes);
    if (llps_runtime_cfg_uses_software_evidence_patrol(cfg)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_software_evidence_patrol_passes);
    }
    (void)llps_record_readiness_evidence_event("readiness_monitor_pass",
                                               LLPS_OK,
                                               0u,
                                               cfg);
    llps_readiness_monitor_log_pass(cfg);
}

static void llps_readiness_monitor_handle_platform_result(
    const llps_yml_config_t * const cfg,
    const llps_status_t status,
    uint32_t failure_mask,
    const bool consumed) {
    if (status != LLPS_OK) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
        if (failure_mask == 0u) {
            failure_mask = LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR;
        }
        llps_readiness_runtime_monitor_count_failure_details(failure_mask);
        llps_readiness_runtime_monitor_count_failure_mask(failure_mask);
        llps_readiness_monitor_record_failure("readiness_platform_fail",
                                              status,
                                              failure_mask,
                                              cfg);
    } else if (consumed) {
        llps_readiness_monitor_record_pass(cfg);
    }
}

static void llps_readiness_runtime_monitor_tick(void) {
    llps_yml_config_t cfg_snapshot;
    uint32_t failure_mask = 0u;
    bool monitor_result_consumed = false;
    llps_status_t status = LLPS_OK;

    if (!llps_readiness_monitor_load_snapshot(&cfg_snapshot) ||
        (cfg_snapshot.require_readiness == 0u)) {
        return;
    }
    if (!llps_readiness_monitor_fast_software_gate(&cfg_snapshot) ||
        !llps_readiness_monitor_synthetic_gates(&cfg_snapshot)) {
        return;
    }

#if defined(LLPS_TEST_HOOKS)
    monitor_result_consumed = true;
    status = llps_check_configured_readiness_platform_snapshot(
        &cfg_snapshot,
        &failure_mask);
#else
    status = llps_readiness_runtime_monitor_worker_poll(
        &cfg_snapshot,
        llps_llam_now_ns_checked("readiness_monitor_now"),
        LLPS_READINESS_RUNTIME_MONITOR_WORKER_TIMEOUT_NS,
        &failure_mask,
        &monitor_result_consumed);
#endif
    llps_readiness_monitor_handle_platform_result(&cfg_snapshot,
                                                  status,
                                                  failure_mask,
                                                  monitor_result_consumed);
}

/* --------------------------------------------------------------------
 * Session lifecycle
 * -------------------------------------------------------------------- */

static llps_status_t llps_normalize_init_config(
    const llps_yml_config_t * const cfg,
    llps_yml_config_t * const out_cfg) {
    if ((cfg == NULL) || (out_cfg == NULL)) {
        return LLPS_E_NULL;
    }

    *out_cfg = *cfg;
    if (out_cfg->session_idle_timeout_ms == 0u) {
        out_cfg->session_idle_timeout_ms =
            LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT;
    }

    return llps_runtime_cfg_values_are_valid(out_cfg) ?
        LLPS_OK : LLPS_E_RANGE;
}

static void llps_init_reset_runtime_state(void) {
    llps_ip_audit_shutdown();
    llps_watchdog_sleep_pipe_init();
    g_backend_addr_valid = false;
    (void)memset(&g_backend_addr, 0, sizeof(g_backend_addr));
    llps_request_counter_reset();
    llps_client_ip_rate_buckets_reset();
}

static llps_status_t llps_init_resolve_backend(
    const llps_yml_config_t * const cfg,
    struct sockaddr_in * const out_backend,
    char * const out_backend_ip,
    const size_t out_backend_ip_cap) {
    uint16_t resolved_backend_port = 0u;
    llps_status_t st = LLPS_OK;

    if ((cfg == NULL) || (out_backend == NULL) || (out_backend_ip == NULL)) {
        return LLPS_E_NULL;
    }

    (void)memset(out_backend, 0, sizeof(*out_backend));
    (void)memset(out_backend_ip, 0, out_backend_ip_cap);
    st = llps_resolve_ipv4_sockaddr(cfg->target_ip,
                                    cfg->target_port,
                                    false,
                                    out_backend);
    if (st != LLPS_OK) {
        return st;
    }

    return (llps_sockaddr_ipv4_text((const struct sockaddr *)out_backend,
                                    out_backend_ip,
                                    out_backend_ip_cap,
                                    &resolved_backend_port) == LLPS_OK) ?
        LLPS_OK : LLPS_E_SOCKET;
}

static void llps_init_publish_runtime_config(
    const llps_yml_config_t * const cfg,
    const struct sockaddr_in * const backend) {
    g_runtime_cfg = *cfg;
    llps_configure_tmr_software_memory_observation(
        (cfg->software_numa_enabled != 0u) &&
        (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL),
        cfg->platform_physical_memory_domains);
    g_backend_addr = *backend;
    g_backend_addr_valid = true;
    llps_logf("backend_resolved target=%s:%u",
              cfg->target_ip,
              (unsigned)cfg->target_port);
}

static void llps_init_reset_memory_latches(void) {
    llps_memory_safety_counters_reset();
    llps_process_memory_locked_set(false);
    llps_tmr_memory_locked_set(false);
    llps_tmr_memory_prefaulted_set(false);
    llps_tmr_memory_domains_bound_set(false);
    llps_tmr_memory_hardened_set(false);
    llps_tmr_startup_self_test_passed_set(false);
    llps_tmr_startup_self_test_set_coverage(0u);
    llps_tmr_memory_prefault_pages_set(0u);
    llps_tmr_memory_domain_observation_fingerprint_set(0u);
}

static void llps_init_prepare_tmr_memory(
    const llps_yml_config_t * const cfg) {
    (void)llps_lock_process_memory();
    (void)llps_lock_tmr_memory();
    (void)llps_bind_tmr_memory_to_configured_domains(cfg);
    (void)llps_prefault_tmr_memory();
    (void)llps_refresh_tmr_memory_domain_binding(cfg);
    (void)llps_harden_tmr_memory();
}

static llps_status_t llps_init_prepare_tmr_regions(void) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_session_tmr_init_region(bank_id);
    }

    if (!llps_tmr_metadata_layout_is_valid()) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_layout_failures);
        return LLPS_E_STATE;
    }

    return LLPS_OK;
}

static void llps_init_prepare_session_pool(void) {
    for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
        llps_session_reset_free(&g_sessions[i], i);
        g_free_sessions[i] = 0u;
    }

    for (uint32_t i = 0u; i < g_runtime_cfg.max_clients; ++i) {
        g_free_sessions[i] = (g_runtime_cfg.max_clients - 1u) - i;
    }

    g_free_sessions_count = g_runtime_cfg.max_clients;
    llps_free_list_write_all_from_canonical(g_free_sessions,
                                            g_free_sessions_count);
}

static llps_status_t llps_init_run_startup_checks(void) {
    llps_tmr_startup_self_test_passed_set(llps_tmr_startup_self_test());
    if (!g_tmr_startup_self_test_passed) {
        return LLPS_E_STATE;
    }

    return llps_session_tmr_scrub_all() ? LLPS_OK : LLPS_E_STATE;
}

static llps_status_t llps_init_enforce_external_readiness(
    const bool enforce_readiness_gate,
    const char * const resolved_backend_ip) {
    if (!enforce_readiness_gate) {
        return LLPS_OK;
    }

    if (llps_require_configured_readiness(&g_runtime_cfg) != LLPS_OK) {
        return LLPS_E_STATE;
    }

    return llps_ip_audit_init(&g_runtime_cfg, resolved_backend_ip) ?
        LLPS_OK : LLPS_E_IO;
}

static llps_status_t llps_init_internal(const llps_yml_config_t *cfg,
                                        const bool enforce_readiness_gate) {
    llps_yml_config_t normalized_cfg;
    struct sockaddr_in resolved_backend;
    char resolved_backend_ip[LLPS_CLIENT_IP_TEXT_LEN];
    llps_status_t st = LLPS_OK;

    st = llps_normalize_init_config(cfg, &normalized_cfg);
    if (st != LLPS_OK) {
        return st;
    }
    llps_init_reset_runtime_state();
    st = llps_init_resolve_backend(&normalized_cfg,
                                   &resolved_backend,
                                   resolved_backend_ip,
                                   sizeof(resolved_backend_ip));
    if (st != LLPS_OK) {
        return st;
    }

    llps_init_publish_runtime_config(&normalized_cfg, &resolved_backend);
    llps_init_reset_memory_latches();
    llps_init_prepare_tmr_memory(&normalized_cfg);
    llps_runtime_cfg_write_all(&g_runtime_cfg);
    llps_control_clear_shutdown();

    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        return LLPS_E_STATE;
    }

    st = llps_init_prepare_tmr_regions();
    if (st != LLPS_OK) {
        return st;
    }
    llps_init_prepare_session_pool();

    st = llps_init_run_startup_checks();
    if (st == LLPS_OK) {
        st = llps_init_enforce_external_readiness(enforce_readiness_gate,
                                                  resolved_backend_ip);
    }

    return st;
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_init(const llps_yml_config_t *cfg) {
    return llps_init_internal(cfg, true);
}

/* cppcheck-suppress unusedFunction -- public API declared in llps.h */
llps_status_t llps_init_for_diagnostics(const llps_yml_config_t *cfg) {
    return llps_init_internal(cfg, false);
}

static void llps_close_session(llps_session_t * const sess) {
    if (sess != NULL) {
        uint32_t session_id = 0u;
        const bool was_free = llps_session_is_free(sess);

        if (!llps_session_index_from_ptr(sess, &session_id)) {
            LLPS_EXPECT(false, return);
        }

        if (!was_free) {
            const char * const close_reason =
                llps_close_reason_text(sess->close_reason);
            llps_logf("session=%u closing client_fd=%d backend_fd=%d reason=%s",
                      (unsigned)session_id,
                      sess->client_fd,
                      sess->backend_fd,
                      close_reason);
            (void)llps_record_ip_audit_event(LLPS_IP_AUDIT_CLOSE,
                                             session_id,
                                             sess->request_no,
                                             sess->client_ip,
                                             sess->client_port,
                                             close_reason);
        }

        if (llps_close_connected_fd(&sess->client_fd) != 0) {
            LLPS_EXPECT(false, (void)0);
        }
        if (llps_close_connected_fd(&sess->backend_fd) != 0) {
            LLPS_EXPECT(false, (void)0);
        }

        if (session_id >= g_runtime_cfg.max_clients) {
            LLPS_EXPECT(false, return);
        }

        llps_session_reset_free(sess, session_id);

        if (!was_free) {
            llps_return_session_to_freelist(session_id);
        }
    }
}

static llps_status_t llps_find_free_session(uint32_t * const out_index) {
    if (out_index == NULL) {
        return LLPS_E_NULL;
    }

    if (!llps_free_list_scheduler_contract_is_valid()) {
        return LLPS_E_STATE;
    }

    if (!llps_free_list_reconcile(g_free_sessions, &g_free_sessions_count, &g_runtime_cfg)) {
        return LLPS_E_STATE;
    }

    for (uint32_t attempt = 0u;
         (g_free_sessions_count > 0u) && (attempt < LLPS_MAX_CLIENTS);
         ++attempt) {
        const uint32_t idx = g_free_sessions[--g_free_sessions_count];
        llps_free_list_write_all_from_canonical(g_free_sessions, g_free_sessions_count);

        if (idx >= g_runtime_cfg.max_clients) {
            LLPS_EXPECT(false, continue);
        }

        if (!llps_session_is_free(&g_sessions[idx])) {
            LLPS_EXPECT(false, continue);
        }

        *out_index = idx;
        return LLPS_OK;
    }

    return LLPS_E_RANGE;
}

static llps_status_t llps_build_backend_addr(struct sockaddr_in * const addr) {
    if (addr == NULL) {
        return LLPS_E_NULL;
    }

    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        return LLPS_E_STATE;
    }

    if (!g_backend_addr_valid) {
        return LLPS_E_STATE;
    }

    *addr = g_backend_addr;
    addr->sin_port = htons(g_runtime_cfg.target_port);
    return LLPS_OK;
}

static const char LLPS_CLIENT_PREFACE_TIMEOUT_REASON[] =
    "client_preface_timeout";
static const char LLPS_PROTOCOL_HANDSHAKE_INVALID_REASON[] =
    "protocol_handshake_invalid";

typedef enum {
    LLPS_PROTOCOL_HANDSHAKE_NEED_MORE = 0,
    LLPS_PROTOCOL_HANDSHAKE_VALID,
    LLPS_PROTOCOL_HANDSHAKE_INVALID
} llps_protocol_handshake_status_t;

static llps_protocol_handshake_status_t llps_protocol_read_varint(
    const uint8_t * const buf,
    const size_t len,
    size_t * const offset,
    uint32_t * const out_value) {
    uint32_t value = 0u;

    if ((buf == NULL) || (offset == NULL) || (out_value == NULL)) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID;
    }

    for (uint32_t byte_index = 0u; byte_index < 5u; ++byte_index) {
        uint8_t byte = 0u;
        uint32_t byte_value = 0u;
        uint32_t shift = 0u;

        if (*offset >= len) {
            return LLPS_PROTOCOL_HANDSHAKE_NEED_MORE;
        }

        byte = buf[*offset];
        ++(*offset);
        byte_value = (uint32_t)(byte & 0x7Fu);
        shift = byte_index * 7u;
        if ((byte_index == 4u) && (byte_value > 0x0Fu)) {
            return LLPS_PROTOCOL_HANDSHAKE_INVALID;
        }
        value |= byte_value << shift;

        if ((byte & 0x80u) == 0u) {
            if ((byte_index > 0u) &&
                (value < (UINT32_C(1) << shift))) {
                return LLPS_PROTOCOL_HANDSHAKE_INVALID;
            }
            *out_value = value;
            return LLPS_PROTOCOL_HANDSHAKE_VALID;
        }
    }

    return LLPS_PROTOCOL_HANDSHAKE_INVALID;
}

static llps_protocol_handshake_status_t llps_protocol_read_packet_frame(
    const uint8_t * const buf,
    const size_t len,
    size_t * const offset,
    size_t * const packet_end) {
    uint32_t packet_len = 0u;
    llps_protocol_handshake_status_t st =
        LLPS_PROTOCOL_HANDSHAKE_INVALID;

    st = llps_protocol_read_varint(buf, len, offset, &packet_len);
    if (st != LLPS_PROTOCOL_HANDSHAKE_VALID) {
        return st;
    }
    if ((packet_len == 0u) ||
        (packet_len > LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX) ||
        (packet_len > (SIZE_MAX - *offset))) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID;
    }

    *packet_end = *offset + (size_t)packet_len;
    return (len < *packet_end) ?
        LLPS_PROTOCOL_HANDSHAKE_NEED_MORE :
        LLPS_PROTOCOL_HANDSHAKE_VALID;
}

static llps_protocol_handshake_status_t llps_protocol_read_packet_id(
    const uint8_t * const buf,
    const size_t packet_end,
    size_t * const offset) {
    uint32_t packet_id = 0u;
    const llps_protocol_handshake_status_t st =
        llps_protocol_read_varint(buf, packet_end, offset, &packet_id);

    return ((st == LLPS_PROTOCOL_HANDSHAKE_VALID) && (packet_id == 0u)) ?
        LLPS_PROTOCOL_HANDSHAKE_VALID :
        LLPS_PROTOCOL_HANDSHAKE_INVALID;
}

static llps_protocol_handshake_status_t llps_protocol_read_protocol_version(
    const uint8_t * const buf,
    const size_t packet_end,
    size_t * const offset) {
    uint32_t protocol_version = 0u;
    const llps_protocol_handshake_status_t st =
        llps_protocol_read_varint(buf, packet_end, offset, &protocol_version);

    return ((st == LLPS_PROTOCOL_HANDSHAKE_VALID) &&
            (protocol_version != 0u) &&
            (protocol_version <= (uint32_t)INT32_MAX)) ?
        LLPS_PROTOCOL_HANDSHAKE_VALID :
        LLPS_PROTOCOL_HANDSHAKE_INVALID;
}

static llps_protocol_handshake_status_t llps_protocol_skip_server_address(
    const uint8_t * const buf,
    const size_t packet_end,
    size_t * const offset) {
    uint32_t server_addr_len = 0u;
    llps_protocol_handshake_status_t st =
        LLPS_PROTOCOL_HANDSHAKE_INVALID;

    st = llps_protocol_read_varint(buf,
                                    packet_end,
                                    offset,
                                    &server_addr_len);
    if ((st != LLPS_PROTOCOL_HANDSHAKE_VALID) ||
        (server_addr_len == 0u) ||
        (server_addr_len > LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX)) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID;
    }
    if (((size_t)server_addr_len > (packet_end - *offset)) ||
        ((packet_end - *offset - (size_t)server_addr_len) < 3u)) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID;
    }

    *offset += (size_t)server_addr_len;
    if ((buf[*offset] == 0u) && (buf[*offset + 1u] == 0u)) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID;
    }

    *offset += 2u;
    return LLPS_PROTOCOL_HANDSHAKE_VALID;
}

static llps_protocol_handshake_status_t llps_protocol_read_next_state(
    const uint8_t * const buf,
    const size_t packet_end,
    size_t * const offset) {
    uint32_t next_state = 0u;
    const llps_protocol_handshake_status_t st =
        llps_protocol_read_varint(buf, packet_end, offset, &next_state);

    return ((st == LLPS_PROTOCOL_HANDSHAKE_VALID) &&
            ((next_state == 1u) || (next_state == 2u)) &&
            (*offset == packet_end)) ?
        LLPS_PROTOCOL_HANDSHAKE_VALID :
        LLPS_PROTOCOL_HANDSHAKE_INVALID;
}

static llps_protocol_handshake_status_t llps_protocol_handshake_validate(
    const uint8_t * const buf,
    const size_t len) {
    size_t offset = 0u;
    size_t packet_end = 0u;
    llps_protocol_handshake_status_t st =
        LLPS_PROTOCOL_HANDSHAKE_INVALID;

    if ((buf == NULL) || (len == 0u)) {
        return LLPS_PROTOCOL_HANDSHAKE_NEED_MORE;
    }

    st = llps_protocol_read_packet_frame(buf, len, &offset, &packet_end);
    if (st == LLPS_PROTOCOL_HANDSHAKE_VALID) {
        st = llps_protocol_read_packet_id(buf, packet_end, &offset);
    }
    if (st == LLPS_PROTOCOL_HANDSHAKE_VALID) {
        st = llps_protocol_read_protocol_version(buf, packet_end, &offset);
    }
    if (st == LLPS_PROTOCOL_HANDSHAKE_VALID) {
        st = llps_protocol_skip_server_address(buf, packet_end, &offset);
    }
    if (st == LLPS_PROTOCOL_HANDSHAKE_VALID) {
        st = llps_protocol_read_next_state(buf, packet_end, &offset);
    }

    return st;
}

static const char *llps_client_preface_seal(
    llps_session_t * const sess,
    const size_t len) {
    if (sess == NULL) {
        return "client_preface_arg";
    }

    if (g_runtime_cfg.payload_ecc_enabled != 0u) {
        llps_pump_args_t preface_pump;
        (void)memset(&preface_pump, 0, sizeof(preface_pump));
        preface_pump.session = sess;
        preface_pump.buf = sess->c2s_buf;
        preface_pump.buf_len = g_runtime_cfg.buffer_size;
        preface_pump.direction = LLPS_DIR_C2S;
        if (!llps_payload_ecc_seal(sess->c2s_buf,
                                   len,
                                   g_runtime_cfg.buffer_size,
                                   sess->c2s_payload_ecc,
                                   LLPS_PAYLOAD_ECC_WORD_COUNT) ||
            !llps_payload_ecc_set_len_for_pump(sess,
                                               &preface_pump,
                                               len)) {
            return "client_preface_payload_ecc";
        }
    }

    return NULL;
}

static uint64_t llps_client_preface_deadline_ns(const uint32_t timeout_ms) {
    const uint64_t start_ns =
        llps_llam_now_ns_checked("client_preface_deadline_now");
    const uint64_t timeout_ns =
        (uint64_t)timeout_ms * LLPS_NSEC_PER_MSEC;

    return ((UINT64_MAX - start_ns) < timeout_ns) ?
        UINT64_MAX : (start_ns + timeout_ns);
}

static const char *llps_client_preface_read_timeout_ms(
    const uint64_t deadline_ns,
    int * const out_timeout_ms) {
    uint64_t now_ns = 0u;
    uint64_t remaining_ns = 0u;
    uint64_t remaining_ms64 = 0u;

    if (out_timeout_ms == NULL) {
        return "client_preface_arg";
    }

    now_ns = llps_llam_now_ns_checked("client_preface_now");
    if (now_ns >= deadline_ns) {
        return LLPS_CLIENT_PREFACE_TIMEOUT_REASON;
    }

    remaining_ns = deadline_ns - now_ns;
    remaining_ms64 = remaining_ns / LLPS_NSEC_PER_MSEC;
    if ((remaining_ns % LLPS_NSEC_PER_MSEC) != 0u) {
        ++remaining_ms64;
    }
    if (remaining_ms64 == 0u) {
        remaining_ms64 = 1u;
    }

    *out_timeout_ms = (remaining_ms64 > (uint64_t)INT_MAX) ?
        INT_MAX : (int)remaining_ms64;
    return NULL;
}

static const char *llps_client_preface_read_chunk(
    llps_session_t * const sess,
    size_t * const out_len,
    const int read_timeout_ms,
    bool * const out_progress) {
    ssize_t n = 0;

    if (out_progress == NULL) {
        return "client_preface_arg";
    }
    *out_progress = false;
    n = llps_llam_read_when_ready_checked(
        sess->client_fd,
        sess->c2s_buf + *out_len,
        g_runtime_cfg.buffer_size - *out_len,
        read_timeout_ms,
        "client_preface_read_ready");
    if (n == 0) {
        return "client_preface_eof";
    }
    if (n < 0) {
        if (errno == ETIMEDOUT) {
            return LLPS_CLIENT_PREFACE_TIMEOUT_REASON;
        }
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            llps_llam_yield_checked("client_preface_retry_yield");
            return NULL;
        }
        return "client_preface_read";
    }
    if ((size_t)n > (g_runtime_cfg.buffer_size - *out_len)) {
        LLPS_EXPECT(false, return "client_preface_contract");
    }

    *out_len += (size_t)n;
    *out_progress = true;
    llps_session_touch(sess);
    return NULL;
}

static const char *llps_client_preface_check_gate(
    const llps_session_t * const sess,
    const size_t len,
    const bool protocol_gate_enabled,
    bool * const out_complete) {
    llps_protocol_handshake_status_t st =
        LLPS_PROTOCOL_HANDSHAKE_INVALID;

    if (out_complete == NULL) {
        return "client_preface_arg";
    }
    *out_complete = !protocol_gate_enabled;
    if (!protocol_gate_enabled) {
        return NULL;
    }

    st = llps_protocol_handshake_validate(sess->c2s_buf, len);
    if (st == LLPS_PROTOCOL_HANDSHAKE_NEED_MORE) {
        if (len >= g_runtime_cfg.buffer_size) {
            return LLPS_PROTOCOL_HANDSHAKE_INVALID_REASON;
        }
        return NULL;
    }
    if (st != LLPS_PROTOCOL_HANDSHAKE_VALID) {
        return LLPS_PROTOCOL_HANDSHAKE_INVALID_REASON;
    }

    llps_logf("session=%u protocol_handshake_valid bytes=%u",
              (unsigned)sess->session_id,
              (unsigned)len);
    *out_complete = true;
    return NULL;
}

static const char *llps_client_preface_load_config(
    uint32_t * const out_timeout_ms,
    bool * const out_protocol_gate_enabled) {
    if ((out_timeout_ms == NULL) || (out_protocol_gate_enabled == NULL)) {
        return "client_preface_arg";
    }

    if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        return "client_preface_config";
    }

    *out_timeout_ms = g_runtime_cfg.client_preface_timeout_ms;
    *out_protocol_gate_enabled =
        g_runtime_cfg.protocol_handshake_gate_enabled != 0u;
    return NULL;
}

static const char *llps_client_preface_read_cycle(
    llps_session_t * const sess,
    size_t * const out_len,
    const uint64_t deadline_ns,
    const bool protocol_gate_enabled,
    bool * const out_complete) {
    int read_timeout_ms = 0;
    bool read_progress = false;
    const char *reason = NULL;

    if (out_complete == NULL) {
        return "client_preface_arg";
    }
    *out_complete = false;
    reason = llps_client_preface_read_timeout_ms(deadline_ns,
                                                 &read_timeout_ms);
    if (reason != NULL) {
        return reason;
    }
    if (*out_len >= g_runtime_cfg.buffer_size) {
        return protocol_gate_enabled ?
            LLPS_PROTOCOL_HANDSHAKE_INVALID_REASON :
            "client_preface_contract";
    }

    reason = llps_client_preface_read_chunk(sess,
                                            out_len,
                                            read_timeout_ms,
                                            &read_progress);
    if ((reason != NULL) || !read_progress) {
        return reason;
    }

    return llps_client_preface_check_gate(sess,
                                          *out_len,
                                          protocol_gate_enabled,
                                          out_complete);
}

static const char *llps_client_preface_read(
    llps_session_t * const sess,
    size_t * const out_len) {
    uint32_t timeout_ms = 0u;
    bool protocol_gate_enabled = false;
    uint64_t deadline_ns = 0u;

    if ((sess == NULL) || (out_len == NULL)) {
        return "client_preface_arg";
    }

    *out_len = 0u;
    {
        const char * const reason =
            llps_client_preface_load_config(&timeout_ms,
                                            &protocol_gate_enabled);
        if (reason != NULL) {
            return reason;
        }
    }

    if (timeout_ms == 0u) {
        return NULL;
    }

    deadline_ns = llps_client_preface_deadline_ns(timeout_ms);

    for (uint32_t read_cycle = 0u;
         read_cycle < LLPS_SOCKET_IO_STEP_MAX;
         ++read_cycle) {
        bool preface_complete = false;
        const char * const reason =
            llps_client_preface_read_cycle(sess,
                                           out_len,
                                           deadline_ns,
                                           protocol_gate_enabled,
                                           &preface_complete);

        if (reason != NULL) {
            return reason;
        }
        if (preface_complete) {
            return llps_client_preface_seal(sess, *out_len);
        }
    }

    return "client_preface_retry";
}

static const char *llps_backend_preface_flush_validate(
    const llps_session_t * const sess,
    const size_t len) {
    if (sess == NULL) {
        return "client_preface_flush_arg";
    }
    if (len > g_runtime_cfg.buffer_size) {
        return "client_preface_flush_contract";
    }

    return NULL;
}

static const char *llps_backend_preface_repair_payload(
    llps_session_t * const sess,
    const size_t len) {
    if (g_runtime_cfg.payload_ecc_enabled == 0u) {
        return NULL;
    }

    return llps_payload_ecc_repair(sess->c2s_buf,
                                   len,
                                   g_runtime_cfg.buffer_size,
                                   sess->c2s_payload_ecc,
                                   LLPS_PAYLOAD_ECC_WORD_COUNT) ?
        NULL : "client_preface_payload_ecc";
}

static const char *llps_backend_preface_wait_writable(
    const int backend_fd,
    uint32_t * const retry_count) {
    short revents = 0;

    if (retry_count == NULL) {
        return "client_preface_flush_arg";
    }
    if (*retry_count >= LLPS_IO_RETRY_BUDGET) {
        return "client_preface_flush_retry";
    }

    ++(*retry_count);
    return (llps_llam_poll_fd_checked(
                backend_fd,
                POLLOUT,
                LLPS_BACKEND_CONNECT_POLL_TIMEOUT_MS,
                &revents,
                "client_preface_flush_poll") < 0) ?
        "client_preface_flush_poll" : NULL;
}

static const char *llps_backend_preface_flush_step(
    llps_session_t * const sess,
    const size_t len,
    size_t * const off,
    uint32_t * const retry_count) {
    const size_t remain = len - *off;
    ssize_t w = 0;
    const char *reason = llps_backend_preface_repair_payload(sess, len);

    if (reason != NULL) {
        return reason;
    }

    w = llps_send_no_sigpipe(sess->backend_fd, sess->c2s_buf + *off, remain);
    if (w < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return llps_backend_preface_wait_writable(sess->backend_fd,
                                                     retry_count);
        }
        return "client_preface_flush";
    }
    if (w == 0) {
        return "client_preface_flush_zero";
    }
    if ((size_t)w > remain) {
        LLPS_EXPECT(false, return "client_preface_flush_contract");
    }

    *off += (size_t)w;
    return NULL;
}

static const char *llps_backend_preface_flush(
    llps_session_t * const sess,
    const size_t len) {
    size_t off = 0u;
    uint32_t retry_count = 0u;
    const char *reason = llps_backend_preface_flush_validate(sess, len);

    if (reason != NULL) {
        return reason;
    }
    if (len == 0u) {
        return NULL;
    }

    for (uint32_t io_step = 0u;
         (off < len) && (io_step < LLPS_SOCKET_IO_STEP_MAX);
         ++io_step) {
        reason = llps_backend_preface_flush_step(sess,
                                                 len,
                                                 &off,
                                                 &retry_count);
        if (reason != NULL) {
            return reason;
        }
    }

    if (off < len) {
        return "client_preface_flush_retry";
    }

    llps_session_touch(sess);
    return NULL;
}

static const char *llps_backend_connect_poll_once(const int fd,
                                                  bool * const out_connected) {
    short revents = 0;
    int poll_rc = 0;
    int so_error = 0;
    socklen_t so_error_len = (socklen_t)sizeof(so_error);

    if (out_connected == NULL) {
        return "backend_connect_arg";
    }
    *out_connected = false;
    poll_rc = llps_llam_poll_fd_checked(fd,
                                        POLLOUT,
                                        LLPS_BACKEND_CONNECT_POLL_TIMEOUT_MS,
                                        &revents,
                                        "backend_connect_poll");
    if (poll_rc < 0) {
        return "backend_poll";
    }
    if (poll_rc == 0) {
        return NULL;
    }
    if ((revents & POLLNVAL) != 0) {
        return "backend_poll_invalid";
    }

    if (getsockopt(fd,
                   SOL_SOCKET,
                   SO_ERROR,
                   &so_error,
                   &so_error_len) < 0) {
        return "backend_so_error";
    }
    if (so_error == 0) {
        if (((revents & (POLLERR | POLLHUP)) != 0) &&
            ((revents & POLLOUT) == 0)) {
            return "backend_so_error";
        }
        *out_connected = true;
        return NULL;
    }
    if ((so_error == EINPROGRESS) || (so_error == EALREADY)) {
        return NULL;
    }

    return "backend_so_error";
}

static const char *llps_backend_connect_wait(
    const int fd,
    const struct sockaddr_in * const addr) {
    int connect_rc = 0;

    if (!llps_fd_is_valid(fd) || (addr == NULL)) {
        return "backend_connect_arg";
    }

    connect_rc = connect(fd,
                         (const struct sockaddr *)(const void *)addr,
                         (socklen_t)sizeof(*addr));
    if (connect_rc == 0) {
        return NULL;
    }

    if (errno != EINPROGRESS) {
        return "backend_connect";
    }

    for (uint32_t attempt = 0u;
         attempt < LLPS_BACKEND_CONNECT_POLL_ATTEMPTS;
         ++attempt) {
        bool connected = false;
        const char * const reason =
            llps_backend_connect_poll_once(fd, &connected);

        if (reason != NULL) {
            return reason;
        }
        if (connected) {
            return NULL;
        }
    }

    return "backend_timeout";
}

/* cppcheck-suppress staticFunction -- public API declared in llps.h */
void llps_shutdown_all_sessions(void) {
    uint32_t max_clients = LLPS_MAX_CLIENTS;

    if (llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
        max_clients = g_runtime_cfg.max_clients;
    }

    for (uint32_t i = 0u; i < max_clients; ++i) {
        if (llps_session_is_active(&g_sessions[i])) {
            llps_force_shutdown_session_fds(&g_sessions[i]);
        } else if (!llps_session_is_free(&g_sessions[i])) {
            LLPS_EXPECT(false, llps_force_shutdown_session_fds(&g_sessions[i]));
        }
    }
}

/* --------------------------------------------------------------------
 * LLAM Tasks
 * -------------------------------------------------------------------- */

/*
 * I/O Architecture:
 * Readiness, sleeps, spawn policy, safepoints, and diagnostics are routed
 * through LLAM contract wrappers. The hot data pump keeps direct nonblocking
 * accept/read/send/connect fast paths for byte movement while LLAM owns every
 * wait boundary so a blocked peer parks the coroutine rather than the runtime
 * worker. Backend connect keeps an explicit bounded nonblocking connect loop
 * with LLAM poll waits so startup latency cannot stretch to the broader session
 * watchdog budget.
 */

static bool llps_pump_context_init(void * const arg,
                                   llps_pump_context_t * const ctx) {
    if ((arg == NULL) || (ctx == NULL)) {
        LLPS_EXPECT(false, return false);
    }

    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->pump = (llps_pump_args_t *)arg;
    ctx->sess = ctx->pump->session;
    ctx->session_id = UINT32_MAX;
    ctx->close_reason = LLPS_CLOSE_REASON_NORMAL;
    if (ctx->sess != NULL) {
        (void)llps_session_index_from_ptr(ctx->sess, &ctx->session_id);
    }
    return true;
}

static bool llps_pump_args_are_valid(const llps_pump_context_t * const ctx) {
    const llps_pump_args_t * const pump = (ctx != NULL) ? ctx->pump : NULL;

    return (pump != NULL) &&
           (pump->buf != NULL) &&
           (pump->buf_len != 0u) &&
           (pump->buf_len <= g_runtime_cfg.buffer_size) &&
           (pump->buf_len <= LLPS_BUFFER_SIZE) &&
           llps_fd_is_valid(pump->src_fd) &&
           llps_fd_is_valid(pump->dst_fd) &&
           llps_fd_is_nonblocking(pump->src_fd) &&
           llps_fd_is_nonblocking(pump->dst_fd) &&
           llps_direction_is_valid(pump->direction);
}

static bool llps_pump_prepare(llps_pump_context_t * const ctx) {
    if ((ctx == NULL) || !llps_session_is_active(ctx->sess) ||
        !llps_pump_args_are_valid(ctx)) {
        if (ctx != NULL) {
            ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        }
        LLPS_EXPECT(false, return false);
    }

    ctx->payload_ecc_enabled = g_runtime_cfg.payload_ecc_enabled != 0u;
    if (ctx->payload_ecc_enabled) {
        ctx->payload_ecc = llps_payload_ecc_for_pump(ctx->sess, ctx->pump);
        if (ctx->payload_ecc == NULL) {
            ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
            LLPS_EXPECT(false, return false);
        }
    }

    return true;
}

static void llps_pump_shutdown_both_fds(const llps_pump_context_t * const ctx) {
    if ((ctx != NULL) && (ctx->pump != NULL)) {
        if (llps_fd_is_valid(ctx->pump->src_fd)) {
            (void)shutdown(ctx->pump->src_fd, SHUT_RDWR);
        }
        if (llps_fd_is_valid(ctx->pump->dst_fd)) {
            (void)shutdown(ctx->pump->dst_fd, SHUT_RDWR);
        }
    }
}

static bool llps_pump_cycle_can_continue(llps_pump_context_t * const ctx) {
    if (!llps_session_hot_path_is_active(ctx->sess)) {
        ctx->close_reason = LLPS_CLOSE_REASON_METADATA_FAULT;
        LLPS_EXPECT(false, return false);
    }
    if (!llps_fd_is_valid(ctx->pump->src_fd) ||
        !llps_fd_is_valid(ctx->pump->dst_fd)) {
        return false;
    }

    return !llps_control_shutdown_is_requested();
}

static bool llps_pump_read_bytes(llps_pump_context_t * const ctx,
                                 ssize_t * const out_n,
                                 bool * const out_continue) {
    ssize_t n = read(ctx->pump->src_fd, ctx->pump->buf, ctx->pump->buf_len);

    *out_n = n;
    *out_continue = false;
    if (n == 0) {
        return false;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            short revents = 0;
            if (llps_llam_poll_fd_checked(ctx->pump->src_fd,
                                          POLLIN,
                                          10,
                                          &revents,
                                          "pump_read_poll") < 0) {
                ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
                return false;
            }
            *out_continue = true;
            return true;
        }
        return false;
    }
    if ((size_t)n > ctx->pump->buf_len) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        LLPS_EXPECT(false, return false);
    }

    return true;
}

static bool llps_pump_seal_read_payload(llps_pump_context_t * const ctx,
                                        const size_t len) {
    if (!ctx->payload_ecc_enabled) {
        return true;
    }

    if (!llps_payload_ecc_seal(ctx->pump->buf,
                               len,
                               ctx->pump->buf_len,
                               ctx->payload_ecc,
                               LLPS_PAYLOAD_ECC_WORD_COUNT) ||
        !llps_payload_ecc_set_len_for_pump(ctx->sess, ctx->pump, len)) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        LLPS_EXPECT(false, return false);
    }

    return true;
}

static bool llps_pump_repair_write_payload(llps_pump_context_t * const ctx,
                                           const size_t len) {
    if (!ctx->payload_ecc_enabled) {
        return true;
    }

    if (!llps_payload_ecc_repair(ctx->pump->buf,
                                 len,
                                 ctx->pump->buf_len,
                                 ctx->payload_ecc,
                                 LLPS_PAYLOAD_ECC_WORD_COUNT)) {
        ctx->close_reason = LLPS_CLOSE_REASON_PAYLOAD_ECC;
        LLPS_EXPECT(false, return false);
    }

    return true;
}

static bool llps_pump_wait_writable(llps_pump_context_t * const ctx,
                                    uint32_t * const retry_count) {
    short revents = 0;

    if (*retry_count >= LLPS_IO_RETRY_BUDGET) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        LLPS_EXPECT(false, return false);
    }
    ++(*retry_count);

    if (llps_llam_poll_fd_checked(ctx->pump->dst_fd,
                                  POLLOUT,
                                  10,
                                  &revents,
                                  "pump_write_poll") < 0) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        return false;
    }

    return true;
}

static bool llps_pump_write_step(llps_pump_context_t * const ctx,
                                 const size_t len,
                                 size_t * const off,
                                 size_t * const remain,
                                 uint32_t * const retry_count) {
    ssize_t w = 0;

    if (!llps_session_hot_path_is_active(ctx->sess)) {
        ctx->close_reason = LLPS_CLOSE_REASON_METADATA_FAULT;
        LLPS_EXPECT(false, return false);
    }
    if (!llps_pump_repair_write_payload(ctx, len)) {
        return false;
    }

    w = llps_send_no_sigpipe(ctx->pump->dst_fd,
                             ctx->pump->buf + *off,
                             *remain);
    if (w < 0) {
        return ((errno == EAGAIN) || (errno == EWOULDBLOCK)) ?
            llps_pump_wait_writable(ctx, retry_count) : false;
    }
    if (w == 0) {
        return false;
    }
    if ((size_t)w > *remain) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        LLPS_EXPECT(false, return false);
    }

    *remain -= (size_t)w;
    *off += (size_t)w;
    return true;
}

static bool llps_pump_write_all(llps_pump_context_t * const ctx,
                                const size_t len) {
    size_t remain = len;
    size_t off = 0u;
    uint32_t retry_count = 0u;

    for (uint32_t io_step = 0u;
         (remain > 0u) && (io_step < LLPS_SOCKET_IO_STEP_MAX);
         ++io_step) {
        if (!llps_pump_write_step(ctx, len, &off, &remain, &retry_count)) {
            return false;
        }
    }

    if (remain > 0u) {
        ctx->close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
        LLPS_EXPECT(false, return false);
    }

    return true;
}

static bool llps_pump_after_success(llps_pump_context_t * const ctx,
                                    const size_t n,
                                    uint64_t * const bytes_since_yield,
                                    uint64_t * const bytes_since_integrity) {
    *bytes_since_yield += (uint64_t)n;
    *bytes_since_integrity += (uint64_t)n;
    if (*bytes_since_integrity >= LLPS_PUMP_INTEGRITY_CHECK_AFTER_BYTES) {
        *bytes_since_integrity = 0u;
        if (!llps_session_is_active(ctx->sess)) {
            ctx->close_reason = LLPS_CLOSE_REASON_METADATA_FAULT;
            LLPS_EXPECT(false, return false);
        }
    }
    if (*bytes_since_yield >= LLPS_PUMP_YIELD_AFTER_BYTES) {
        *bytes_since_yield = 0u;
        llps_llam_yield_checked("pump_yield");
    }

    return true;
}

static void llps_pump_log_start(const llps_pump_context_t * const ctx) {
    llps_logf("session=%u pump=%s start src_fd=%d dst_fd=%d",
              (unsigned)ctx->session_id,
              llps_direction_text(ctx->pump->direction),
              ctx->pump->src_fd,
              ctx->pump->dst_fd);
}

static void llps_pump_log_read(const llps_pump_context_t * const ctx,
                               const size_t n) {
    if (llps_io_log_enabled()) {
        llps_logf("session=%u pump=%s read_bytes=%llu",
                  (unsigned)ctx->session_id,
                  llps_direction_text(ctx->pump->direction),
                  (unsigned long long)n);
    }
}

static void llps_pump_finish(const llps_pump_context_t * const ctx,
                             const bool hard_error,
                             const uint64_t bytes_moved) {
    if (hard_error) {
        llps_session_mark_close_reason_if_active(ctx->sess, ctx->close_reason);
        llps_logf("session=%u pump=%s stop status=error bytes=%llu",
                  (unsigned)ctx->session_id,
                  llps_direction_text(ctx->pump->direction),
                  (unsigned long long)bytes_moved);
        llps_pump_shutdown_both_fds(ctx);
    } else {
        llps_logf("session=%u pump=%s stop status=eof bytes=%llu",
                  (unsigned)ctx->session_id,
                  llps_direction_text(ctx->pump->direction),
                  (unsigned long long)bytes_moved);
        if (llps_fd_is_valid(ctx->pump->dst_fd)) {
            (void)shutdown(ctx->pump->dst_fd, SHUT_WR);
        }
    }
}

static void llps_task_pump(void *arg) {
    llps_pump_context_t ctx = {0};
    bool hard_error = false;
    uint64_t bytes_moved = 0u;
    uint64_t bytes_since_yield = 0u;
    uint64_t bytes_since_integrity_check = 0u;

    ctx.session_id = UINT32_MAX;
    ctx.close_reason = LLPS_CLOSE_REASON_CONTRACT_VIOLATION;
    if (!llps_pump_context_init(arg, &ctx) || !llps_pump_prepare(&ctx)) {
        llps_session_mark_close_reason_if_active(ctx.sess, ctx.close_reason);
        llps_pump_shutdown_both_fds(&ctx);
        return;
    }

    llps_pump_log_start(&ctx);
    for (uint64_t pump_cycle = 0u; pump_cycle < UINT64_MAX; ++pump_cycle) {
        ssize_t n = 0;
        bool retry_read = false;

        if (!llps_pump_cycle_can_continue(&ctx)) {
            hard_error = ctx.close_reason != LLPS_CLOSE_REASON_NORMAL;
            break;
        }
        if (!llps_pump_read_bytes(&ctx, &n, &retry_read)) {
            hard_error = (n != 0);
            break;
        }
        if (retry_read) {
            continue;
        }
        bytes_moved += (uint64_t)((size_t)n);
        llps_session_touch(ctx.sess);
        if (!llps_pump_seal_read_payload(&ctx, (size_t)n) ||
            !llps_pump_write_all(&ctx, (size_t)n) ||
            !llps_pump_after_success(&ctx,
                                     (size_t)n,
                                     &bytes_since_yield,
                                     &bytes_since_integrity_check)) {
            hard_error = true;
            break;
        }
        llps_pump_log_read(&ctx, (size_t)n);
    }

    llps_pump_finish(&ctx, hard_error, bytes_moved);
}

static bool llps_watchdog_runtime_contract_ok(void) {
#if !defined(LLPS_TEST_HOOKS)
    if (!llps_llam_runtime_contract_check()) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
        return false;
    }
#endif

    return true;
}

static void llps_watchdog_run_safety_scrubs(void) {
    if (!llps_session_tmr_scrub_all()) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_software_tmr_failures);
        llps_control_request_shutdown();
        llps_shutdown_all_sessions();
    }
    (void)llps_payload_ecc_scrub_all();
}

static void llps_watchdog_close_idle_session(llps_session_t * const sess,
                                             const uint32_t session_id,
                                             const uint64_t now,
                                             const uint64_t idle_timeout_ns) {
    llps_logf("session=%u idle_timeout age_ns=%llu timeout_ns=%llu",
              (unsigned)session_id,
              (unsigned long long)(now - sess->last_activity_ns),
              (unsigned long long)idle_timeout_ns);
    llps_session_mark_close_reason(sess, LLPS_CLOSE_REASON_IDLE_TIMEOUT);
    llps_force_shutdown_session_fds(sess);
}

static void llps_watchdog_scan_idle_sessions(const uint64_t now) {
    const uint64_t idle_timeout_ns = llps_session_idle_timeout_ns();

    for (uint32_t i = 0u; i < g_runtime_cfg.max_clients; ++i) {
        llps_session_t * const sess = &g_sessions[i];

        LLAM_PREEMPT_POLL_EVERY(i, 16u);
        if (llps_session_is_active(sess)) {
            if ((now >= sess->last_activity_ns) &&
                ((now - sess->last_activity_ns) > idle_timeout_ns)) {
                llps_watchdog_close_idle_session(sess,
                                                 i,
                                                 now,
                                                 idle_timeout_ns);
            }
        } else if (!llps_session_is_free(sess)) {
            LLPS_EXPECT(false, llps_force_shutdown_session_fds(sess));
        }
    }
}

static void llps_task_watchdog(void *arg) {
    (void)arg;

    for (uint64_t watchdog_cycle = 0u;
         watchdog_cycle < UINT64_MAX;
         ++watchdog_cycle) {
        const uint64_t now = llps_llam_now_ns_checked("watchdog_now");

        if (llps_control_shutdown_is_requested()) {
            llps_shutdown_all_sessions();
            break;
        }

        if (!llps_watchdog_runtime_contract_ok()) {
            break;
        }

        llps_watchdog_run_safety_scrubs();
        llps_readiness_runtime_monitor_tick();
        if (llps_control_shutdown_is_requested()) {
            llps_shutdown_all_sessions();
            break;
        }

        llps_watchdog_scan_idle_sessions(now);
        llps_watchdog_sleep_ms(
            (int)(LLPS_WATCHDOG_SCAN_INTERVAL_NS / 1000000ULL));

        if (llps_control_shutdown_is_requested()) {
            llps_shutdown_all_sessions();
            break;
        }
    }
}

static void llps_connection_record_backend_fail(const llps_session_t * const sess,
                                                const uint32_t session_id,
                                                const char * const reason) {
    (void)llps_record_ip_audit_event(LLPS_IP_AUDIT_BACKEND_FAIL,
                                     session_id,
                                     sess->request_no,
                                     sess->client_ip,
                                     sess->client_port,
                                     reason);
}

static bool llps_connection_prepare_backend_addr(
    llps_session_t * const sess,
    const uint32_t session_id,
    struct sockaddr_in * const baddr) {
    if (llps_build_backend_addr(baddr) == LLPS_OK) {
        return true;
    }

    llps_connection_record_backend_fail(sess, session_id, "backend_addr");
    llps_close_session(sess);
    return false;
}

static bool llps_connection_read_preface(llps_session_t * const sess,
                                         const uint32_t session_id,
                                         size_t * const out_len) {
    const char * const failure = llps_client_preface_read(sess, out_len);

    if (failure == NULL) {
        if (*out_len > 0u) {
            llps_logf("session=%u client_preface_ready bytes=%u",
                      (unsigned)session_id,
                      (unsigned)*out_len);
        }
        return true;
    }

    if (failure == LLPS_CLIENT_PREFACE_TIMEOUT_REASON) {
        llps_session_mark_close_reason(
            sess,
            LLPS_CLOSE_REASON_CLIENT_PREFACE_TIMEOUT);
    } else if (failure == LLPS_PROTOCOL_HANDSHAKE_INVALID_REASON) {
        llps_session_mark_close_reason(sess,
                                       LLPS_CLOSE_REASON_PROTOCOL_HANDSHAKE);
    }
    llps_connection_record_backend_fail(sess, session_id, failure);
    llps_close_session(sess);
    return false;
}

static bool llps_connection_open_backend_socket(llps_session_t * const sess,
                                                const uint32_t session_id) {
    sess->backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sess->backend_fd >= 0) {
        llps_session_refresh_crc(sess);
        return true;
    }

    sess->backend_fd = LLPS_INVALID_FD;
    llps_session_refresh_crc(sess);
    llps_connection_record_backend_fail(sess, session_id, "backend_socket");
    llps_close_session(sess);
    return false;
}

static bool llps_connection_setup_backend_fd(llps_session_t * const sess,
                                             const uint32_t session_id) {
    if ((llps_set_close_on_exec(sess->backend_fd) == LLPS_OK) &&
        (llps_set_nonblocking(sess->backend_fd) == LLPS_OK) &&
        (llps_set_no_sigpipe(sess->backend_fd) == LLPS_OK) &&
        (llps_set_tcp_nodelay(sess->backend_fd) == LLPS_OK)) {
        return true;
    }

    llps_connection_record_backend_fail(sess, session_id, "backend_fd_setup");
    llps_close_session(sess);
    return false;
}

static bool llps_connection_connect_backend(
    llps_session_t * const sess,
    const uint32_t session_id,
    const struct sockaddr_in * const baddr) {
    const char * const failure =
        llps_backend_connect_wait(sess->backend_fd, baddr);

    if (failure != NULL) {
        llps_connection_record_backend_fail(sess, session_id, failure);
        llps_close_session(sess);
        return false;
    }

    llps_session_touch(sess);
    llps_logf("session=%u backend_connect_ok backend_fd=%d",
              (unsigned)session_id,
              sess->backend_fd);
    return true;
}

static bool llps_connection_flush_preface(
    llps_session_t * const sess,
    const uint32_t session_id,
    const size_t client_preface_len) {
    const char * const failure =
        llps_backend_preface_flush(sess, client_preface_len);

    if (failure != NULL) {
        llps_connection_record_backend_fail(sess, session_id, failure);
        llps_close_session(sess);
        return false;
    }

    return true;
}

static bool llps_connection_record_connected(llps_session_t * const sess,
                                             const uint32_t session_id) {
    if (llps_record_ip_audit_event(LLPS_IP_AUDIT_BACKEND_CONNECT,
                                   session_id,
                                   sess->request_no,
                                   sess->client_ip,
                                   sess->client_port,
                                   "connected")) {
        return true;
    }

    llps_close_session(sess);
    return false;
}

static bool llps_connection_setup_client_fd(llps_session_t * const sess,
                                            const uint32_t session_id) {
    if (llps_set_nonblocking(sess->client_fd) == LLPS_OK) {
        return true;
    }

    llps_connection_record_backend_fail(sess, session_id, "client_fd_setup");
    llps_close_session(sess);
    return false;
}

static void llps_connection_prepare_pump_args(llps_session_t * const sess) {
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = g_runtime_cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    sess->pump_s2c.session = sess;
    sess->pump_s2c.src_fd = sess->backend_fd;
    sess->pump_s2c.dst_fd = sess->client_fd;
    sess->pump_s2c.buf = sess->s2c_buf;
    sess->pump_s2c.buf_len = g_runtime_cfg.buffer_size;
    sess->pump_s2c.direction = LLPS_DIR_S2C;
    llps_session_refresh_crc(sess);
}

static bool llps_connection_prepare_pump_group(
    llam_task_group_t ** const group_ref,
    llam_spawn_opts_t * const pump_opts) {
    *group_ref = llps_llam_task_group_create_checked("pump_group_create");
    if (*group_ref == NULL) {
        return false;
    }

    if (!llps_llam_spawn_opts_prepare(pump_opts,
                                      LLAM_TASK_CLASS_LATENCY,
                                      LLAM_SPAWN_F_LATENCY_CRITICAL)) {
        (void)llps_llam_task_group_destroy_checked(*group_ref,
                                                   "pump_group_destroy");
        *group_ref = NULL;
        return false;
    }

    return true;
}

static bool llps_connection_spawn_pump_pair(llps_session_t * const sess,
                                            llam_task_group_t * const group,
                                            const llam_spawn_opts_t * const opts) {
    if (llps_llam_task_group_spawn_checked(group,
                                           llps_task_pump,
                                           &sess->pump_c2s,
                                           opts,
                                           "pump_c2s_spawn") == NULL) {
        return false;
    }

    if (llps_llam_task_group_spawn_checked(group,
                                           llps_task_pump,
                                           &sess->pump_s2c,
                                           opts,
                                           "pump_s2c_spawn") == NULL) {
        (void)shutdown(sess->client_fd, SHUT_RDWR);
        (void)shutdown(sess->backend_fd, SHUT_RDWR);
        (void)llps_llam_task_group_join_checked(group,
                                                "pump_group_join_s2c_fail");
        return false;
    }

    return true;
}

static bool llps_connection_run_pumps(llps_session_t * const sess,
                                      const uint32_t session_id) {
    llam_task_group_t *group = NULL;
    llam_spawn_opts_t pump_opts;

    if (!llps_connection_prepare_pump_group(&group, &pump_opts)) {
        llps_connection_record_backend_fail(sess, session_id, "pump_group");
        llps_close_session(sess);
        return false;
    }

    if (!llps_connection_spawn_pump_pair(sess, group, &pump_opts)) {
        (void)llps_llam_task_group_destroy_checked(group,
                                                   "pump_group_destroy_fail");
        llps_connection_record_backend_fail(sess, session_id, "pump_spawn");
        llps_close_session(sess);
        return false;
    }

    (void)llps_llam_task_group_join_checked(group, "pump_group_join");
    (void)llps_llam_task_group_destroy_checked(group, "pump_group_destroy");
    return true;
}

/* Manages a single client connection, connects to backend, and spawns pumps */
static void llps_task_connection(void *arg) {
    llps_session_t *sess = (llps_session_t *)arg;
    struct sockaddr_in baddr;
    uint32_t session_id = UINT32_MAX;
    size_t client_preface_len = 0u;

    LLPS_EXPECT(sess != NULL, return);
    (void)llps_session_index_from_ptr(sess, &session_id);

    if (!llps_session_is_active(sess)) {
        LLPS_EXPECT(false, return);
    }

    if (!llps_connection_prepare_backend_addr(sess, session_id, &baddr) ||
        !llps_connection_read_preface(sess, session_id, &client_preface_len)) {
        return;
    }
    llps_logf("session=%u backend_connect_start target=%s:%u",
              (unsigned)session_id,
              g_runtime_cfg.target_ip,
              (unsigned)g_runtime_cfg.target_port);
    if (!llps_connection_open_backend_socket(sess, session_id) ||
        !llps_connection_setup_backend_fd(sess, session_id) ||
        !llps_connection_connect_backend(sess, session_id, &baddr) ||
        !llps_connection_flush_preface(sess,
                                       session_id,
                                       client_preface_len) ||
        !llps_connection_record_connected(sess, session_id) ||
        !llps_connection_setup_client_fd(sess, session_id)) {
        return;
    }

    llps_connection_prepare_pump_args(sess);
    llps_logf("session=%u pumps_ready client_fd=%d backend_fd=%d buffer=%u",
              (unsigned)session_id,
              sess->client_fd,
              sess->backend_fd,
              (unsigned)g_runtime_cfg.buffer_size);

    if (!llps_connection_run_pumps(sess, session_id)) {
        return;
    }

    llps_close_session(sess);
}

static void llps_server_stop_readiness_worker(void) {
#if !defined(LLPS_TEST_HOOKS)
    llps_readiness_runtime_monitor_worker_stop();
#endif
}

static bool llps_server_start_readiness_worker(int * const listen_fd_ref) {
    (void)listen_fd_ref;

#if !defined(LLPS_TEST_HOOKS)
    if ((g_runtime_cfg.require_readiness != 0u) &&
        !llps_readiness_runtime_monitor_worker_start()) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_monitor_failures);
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_cfg_failures);
        LLPS_EXPECT(false, llps_control_request_shutdown());
        (void)llps_close_listen_socket(listen_fd_ref);
        return false;
    }
#endif

    return true;
}

static void llps_server_cleanup(int * const listen_fd_ref) {
    llps_control_request_shutdown();
    llps_shutdown_all_sessions();
    llps_server_stop_readiness_worker();
    (void)llps_close_listen_socket(listen_fd_ref);
    llps_watchdog_sleep_pipe_close();
    llps_logf("server_task_stop");
}

static bool llps_server_prepare_spawn_opts(
    llam_spawn_opts_t * const watchdog_opts,
    llam_spawn_opts_t * const connection_opts) {
    if (!llps_llam_spawn_opts_prepare(watchdog_opts,
                                      LLAM_TASK_CLASS_LATENCY,
                                      LLAM_SPAWN_F_SYS_TASK |
                                      LLAM_SPAWN_F_LATENCY_CRITICAL)) {
        return false;
    }

    return llps_llam_spawn_opts_prepare(connection_opts,
                                        LLAM_TASK_CLASS_LATENCY,
                                        LLAM_SPAWN_F_LATENCY_CRITICAL);
}

static bool llps_server_start_watchdog(
    const llam_spawn_opts_t * const watchdog_opts) {
    llam_task_t * const watchdog_task =
        llps_llam_spawn_checked(llps_task_watchdog,
                                NULL,
                                watchdog_opts,
                                "watchdog_spawn");

    if (watchdog_task == NULL) {
        return false;
    }
    if (!llps_llam_detach_checked(watchdog_task, "watchdog_detach")) {
        return false;
    }

    llps_logf("watchdog_task_start");
    return true;
}

static bool llps_server_poll_accept_ready(const int listen_fd,
                                          bool * const out_ready) {
    short revents = 0;
    const int p_res = llps_llam_poll_fd_checked(listen_fd,
                                                POLLIN,
                                                LLPS_ACCEPT_POLL_TIMEOUT_MS,
                                                &revents,
                                                "accept_poll");
    if (out_ready == NULL) {
        return false;
    }

    *out_ready = false;
    if (p_res < 0) {
        return false;
    }
    if (p_res == 0) {
        llps_watchdog_sleep_ms(LLPS_ACCEPT_IDLE_BACKOFF_MS);
        return true;
    }

    *out_ready = true;
    return true;
}

static bool llps_server_accept_client(
    const int listen_fd,
    llps_accept_client_t * const client,
    bool * const server_running) {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    (void)memset(client, 0, sizeof(*client));
    client->client_fd = accept(listen_fd,
                               (struct sockaddr *)&client_addr,
                               &addrlen);
    if (client->client_fd < 0) {
        if (!llps_handle_accept_error(errno)) {
            *server_running = false;
        }
        return false;
    }

    llps_peer_text_from_sockaddr((const struct sockaddr *)&client_addr,
                                 addrlen,
                                 client->client_ip,
                                 sizeof(client->client_ip),
                                 &client->client_port);
    if (!llps_next_request_no(&client->request_no)) {
        LLPS_EXPECT(false, (void)0);
        llps_control_request_shutdown();
        *server_running = false;
        (void)llps_close_connected_fd(&client->client_fd);
        return false;
    }

    return true;
}

static bool llps_server_drop_for_rate_limit(
    llps_accept_client_t * const client,
    bool * const server_running) {
    uint32_t count = 0u;
    uint32_t limit = 0u;
    uint32_t window_ms = 0u;
    const char *drop_reason = NULL;

    if (!llps_client_ip_rate_limit_exceeded(client->client_ip,
                                            &count,
                                            &limit,
                                            &window_ms,
                                            &drop_reason)) {
        return false;
    }

    llps_logf("accept_drop reason=%s peer=%s:%u count=%u limit=%u window_ms=%u",
              (drop_reason != NULL) ? drop_reason : "client_ip_rate_limit",
              client->client_ip,
              (unsigned)client->client_port,
              (unsigned)count,
              (unsigned)limit,
              (unsigned)window_ms);
    if (!llps_record_ip_audit_event(LLPS_IP_AUDIT_DROP,
                                    UINT32_MAX,
                                    client->request_no,
                                    client->client_ip,
                                    client->client_port,
                                    (drop_reason != NULL) ?
                                        drop_reason : "client_ip_rate_limit")) {
        *server_running = false;
    }
    (void)llps_close_connected_fd(&client->client_fd);
    return true;
}

static bool llps_server_drop_for_session_limit(
    llps_accept_client_t * const client,
    bool * const server_running) {
    uint32_t active = 0u;
    uint32_t limit = 0u;

    if (!llps_client_ip_session_limit_exceeded(client->client_ip,
                                               &active,
                                               &limit)) {
        return false;
    }

    llps_logf("accept_drop reason=client_ip_limit peer=%s:%u active=%u limit=%u",
              client->client_ip,
              (unsigned)client->client_port,
              (unsigned)active,
              (unsigned)limit);
    if (!llps_record_ip_audit_event(LLPS_IP_AUDIT_DROP,
                                    UINT32_MAX,
                                    client->request_no,
                                    client->client_ip,
                                    client->client_port,
                                    "client_ip_limit")) {
        *server_running = false;
    }
    (void)llps_close_connected_fd(&client->client_fd);
    return true;
}

static bool llps_server_setup_client_fd(llps_accept_client_t * const client,
                                        bool * const server_running) {
    if ((llps_set_close_on_exec(client->client_fd) == LLPS_OK) &&
        (llps_set_nonblocking(client->client_fd) == LLPS_OK) &&
        (llps_set_no_sigpipe(client->client_fd) == LLPS_OK) &&
        (llps_set_tcp_nodelay(client->client_fd) == LLPS_OK)) {
        return true;
    }

    if (!llps_record_ip_audit_event(LLPS_IP_AUDIT_DROP,
                                    UINT32_MAX,
                                    client->request_no,
                                    client->client_ip,
                                    client->client_port,
                                    "fd_setup_failed")) {
        *server_running = false;
    }
    (void)llps_close_connected_fd(&client->client_fd);
    return false;
}

static void llps_server_drop_pool_full(llps_accept_client_t * const client,
                                       bool * const server_running) {
    llps_logf("accept_drop reason=session_pool_full client_fd=%d",
              client->client_fd);
    if (!llps_record_ip_audit_event(LLPS_IP_AUDIT_DROP,
                                    UINT32_MAX,
                                    client->request_no,
                                    client->client_ip,
                                    client->client_port,
                                    "session_pool_full")) {
        *server_running = false;
    }
    (void)llps_close_connected_fd(&client->client_fd);
}

static bool llps_server_spawn_connection(
    llps_session_t * const sess,
    const uint32_t sess_idx,
    const llam_spawn_opts_t * const connection_opts) {
    llam_task_t * const task = llps_llam_spawn_checked(llps_task_connection,
                                                       sess,
                                                       connection_opts,
                                                       "connection_spawn");
    if (task == NULL) {
        (void)llps_record_ip_audit_event(LLPS_IP_AUDIT_BACKEND_FAIL,
                                         sess_idx,
                                         sess->request_no,
                                         sess->client_ip,
                                         sess->client_port,
                                         "connection_spawn");
        llps_close_session(sess);
        return false;
    }
    if (!llps_llam_detach_checked(task, "connection_detach")) {
        LLPS_EXPECT(false, llps_force_shutdown_session_fds(sess));
    }

    return true;
}

static bool llps_server_assign_session(
    llps_accept_client_t * const client,
    const llam_spawn_opts_t * const connection_opts,
    bool * const server_running) {
    uint32_t sess_idx = 0u;

    if (llps_find_free_session(&sess_idx) != LLPS_OK) {
        llps_server_drop_pool_full(client, server_running);
        return false;
    }

    llps_session_t * const sess = &g_sessions[sess_idx];
    llps_session_prepare_active_with_peer(sess,
                                          sess_idx,
                                          client->client_fd,
                                          client->client_ip,
                                          client->client_port,
                                          client->request_no);
    llps_logf("session=%u request=%llu assigned client_fd=%d peer=%s:%u",
              (unsigned)sess_idx,
              (unsigned long long)sess->request_no,
              client->client_fd,
              sess->client_ip,
              (unsigned)sess->client_port);
    if (!llps_record_ip_audit_event(LLPS_IP_AUDIT_ACCEPT,
                                    sess_idx,
                                    sess->request_no,
                                    sess->client_ip,
                                    sess->client_port,
                                    "accepted")) {
        llps_close_session(sess);
        *server_running = false;
        return false;
    }

    (void)llps_server_spawn_connection(sess, sess_idx, connection_opts);
    return true;
}

static void llps_server_handle_client(
    llps_accept_client_t * const client,
    const llam_spawn_opts_t * const connection_opts,
    bool * const server_running) {
    if (llps_server_drop_for_rate_limit(client, server_running) ||
        llps_server_drop_for_session_limit(client, server_running)) {
        return;
    }
    if (!llps_server_setup_client_fd(client, server_running)) {
        return;
    }

    llps_logf("accept client_fd=%d peer=%s:%u",
              client->client_fd,
              client->client_ip,
              (unsigned)client->client_port);
    (void)llps_server_assign_session(client,
                                     connection_opts,
                                     server_running);
}

static void llps_server_accept_batch(
    const int listen_fd,
    const llam_spawn_opts_t * const connection_opts,
    bool * const server_running) {
    for (uint32_t batch_count = 0u;
         batch_count < g_runtime_cfg.accept_batch_max;
         ++batch_count) {
        llps_accept_client_t client;

        if (!llps_server_accept_client(listen_fd, &client, server_running)) {
            break;
        }
        llps_server_handle_client(&client, connection_opts, server_running);
        LLAM_PREEMPT_POLL_EVERY(batch_count + 1u, 8u);
        if (!*server_running) {
            break;
        }
    }
}

/* Master acceptor task */
void llps_run_server(void *arg) {
    int *listen_fd_ref = (int *)arg;
    int listen_fd = LLPS_INVALID_FD;
    llam_spawn_opts_t watchdog_opts;
    llam_spawn_opts_t connection_opts;
    bool server_running = true;

    if (listen_fd_ref != NULL) {
        listen_fd = *listen_fd_ref;
    }

    if (listen_fd < 0) {
        return;
    }

    if (listen_fd_ref != NULL) {
        *listen_fd_ref = LLPS_INVALID_FD;
    }

    llps_logf("server_task_start listen_fd=%d", listen_fd);

    if (!llps_server_start_readiness_worker(&listen_fd) ||
        !llps_server_prepare_spawn_opts(&watchdog_opts, &connection_opts) ||
        !llps_server_start_watchdog(&watchdog_opts)) {
        llps_server_cleanup(&listen_fd);
        return;
    }

    for (; server_running && !llps_control_shutdown_is_requested();) {
        bool accept_ready = false;

        if (!llps_server_poll_accept_ready(listen_fd, &accept_ready)) {
            break;
        }
        if (!accept_ready) {
            continue;
        }
        if (!llps_runtime_cfg_reconcile(&g_runtime_cfg)) {
            break;
        }
        llps_server_accept_batch(listen_fd,
                                 &connection_opts,
                                 &server_running);
    }

    llps_server_cleanup(&listen_fd);
}

void llps_request_shutdown(void) {
    llps_control_request_shutdown();
}
