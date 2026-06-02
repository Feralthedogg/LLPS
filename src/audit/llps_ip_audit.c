/**
 * @file src/audit/llps_ip_audit.c
 * @brief PXF audit logging for proxied client and backend endpoints.
 *
 * @details
 * Audit code stays isolated from the proxy pump so observability can evolve
 * without changing data forwarding semantics.
 */

#include "llps_ip_audit.h"

#include "llam/runtime.h"

#include "llps_crc.h"
#include "llps_hmac.h"
#include "llps_internal.h"
#include "llps_log.h"
#include "llps_net.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LLPS_IP_AUDIT_LINE_BYTES          (4096u)
#define LLPS_IP_AUDIT_MAC_MESSAGE_BYTES   (1024u)
#define LLPS_IP_AUDIT_IO_ATTEMPT_MAX      (LLPS_IP_AUDIT_LINE_BYTES * 2u)

static const char llps_ip_audit_pxf_header[] =
    "pxf/1\n"
    "# LLPS IP audit\n"
    "@table audit seq:tok request_no:tok event:tok event_no:tok "
    "total_events:tok time_ns:tok session:tok reason:tok "
    "duration_ns:tok crc32:tok\n"
    "@table audit_endpoint seq:tok role:tok host:host port:u16\n"
    "@table audit_mac seq:tok key_fingerprint:tok hmac_sha256:tok\n"
    "@table evidence seq:tok event:tok time_ns:tok status:tok "
    "failure_mask:tok monitor_passes:tok software_evidence_patrol:tok "
    "synthetic_ecc_topology_patrol:tok "
    "synthetic_ecc_topology_patrol_failures:tok "
    "synthetic_fault_patrol:tok synthetic_fault_patrol_failures:tok "
    "synthetic_numa_patrol:tok synthetic_numa_patrol_failures:tok "
    "require_readiness:tok platform_evidence_mode:tok "
    "software_ecc_enabled:tok software_numa_enabled:tok "
    "software_fault_injection_mode:tok crc32:tok\n"
    "@table evidence_mac seq:tok key_fingerprint:tok hmac_sha256:tok\n";

static const char llps_ip_audit_pxf_header_without_evidence_mac[] =
    "pxf/1\n"
    "# LLPS IP audit\n"
    "@table audit seq:tok request_no:tok event:tok event_no:tok "
    "total_events:tok time_ns:tok session:tok reason:tok "
    "duration_ns:tok crc32:tok\n"
    "@table audit_endpoint seq:tok role:tok host:host port:u16\n"
    "@table audit_mac seq:tok key_fingerprint:tok hmac_sha256:tok\n"
    "@table evidence seq:tok event:tok time_ns:tok status:tok "
    "failure_mask:tok monitor_passes:tok software_evidence_patrol:tok "
    "synthetic_ecc_topology_patrol:tok "
    "synthetic_ecc_topology_patrol_failures:tok "
    "synthetic_fault_patrol:tok synthetic_fault_patrol_failures:tok "
    "synthetic_numa_patrol:tok synthetic_numa_patrol_failures:tok "
    "require_readiness:tok platform_evidence_mode:tok "
    "software_ecc_enabled:tok software_numa_enabled:tok "
    "software_fault_injection_mode:tok crc32:tok\n";

static const char llps_ip_audit_pxf_header_without_evidence[] =
    "pxf/1\n"
    "# LLPS IP audit\n"
    "@table audit seq:tok request_no:tok event:tok event_no:tok "
    "total_events:tok time_ns:tok session:tok reason:tok "
    "duration_ns:tok crc32:tok\n"
    "@table audit_endpoint seq:tok role:tok host:host port:u16\n"
    "@table audit_mac seq:tok key_fingerprint:tok hmac_sha256:tok\n";

static const char llps_ip_audit_event_line_format[] =
    "# ---- llps audit event ----\n"
    "#   seq: %llu\n"
    "#   request_no: %llu\n"
    "#   event: %s\n"
    "#   event_no: %llu\n"
    "#   total_events: %llu\n"
    "#   time_ns: %llu\n"
    "#   session: %u\n"
    "#   reason: %s\n"
    "#   duration_ns: %llu\n"
    "#   crc32: 0x%08x\n"
    "%s"
    "#   endpoints:\n"
    "#     client: %s:%u\n"
    "#     listen: %s:%u\n"
    "#     target: %s:%u\n"
    "#     backend: %s:%u\n"
    "+audit %llu %llu %s %llu %llu %llu %u %s %llu 0x%08x\n"
    "+audit_endpoint %llu client %s %u\n"
    "+audit_endpoint %llu listen %s %u\n"
    "+audit_endpoint %llu target %s %u\n"
    "+audit_endpoint %llu backend %s %u\n"
    "%s"
    "\n";

static const char llps_ip_audit_evidence_line_format[] =
    "# ---- llps readiness evidence ----\n"
    "#   evidence_seq: %llu\n"
    "#   event: %s\n"
    "#   time_ns: %llu\n"
    "#   status: 0x%08x\n"
    "#   failure_mask: 0x%08x\n"
    "#   monitor_passes: %llu\n"
    "#   software_evidence_patrol: %llu\n"
    "#   synthetic_ecc_topology_patrol: %llu\n"
    "#   synthetic_ecc_topology_patrol_failures: %llu\n"
    "#   synthetic_fault_patrol: %llu\n"
    "#   synthetic_fault_patrol_failures: %llu\n"
    "#   synthetic_numa_patrol: %llu\n"
    "#   synthetic_numa_patrol_failures: %llu\n"
    "#   require_readiness: %u\n"
    "#   platform_evidence_mode: %u\n"
    "#   software_ecc_enabled: %u\n"
    "#   software_numa_enabled: %u\n"
    "#   software_fault_injection_mode: %u\n"
    "#   crc32: 0x%08x\n"
    "%s"
    "+evidence %llu %s %llu 0x%08x 0x%08x %llu %llu %llu %llu "
    "%llu %llu %llu %llu 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "
    "0x%08x\n"
    "%s"
    "\n";

static bool llps_ip_audit_call_blocking_checked(
    llam_blocking_fn fn,
    void * const arg,
    void ** const out,
    const char * const operation) {
    if ((fn == NULL) || (out == NULL) || (operation == NULL)) {
        llps_logf("ip_audit_llam_contract_failure operation=%s reason=bad_args",
                  (operation != NULL) ? operation : "unknown");
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    *out = NULL;
    if (llam_call_blocking_result(fn, arg, out) != 0) {
        llps_logf("ip_audit_llam_contract_failure operation=%s",
                  (operation != NULL) ? operation : "unknown");
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    return true;
}

static const char llps_ip_audit_pxf_header_legacy[] =
    "pxf/1\n"
    "# LLPS IP audit\n"
    "@table audit seq:tok request_no:tok event:tok event_no:tok "
    "total_events:tok time_ns:tok session:tok reason:tok "
    "duration_ns:tok crc32:tok\n"
    "@table audit_endpoint seq:tok role:tok host:host port:u16\n";

typedef struct {
    int fd;
    const char *line;
    size_t len;
    int rc;
} llps_ip_audit_write_job_t;

typedef enum {
    LLPS_IP_AUDIT_ROLE_CLIENT = 0,
    LLPS_IP_AUDIT_ROLE_LISTEN,
    LLPS_IP_AUDIT_ROLE_TARGET,
    LLPS_IP_AUDIT_ROLE_BACKEND,
    LLPS_IP_AUDIT_ROLE_COUNT
} llps_ip_audit_role_t;

typedef struct {
    bool active;
    bool require_mac;
    uint64_t seq;
    uint64_t request_no;
    uint64_t event_no;
    uint64_t total_events;
    uint64_t time_ns;
    uint64_t duration_ns;
    uint32_t session_id;
    uint32_t crc32;
    llps_ip_audit_event_type_t type;
    char reason[32];
    char endpoint_host[LLPS_IP_AUDIT_ROLE_COUNT][LLPS_YML_MAX_IP_TEXT];
    uint16_t endpoint_port[LLPS_IP_AUDIT_ROLE_COUNT];
    uint32_t endpoint_mask;
    bool mac_seen;
    uint32_t mac_key_fingerprint;
    char mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];
} llps_ip_audit_scan_state_t;

typedef struct {
    bool active;
    bool require_mac;
    uint64_t seq;
    uint32_t crc32;
    llps_ip_audit_evidence_event_t event;
    bool mac_seen;
} llps_ip_audit_evidence_scan_state_t;

typedef struct {
    llps_ip_audit_scan_state_t *audit_state;
    llps_ip_audit_evidence_scan_state_t *evidence_state;
    uint64_t *out_seq;
    uint64_t *out_evidence_seq;
    uint64_t *event_counts;
    const char *mac_key_path;
    uint32_t expected_mac_key_fingerprint;
} llps_ip_audit_scan_context_t;

typedef struct {
    llps_ip_audit_event_t normalized;
    llps_ip_audit_write_job_t job;
    char line[LLPS_IP_AUDIT_LINE_BYTES];
    char mac_message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES];
    char mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];
    char mac_comment[160u];
    char mac_row[128u];
    uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint64_t seq;
    uint64_t event_no;
    uint64_t total_events;
    uint32_t crc;
    uint32_t mac_key_fingerprint;
    size_t mac_message_len;
    int written;
    void *write_result;
    bool writer_locked;
    bool ok;
} llps_ip_audit_record_context_t;

typedef struct {
    llps_ip_audit_evidence_event_t normalized;
    llps_ip_audit_write_job_t job;
    char line[LLPS_IP_AUDIT_LINE_BYTES];
    char mac_message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES];
    char mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];
    char mac_comment[160u];
    char mac_row[128u];
    uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint64_t seq;
    uint32_t crc;
    uint32_t mac_key_fingerprint;
    size_t mac_message_len;
    int written;
    void *write_result;
    bool writer_locked;
    bool ok;
} llps_ip_audit_evidence_record_context_t;

static int g_ip_audit_fd = LLPS_INVALID_FD;
static bool g_ip_audit_enabled = false;
static uint64_t g_ip_audit_seq = 0u;
static uint64_t g_ip_audit_seq_inverse = UINT64_MAX;
static uint64_t g_ip_audit_evidence_seq = 0u;
static uint64_t g_ip_audit_evidence_seq_inverse = UINT64_MAX;
static uint64_t g_ip_audit_event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT];
static uint64_t g_ip_audit_event_counts_inverse[LLPS_IP_AUDIT_EVENT_TYPE_COUNT];
static char g_ip_audit_listen_host[LLPS_YML_MAX_IP_TEXT];
static uint16_t g_ip_audit_listen_port = 0u;
static char g_ip_audit_target_host[LLPS_YML_MAX_IP_TEXT];
static uint16_t g_ip_audit_target_port = 0u;
static char g_ip_audit_backend_ip[LLPS_CLIENT_IP_TEXT_LEN];
static uint16_t g_ip_audit_backend_port = 0u;
static bool g_ip_audit_mac_enabled = false;
static char g_ip_audit_mac_key_path[LLPS_YML_MAX_PATH_TEXT];
static uint32_t g_ip_audit_mac_key_fingerprint = 0u;
static uint32_t g_ip_audit_mac_key_fingerprint_inverse = UINT32_MAX;
static llam_mutex_t *g_ip_audit_writer_mutex = NULL;

static uint32_t llps_ip_audit_event_crc(
    uint64_t seq,
    uint64_t event_no,
    uint64_t total_events,
    const llps_ip_audit_event_t *event);

static uint32_t llps_ip_audit_evidence_crc(
    uint64_t seq,
    const llps_ip_audit_evidence_event_t *event);

static bool llps_ip_audit_build_mac_message(
    uint64_t seq,
    uint64_t event_no,
    uint64_t total_events,
    uint32_t crc,
    const llps_ip_audit_event_t *event,
    char message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES],
    size_t *out_message_len);

static bool llps_ip_audit_build_evidence_mac_message(
    uint64_t seq,
    uint32_t crc,
    const llps_ip_audit_evidence_event_t *event,
    char message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES],
    size_t *out_message_len);

static bool llps_ip_audit_hex_encode(
    const uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    char out_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u]);

static bool llps_ip_audit_writer_mutex_create_checked(void) {
    if (g_ip_audit_writer_mutex != NULL) {
        return true;
    }

    g_ip_audit_writer_mutex = llam_mutex_create();
    if (g_ip_audit_writer_mutex == NULL) {
        llps_logf("ip_audit_llam_contract_failure operation=writer_mutex_create errno=%d",
                  errno);
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    return true;
}

static bool llps_ip_audit_writer_mutex_destroy_checked(void) {
    if (g_ip_audit_writer_mutex == NULL) {
        return true;
    }

    if (llam_mutex_destroy(g_ip_audit_writer_mutex) != 0) {
        llps_logf("ip_audit_llam_contract_failure operation=writer_mutex_destroy errno=%d",
                  errno);
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    g_ip_audit_writer_mutex = NULL;
    return true;
}

static bool llps_ip_audit_writer_lock_checked(bool * const out_locked) {
    if (out_locked == NULL) {
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    *out_locked = false;
    if (g_ip_audit_writer_mutex == NULL) {
        return true;
    }

    if (llam_mutex_lock(g_ip_audit_writer_mutex) == 0) {
        *out_locked = true;
        return true;
    }

    if (errno == ENOTSUP) {
        return true;
    }

    llps_logf("ip_audit_llam_contract_failure operation=writer_mutex_lock errno=%d",
              errno);
    LLPS_EXPECT(false, (void)0);
    return false;
}

static bool llps_ip_audit_writer_unlock_checked(const bool locked) {
    if (!locked) {
        return true;
    }

    if (g_ip_audit_writer_mutex == NULL) {
        LLPS_EXPECT(false, (void)0);
        return false;
    }

    if (llam_mutex_unlock(g_ip_audit_writer_mutex) == 0) {
        return true;
    }

    llps_logf("ip_audit_llam_contract_failure operation=writer_mutex_unlock errno=%d",
              errno);
    LLPS_EXPECT(false, (void)0);
    return false;
}

static bool llps_ip_audit_copy_text(char * const dst,
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

static bool llps_ip_audit_ascii_is_alnum(const char c) {
    return ((c >= '0') && (c <= '9')) ||
           ((c >= 'A') && (c <= 'Z')) ||
           ((c >= 'a') && (c <= 'z'));
}

static bool llps_ip_audit_token_is_safe(const char * const text,
                                        const size_t cap,
                                        const bool host_token) {
    bool saw_char = false;

    if ((text == NULL) || (cap == 0u)) {
        return false;
    }

    for (size_t i = 0u; i < cap; ++i) {
        const char c = text[i];

        if (c == '\0') {
            return saw_char;
        }

        if (llps_ip_audit_ascii_is_alnum(c) ||
            (c == '_') ||
            (c == '-') ||
            (host_token && ((c == '.') || (c == ':')))) {
            saw_char = true;
            continue;
        }

        return false;
    }

    return false;
}

static bool llps_ip_audit_event_tokens_are_safe(
    const llps_ip_audit_event_t * const event) {
    if (event == NULL) {
        return false;
    }

    return ((uint32_t)event->type <
            (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT) &&
           llps_ip_audit_token_is_safe(event->client_ip,
                                       sizeof(event->client_ip),
                                       true) &&
           llps_ip_audit_token_is_safe(event->listen_host,
                                       sizeof(event->listen_host),
                                       true) &&
           llps_ip_audit_token_is_safe(event->target_host,
                                       sizeof(event->target_host),
                                       true) &&
           llps_ip_audit_token_is_safe(event->backend_ip,
                                       sizeof(event->backend_ip),
                                       true) &&
           llps_ip_audit_token_is_safe(event->reason,
                                       sizeof(event->reason),
                                       false);
}

static bool llps_ip_audit_path_has_pxf_extension(const char * const path) {
    static const char suffix[] = ".pxf";
    const size_t suffix_len = sizeof(suffix) - 1u;
    size_t len = 0u;

    if (path == NULL) {
        return false;
    }

    for (len = 0u;
         (len < LLPS_YML_MAX_PATH_TEXT) && (path[len] != '\0');
         ++len) {
    }

    if ((len == LLPS_YML_MAX_PATH_TEXT) || (len <= suffix_len)) {
        return false;
    }

    return memcmp(&path[len - suffix_len], suffix, suffix_len) == 0;
}

static bool llps_ip_audit_write_all_direct(const int fd,
                                           const char * const text,
                                           const size_t len) {
    size_t off = 0u;

    if (!llps_fd_is_valid(fd) || (text == NULL) || (len == 0u)) {
        return false;
    }

    for (size_t attempt = 0u;
         (off < len) && (attempt < LLPS_IP_AUDIT_IO_ATTEMPT_MAX);
         ++attempt) {
        const ssize_t n = write(fd, &text[off], len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        if (n == 0) {
            return false;
        }

        off += (size_t)n;
    }

    return off == len;
}

static bool llps_ip_audit_read_exact_prefix(const int fd,
                                            char * const out,
                                            const size_t len) {
    size_t off = 0u;

    if (!llps_fd_is_valid(fd) || (out == NULL) || (len == 0u)) {
        return false;
    }

    if (lseek(fd, (off_t)0, SEEK_SET) < (off_t)0) {
        return false;
    }

    for (size_t attempt = 0u;
         (off < len) && (attempt < LLPS_IP_AUDIT_IO_ATTEMPT_MAX);
         ++attempt) {
        const ssize_t n = read(fd, &out[off], len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        if (n == 0) {
            return false;
        }

        off += (size_t)n;
    }

    return off == len;
}

static bool llps_ip_audit_header_matches(const int fd,
                                         const char * const expected,
                                         const size_t expected_len) {
    char actual_header[sizeof(llps_ip_audit_pxf_header)];

    if ((expected == NULL) ||
        (expected_len == 0u) ||
        (expected_len >= sizeof(actual_header))) {
        return false;
    }

    if (!llps_ip_audit_read_exact_prefix(fd, actual_header, expected_len)) {
        return false;
    }

    return memcmp(actual_header, expected, expected_len) == 0;
}

static bool llps_ip_audit_write_new_pxf_header(const int fd) {
    if (!llps_ip_audit_write_all_direct(fd,
                                        llps_ip_audit_pxf_header,
                                        sizeof(llps_ip_audit_pxf_header) - 1u)) {
        return false;
    }

    return fsync(fd) == 0;
}

static bool llps_ip_audit_existing_pxf_header_matches(
    const int fd,
    const off_t size,
    const bool require_mac_table) {
    const size_t header_len = sizeof(llps_ip_audit_pxf_header) - 1u;
    const size_t no_evidence_mac_header_len =
        sizeof(llps_ip_audit_pxf_header_without_evidence_mac) - 1u;
    const size_t no_evidence_header_len =
        sizeof(llps_ip_audit_pxf_header_without_evidence) - 1u;
    const size_t legacy_header_len =
        sizeof(llps_ip_audit_pxf_header_legacy) - 1u;

    if ((size >= (off_t)header_len) &&
        llps_ip_audit_header_matches(fd,
                                     llps_ip_audit_pxf_header,
                                     header_len)) {
        return true;
    }
    if ((size >= (off_t)no_evidence_mac_header_len) &&
        llps_ip_audit_header_matches(
            fd,
            llps_ip_audit_pxf_header_without_evidence_mac,
            no_evidence_mac_header_len)) {
        return true;
    }
    if ((size >= (off_t)no_evidence_header_len) &&
        llps_ip_audit_header_matches(
            fd,
            llps_ip_audit_pxf_header_without_evidence,
            no_evidence_header_len)) {
        return true;
    }
    return !require_mac_table &&
           (size >= (off_t)legacy_header_len) &&
           llps_ip_audit_header_matches(fd,
                                        llps_ip_audit_pxf_header_legacy,
                                        legacy_header_len);
}

static bool llps_ip_audit_prepare_pxf_document(const int fd,
                                               const bool require_mac_table) {
    struct stat st;

    if (!llps_fd_is_valid(fd)) {
        return false;
    }

    if (fstat(fd, &st) != 0) {
        return false;
    }

    if (st.st_size == (off_t)0) {
        return llps_ip_audit_write_new_pxf_header(fd);
    }

    return llps_ip_audit_existing_pxf_header_matches(fd,
                                                     st.st_size,
                                                     require_mac_table);
}

static const char *llps_ip_audit_event_text(
    const llps_ip_audit_event_type_t type) {
    switch (type) {
    case LLPS_IP_AUDIT_ACCEPT:
        return "accept";
    case LLPS_IP_AUDIT_DROP:
        return "drop";
    case LLPS_IP_AUDIT_BACKEND_CONNECT:
        return "backend_connect";
    case LLPS_IP_AUDIT_BACKEND_FAIL:
        return "backend_fail";
    case LLPS_IP_AUDIT_CLOSE:
        return "close";
    default:
        break;
    }

    return "unknown";
}

static void llps_ip_audit_log_detail(
    const uint64_t seq,
    const uint64_t event_no,
    const uint64_t total_events,
    const uint32_t crc,
    const uint32_t mac_key_fingerprint,
    const llps_ip_audit_event_t * const event) {
    if ((event == NULL) ||
        !llps_log_enabled() ||
        !llps_audit_log_enabled()) {
        return;
    }

    llps_log_begin();
    (void)fprintf(stdout,
                  "audit_event\n"
                  "  seq=%llu\n"
                  "  request_no=%llu\n"
                  "  event=%s\n"
                  "  event_no=%llu\n"
                  "  total_events=%llu\n"
                  "  session=%u\n"
                  "  reason=%s\n"
                  "  duration_ns=%llu\n"
                  "  crc32=0x%08x\n"
                  "  mac=%s\n"
                  "  mac_key_fingerprint=0x%08x\n"
                  "  endpoints:\n"
                  "    client=%s:%u\n"
                  "    listen=%s:%u\n"
                  "    target=%s:%u\n"
                  "    backend=%s:%u",
                  (unsigned long long)seq,
                  (unsigned long long)event->request_no,
                  llps_ip_audit_event_text(event->type),
                  (unsigned long long)event_no,
                  (unsigned long long)total_events,
                  (unsigned)event->session_id,
                  event->reason,
                  (unsigned long long)event->duration_ns,
                  (unsigned)crc,
                  g_ip_audit_mac_enabled ? "enabled" : "disabled",
                  (unsigned)mac_key_fingerprint,
                  event->client_ip,
                  (unsigned)event->client_port,
                  event->listen_host,
                  (unsigned)event->listen_port,
                  event->target_host,
                  (unsigned)event->target_port,
                  event->backend_ip,
                  (unsigned)event->backend_port);
    llps_log_end();
}

static bool llps_ip_audit_event_type_from_text(
    const char * const text,
    llps_ip_audit_event_type_t * const out_type) {
    if ((text == NULL) || (out_type == NULL)) {
        return false;
    }

    for (uint32_t i = 0u;
         i < (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
         ++i) {
        const llps_ip_audit_event_type_t type =
            (llps_ip_audit_event_type_t)i;
        if (strcmp(text, llps_ip_audit_event_text(type)) == 0) {
            *out_type = type;
            return true;
        }
    }

    return false;
}

static void llps_ip_audit_reset_event_counts(void) {
    for (uint32_t i = 0u;
         i < (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
         ++i) {
        g_ip_audit_event_counts[i] = 0u;
        g_ip_audit_event_counts_inverse[i] = UINT64_MAX;
    }
}

static bool llps_ip_audit_next_token(const char ** const cursor,
                                     char * const out,
                                     const size_t out_cap) {
    const char *p = NULL;
    size_t len = 0u;

    if ((cursor == NULL) || (*cursor == NULL) ||
        (out == NULL) || (out_cap == 0u)) {
        return false;
    }

    p = *cursor;
    for (size_t skip = 0u;
         (skip < LLPS_IP_AUDIT_LINE_BYTES) &&
         ((*p == ' ') || (*p == '\t'));
         ++skip) {
        ++p;
    }

    for (size_t scan = 0u;
         (scan < LLPS_IP_AUDIT_LINE_BYTES) &&
         ((*p != '\0') && (*p != ' ') && (*p != '\t') &&
          (*p != '\r') && (*p != '\n'));
         ++scan) {
        if ((len + 1u) >= out_cap) {
            return false;
        }
        out[len] = *p;
        ++len;
        ++p;
    }

    if (len == 0u) {
        return false;
    }

    out[len] = '\0';
    *cursor = p;
    return true;
}

static bool llps_ip_audit_parse_u64_token(const char * const text,
                                          uint64_t * const out_value) {
    uint64_t value = 0u;

    if ((text == NULL) || (out_value == NULL) || (text[0] == '\0')) {
        return false;
    }

    for (size_t i = 0u; text[i] != '\0'; ++i) {
        const char ch = text[i];
        const uint64_t digit = (uint64_t)(ch - '0');

        if ((ch < '0') || (ch > '9')) {
            return false;
        }
        if (value > ((UINT64_MAX - digit) / 10u)) {
            return false;
        }
        value = (value * 10u) + digit;
    }

    *out_value = value;
    return true;
}

static bool llps_ip_audit_parse_u16_token(const char * const text,
                                          uint16_t * const out_value) {
    uint64_t value = 0u;

    if ((out_value == NULL) ||
        !llps_ip_audit_parse_u64_token(text, &value) ||
        (value > UINT16_MAX)) {
        return false;
    }

    *out_value = (uint16_t)value;
    return true;
}

static bool llps_ip_audit_hex_nibble(const char ch, uint8_t * const out) {
    if (out == NULL) {
        return false;
    }

    if ((ch >= '0') && (ch <= '9')) {
        *out = (uint8_t)(ch - '0');
        return true;
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        *out = (uint8_t)((ch - 'a') + 10);
        return true;
    }
    if ((ch >= 'A') && (ch <= 'F')) {
        *out = (uint8_t)((ch - 'A') + 10);
        return true;
    }

    return false;
}

static bool llps_ip_audit_parse_hex32_token(const char * const text,
                                            uint32_t * const out_value) {
    uint32_t value = 0u;

    if ((text == NULL) || (out_value == NULL) ||
        (text[0] != '0') || ((text[1] != 'x') && (text[1] != 'X'))) {
        return false;
    }

    for (uint32_t i = 0u; i < 8u; ++i) {
        uint8_t nibble = 0u;

        if (!llps_ip_audit_hex_nibble(text[2u + i], &nibble)) {
            return false;
        }
        value = (value << 4u) | (uint32_t)nibble;
    }

    if (text[10u] != '\0') {
        return false;
    }

    *out_value = value;
    return true;
}

static bool llps_ip_audit_parse_hex256_token(
    const char * const text,
    char out_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u]) {
    if ((text == NULL) || (out_hex == NULL)) {
        return false;
    }

    for (uint32_t i = 0u;
         i < (LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u);
         ++i) {
        uint8_t nibble = 0u;

        if (!llps_ip_audit_hex_nibble(text[i], &nibble)) {
            return false;
        }
        if ((text[i] >= 'A') && (text[i] <= 'F')) {
            out_hex[i] = (char)(text[i] + ('a' - 'A'));
        } else {
            out_hex[i] = text[i];
        }
    }

    if (text[LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u] != '\0') {
        return false;
    }

    out_hex[LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u] = '\0';
    return true;
}

static bool llps_ip_audit_no_extra_tokens(const char *cursor) {
    if (cursor == NULL) {
        return false;
    }

    for (size_t skip = 0u;
         (skip < LLPS_IP_AUDIT_LINE_BYTES) &&
         ((*cursor == ' ') || (*cursor == '\t') ||
          (*cursor == '\r') || (*cursor == '\n'));
         ++skip) {
        ++cursor;
    }

    return *cursor == '\0';
}

static bool llps_ip_audit_role_from_text(
    const char * const text,
    llps_ip_audit_role_t * const out_role) {
    if ((text == NULL) || (out_role == NULL)) {
        return false;
    }

    if (strcmp(text, "client") == 0) {
        *out_role = LLPS_IP_AUDIT_ROLE_CLIENT;
        return true;
    }
    if (strcmp(text, "listen") == 0) {
        *out_role = LLPS_IP_AUDIT_ROLE_LISTEN;
        return true;
    }
    if (strcmp(text, "target") == 0) {
        *out_role = LLPS_IP_AUDIT_ROLE_TARGET;
        return true;
    }
    if (strcmp(text, "backend") == 0) {
        *out_role = LLPS_IP_AUDIT_ROLE_BACKEND;
        return true;
    }

    return false;
}

static size_t llps_ip_audit_endpoint_host_cap(
    const llps_ip_audit_role_t role) {
    if ((role == LLPS_IP_AUDIT_ROLE_CLIENT) ||
        (role == LLPS_IP_AUDIT_ROLE_BACKEND)) {
        return LLPS_CLIENT_IP_TEXT_LEN;
    }

    return LLPS_YML_MAX_IP_TEXT;
}

static bool llps_ip_audit_hex_strings_equal(const char * const lhs,
                                            const char * const rhs,
                                            const size_t len) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < len; ++i) {
        char lc = lhs[i];
        char rc = rhs[i];

        if ((lc >= 'A') && (lc <= 'F')) {
            lc = (char)(lc + ('a' - 'A'));
        }
        if ((rc >= 'A') && (rc <= 'F')) {
            rc = (char)(rc + ('a' - 'A'));
        }
        if (lc != rc) {
            return false;
        }
    }

    return true;
}

static bool llps_ip_audit_scan_event_from_state(
    const llps_ip_audit_scan_state_t * const state,
    llps_ip_audit_event_t * const out_event) {
    if ((state == NULL) || (out_event == NULL) || !state->active) {
        return false;
    }

    (void)memset(out_event, 0, sizeof(*out_event));
    out_event->type = state->type;
    out_event->request_no = state->request_no;
    out_event->time_ns = state->time_ns;
    out_event->duration_ns = state->duration_ns;
    out_event->session_id = state->session_id;
    out_event->client_port =
        state->endpoint_port[LLPS_IP_AUDIT_ROLE_CLIENT];
    out_event->listen_port =
        state->endpoint_port[LLPS_IP_AUDIT_ROLE_LISTEN];
    out_event->target_port =
        state->endpoint_port[LLPS_IP_AUDIT_ROLE_TARGET];
    out_event->backend_port =
        state->endpoint_port[LLPS_IP_AUDIT_ROLE_BACKEND];

    return llps_ip_audit_copy_text(
               out_event->client_ip,
               sizeof(out_event->client_ip),
               state->endpoint_host[LLPS_IP_AUDIT_ROLE_CLIENT]) &&
           llps_ip_audit_copy_text(
               out_event->listen_host,
               sizeof(out_event->listen_host),
               state->endpoint_host[LLPS_IP_AUDIT_ROLE_LISTEN]) &&
           llps_ip_audit_copy_text(
               out_event->target_host,
               sizeof(out_event->target_host),
               state->endpoint_host[LLPS_IP_AUDIT_ROLE_TARGET]) &&
           llps_ip_audit_copy_text(
               out_event->backend_ip,
               sizeof(out_event->backend_ip),
               state->endpoint_host[LLPS_IP_AUDIT_ROLE_BACKEND]) &&
           llps_ip_audit_copy_text(out_event->reason,
                                   sizeof(out_event->reason),
	                                   state->reason);
}

static bool llps_ip_audit_scan_record_mac_is_valid(
    const llps_ip_audit_scan_state_t * const state,
    const llps_ip_audit_event_t * const event,
    const char * const mac_key_path,
    const uint32_t expected_mac_key_fingerprint) {
    uint32_t mac_key_fingerprint = 0u;
    size_t mac_message_len = 0u;
    uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    char mac_message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES];
    char expected_mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];

    if ((state == NULL) || (event == NULL)) {
        return false;
    }
    if (!state->require_mac) {
        return true;
    }
    if (!state->mac_seen ||
        (mac_key_path == NULL) ||
        (expected_mac_key_fingerprint == 0u) ||
        (state->mac_key_fingerprint != expected_mac_key_fingerprint)) {
        return false;
    }
    if (!llps_ip_audit_build_mac_message(state->seq,
                                         state->event_no,
                                         state->total_events,
                                         state->crc32,
                                         event,
                                         mac_message,
                                         &mac_message_len)) {
        return false;
    }
    if (!llps_hmac_sha256_file_message(mac_key_path,
                                       (const uint8_t *)mac_message,
                                       mac_message_len,
                                       mac,
                                       &mac_key_fingerprint)) {
        return false;
    }
    if ((mac_key_fingerprint != expected_mac_key_fingerprint) ||
        !llps_ip_audit_hex_encode(mac, expected_mac_hex)) {
        return false;
    }
    return llps_ip_audit_hex_strings_equal(
        state->mac_hex,
        expected_mac_hex,
        LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u);
}

static bool llps_ip_audit_scan_finalize_record(
    llps_ip_audit_scan_state_t * const state,
    uint64_t * const max_seq,
    uint64_t event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT],
    const char * const mac_key_path,
    const uint32_t expected_mac_key_fingerprint) {
    static const uint32_t required_endpoint_mask =
        (1u << (uint32_t)LLPS_IP_AUDIT_ROLE_CLIENT) |
        (1u << (uint32_t)LLPS_IP_AUDIT_ROLE_LISTEN) |
        (1u << (uint32_t)LLPS_IP_AUDIT_ROLE_TARGET) |
        (1u << (uint32_t)LLPS_IP_AUDIT_ROLE_BACKEND);
    llps_ip_audit_event_t event;
    uint32_t computed_crc = 0u;
    const uint32_t type_index =
        (state != NULL) ? (uint32_t)state->type :
                          (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;

    if ((state == NULL) || (max_seq == NULL) || (event_counts == NULL)) {
        return false;
    }

    if (!state->active) {
        return true;
    }

    if ((type_index >= (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT) ||
        (state->endpoint_mask != required_endpoint_mask) ||
        !llps_ip_audit_scan_event_from_state(state, &event)) {
        return false;
    }

    computed_crc = llps_ip_audit_event_crc(state->seq,
                                           state->event_no,
                                           state->total_events,
                                           &event);
    if (computed_crc != state->crc32) {
        return false;
    }

    if (!llps_ip_audit_scan_record_mac_is_valid(state,
                                                &event,
                                                mac_key_path,
                                                expected_mac_key_fingerprint)) {
        return false;
    }

    *max_seq = state->seq;
    event_counts[type_index] = state->event_no;
    state->active = false;
    return true;
}

static void llps_ip_audit_scan_next_state_init(
    const llps_ip_audit_scan_state_t * const current,
    llps_ip_audit_scan_state_t * const next_state) {
    const bool require_mac = (current != NULL) && current->require_mac;

    if (next_state != NULL) {
        (void)memset(next_state, 0, sizeof(*next_state));
        next_state->require_mac = require_mac;
        next_state->type = LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
    }
}

static bool llps_ip_audit_scan_parse_audit_row_fields(
    const char * const line,
    llps_ip_audit_scan_state_t * const next_state,
    uint64_t * const parsed_session) {
    const char *cursor = NULL;
    char token[64u];
    char event_text[32u];

    if ((line == NULL) || (next_state == NULL) ||
        (parsed_session == NULL)) {
        return false;
    }

    cursor = &line[7u];
    if (!llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->seq) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->request_no) ||
        !llps_ip_audit_next_token(&cursor, event_text, sizeof(event_text)) ||
        !llps_ip_audit_event_type_from_text(event_text, &next_state->type) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->event_no) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->total_events) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->time_ns) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, parsed_session)) {
        return false;
    }

    if ((*parsed_session > UINT32_MAX) ||
        !llps_ip_audit_next_token(&cursor,
                                  next_state->reason,
                                  sizeof(next_state->reason)) ||
        !llps_ip_audit_token_is_safe(next_state->reason,
                                     sizeof(next_state->reason),
                                     false) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &next_state->duration_ns) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_hex32_token(token, &next_state->crc32) ||
        !llps_ip_audit_no_extra_tokens(cursor)) {
        return false;
    }
    return true;
}

static bool llps_ip_audit_scan_audit_sequence_is_valid(
    const llps_ip_audit_scan_state_t * const next_state,
    const uint64_t max_seq,
    const uint64_t event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    const uint32_t type_index = (next_state != NULL) ?
        (uint32_t)next_state->type :
        (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;

    if ((next_state == NULL) || (event_counts == NULL) ||
        (type_index >= (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT)) {
        return false;
    }
    return (max_seq != UINT64_MAX) &&
           (next_state->seq == (max_seq + 1u)) &&
           (next_state->total_events == next_state->seq) &&
           (event_counts[type_index] != UINT64_MAX) &&
           (next_state->event_no == (event_counts[type_index] + 1u));
}

static bool llps_ip_audit_scan_audit_row(
    const char * const line,
    llps_ip_audit_scan_state_t * const state,
    uint64_t * const max_seq,
    uint64_t event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT],
    const char * const mac_key_path,
    const uint32_t expected_mac_key_fingerprint) {
    uint64_t parsed_session = 0u;
    llps_ip_audit_scan_state_t next_state;

    if ((line == NULL) || (state == NULL) ||
        (max_seq == NULL) || (event_counts == NULL)) {
        return false;
    }

    if (strncmp(line, "+audit ", 7u) != 0) {
        return false;
    }

    if (!llps_ip_audit_scan_finalize_record(state,
                                            max_seq,
                                            event_counts,
                                            mac_key_path,
                                            expected_mac_key_fingerprint)) {
        return false;
    }

    llps_ip_audit_scan_next_state_init(state, &next_state);
    if (!llps_ip_audit_scan_parse_audit_row_fields(line,
                                                   &next_state,
                                                   &parsed_session)) {
        return false;
    }

    if (!llps_ip_audit_scan_audit_sequence_is_valid(&next_state,
                                                    *max_seq,
                                                    event_counts)) {
        return false;
    }

    next_state.session_id = (uint32_t)parsed_session;
    next_state.active = true;
    *state = next_state;
    return true;
}

static bool llps_ip_audit_scan_endpoint_row(
    const char * const line,
    llps_ip_audit_scan_state_t * const state) {
    const char *cursor = NULL;
    char token[64u];
    char role_text[16u];
    llps_ip_audit_role_t role = LLPS_IP_AUDIT_ROLE_COUNT;
    uint64_t seq = 0u;
    uint16_t port = 0u;
    size_t host_cap = 0u;

    if ((line == NULL) || (state == NULL) || !state->active) {
        return false;
    }

    cursor = &line[16u];
    if (!llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &seq) ||
        !llps_ip_audit_next_token(&cursor, role_text, sizeof(role_text)) ||
        !llps_ip_audit_role_from_text(role_text, &role) ||
        ((uint32_t)role >= (uint32_t)LLPS_IP_AUDIT_ROLE_COUNT)) {
        return false;
    }

    host_cap = llps_ip_audit_endpoint_host_cap(role);
    if ((seq != state->seq) ||
        !llps_ip_audit_next_token(&cursor,
                                  state->endpoint_host[(uint32_t)role],
                                  host_cap) ||
        !llps_ip_audit_token_is_safe(
            state->endpoint_host[(uint32_t)role],
            host_cap,
            true) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u16_token(token, &port) ||
        !llps_ip_audit_no_extra_tokens(cursor)) {
        return false;
    }

    if ((state->endpoint_mask & (1u << (uint32_t)role)) != 0u) {
        return false;
    }

    state->endpoint_port[(uint32_t)role] = port;
    state->endpoint_mask |= (1u << (uint32_t)role);
    return true;
}

static bool llps_ip_audit_scan_mac_row(
    const char * const line,
    llps_ip_audit_scan_state_t * const state) {
    const char *cursor = NULL;
    char token[64u];
    uint64_t seq = 0u;

    if ((line == NULL) || (state == NULL) ||
        !state->active || !state->require_mac) {
        return false;
    }

    cursor = &line[11u];
    if (!llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &seq) ||
        (seq != state->seq) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_hex32_token(token,
                                         &state->mac_key_fingerprint) ||
        !llps_ip_audit_next_token(&cursor,
                                  state->mac_hex,
                                  sizeof(state->mac_hex)) ||
        !llps_ip_audit_parse_hex256_token(state->mac_hex,
                                          state->mac_hex) ||
        !llps_ip_audit_no_extra_tokens(cursor) ||
        state->mac_seen) {
        return false;
    }

    state->mac_seen = true;
    return true;
}

static bool llps_ip_audit_scan_next_u64_token(const char ** const cursor,
                                              uint64_t * const out_value) {
    char token[64u];

    return (cursor != NULL) &&
           (out_value != NULL) &&
           llps_ip_audit_next_token(cursor, token, sizeof(token)) &&
           llps_ip_audit_parse_u64_token(token, out_value);
}

static bool llps_ip_audit_scan_next_hex32_token(const char ** const cursor,
                                                uint32_t * const out_value) {
    char token[64u];

    return (cursor != NULL) &&
           (out_value != NULL) &&
           llps_ip_audit_next_token(cursor, token, sizeof(token)) &&
           llps_ip_audit_parse_hex32_token(token, out_value);
}

static bool llps_ip_audit_scan_evidence_patrol_tokens(
    const char ** const cursor,
    llps_ip_audit_evidence_event_t * const event) {
    return llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->monitor_passes) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->software_evidence_patrol_passes) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_ecc_topology_patrol_passes) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_ecc_topology_patrol_failures) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_fault_patrol_passes) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_fault_patrol_failures) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_numa_patrol_passes) &&
           llps_ip_audit_scan_next_u64_token(
               cursor,
               &event->synthetic_numa_patrol_failures);
}

static bool llps_ip_audit_scan_evidence_config_tokens(
    const char ** const cursor,
    llps_ip_audit_evidence_event_t * const event,
    uint32_t * const crc) {
    return llps_ip_audit_scan_next_hex32_token(
               cursor,
               &event->require_readiness) &&
           llps_ip_audit_scan_next_hex32_token(
               cursor,
               &event->platform_evidence_mode) &&
           llps_ip_audit_scan_next_hex32_token(
               cursor,
               &event->software_ecc_enabled) &&
           llps_ip_audit_scan_next_hex32_token(
               cursor,
               &event->software_numa_enabled) &&
           llps_ip_audit_scan_next_hex32_token(
               cursor,
               &event->software_fault_injection_mode) &&
           llps_ip_audit_scan_next_hex32_token(cursor, crc);
}

static bool llps_ip_audit_scan_evidence_row(
    const char * const line,
    llps_ip_audit_evidence_scan_state_t * const state,
    uint64_t * const out_evidence_seq) {
    const char *cursor = NULL;
    llps_ip_audit_evidence_event_t event;
    uint64_t seq = 0u;
    uint32_t crc = 0u;

    if ((line == NULL) || (state == NULL) || (out_evidence_seq == NULL)) {
        return false;
    }

    (void)memset(&event, 0, sizeof(event));
    cursor = &line[10u];
    if (!llps_ip_audit_scan_next_u64_token(&cursor, &seq) ||
        (seq != (*out_evidence_seq + 1u)) ||
        !llps_ip_audit_next_token(&cursor,
                                  event.event,
                                  sizeof(event.event)) ||
        !llps_ip_audit_token_is_safe(event.event,
                                     sizeof(event.event),
                                     false) ||
        !llps_ip_audit_scan_next_u64_token(&cursor, &event.time_ns) ||
        !llps_ip_audit_scan_next_hex32_token(&cursor, &event.status) ||
        !llps_ip_audit_scan_next_hex32_token(&cursor, &event.failure_mask) ||
        !llps_ip_audit_scan_evidence_patrol_tokens(&cursor, &event) ||
        !llps_ip_audit_scan_evidence_config_tokens(&cursor, &event, &crc) ||
        !llps_ip_audit_no_extra_tokens(cursor)) {
        return false;
    }

    if (crc != llps_ip_audit_evidence_crc(seq, &event)) {
        return false;
    }

    state->active = true;
    state->seq = seq;
    state->crc32 = crc;
    state->event = event;
    state->mac_seen = false;
    *out_evidence_seq = seq;
    return true;
}

static bool llps_ip_audit_scan_evidence_mac_row(
    const char * const line,
    llps_ip_audit_evidence_scan_state_t * const state,
    const char * const mac_key_path,
    const uint32_t expected_mac_key_fingerprint) {
    const char *cursor = NULL;
    char token[64u];
    char mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];
    char expected_mac_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u];
    char mac_message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES];
    uint8_t expected_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint64_t seq = 0u;
    uint32_t mac_key_fingerprint = 0u;
    uint32_t computed_key_fingerprint = 0u;
    size_t mac_message_len = 0u;

    if ((line == NULL) || (state == NULL) || !state->active ||
        !state->require_mac || (mac_key_path == NULL)) {
        return false;
    }

    cursor = &line[14u];
    if (!llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_u64_token(token, &seq) ||
        (seq != state->seq) ||
        !llps_ip_audit_next_token(&cursor, token, sizeof(token)) ||
        !llps_ip_audit_parse_hex32_token(token, &mac_key_fingerprint) ||
        (mac_key_fingerprint != expected_mac_key_fingerprint) ||
        !llps_ip_audit_next_token(&cursor, mac_hex, sizeof(mac_hex)) ||
        !llps_ip_audit_parse_hex256_token(mac_hex, mac_hex) ||
        !llps_ip_audit_no_extra_tokens(cursor) ||
        state->mac_seen ||
        !llps_ip_audit_build_evidence_mac_message(state->seq,
                                                  state->crc32,
                                                  &state->event,
                                                  mac_message,
                                                  &mac_message_len) ||
        !llps_hmac_sha256_file_message(mac_key_path,
                                       (const uint8_t *)mac_message,
                                       mac_message_len,
                                       expected_mac,
                                       &computed_key_fingerprint) ||
        (computed_key_fingerprint != expected_mac_key_fingerprint) ||
        !llps_ip_audit_hex_encode(expected_mac, expected_mac_hex) ||
        !llps_ip_audit_hex_strings_equal(
            mac_hex,
            expected_mac_hex,
            LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u)) {
        return false;
    }

    state->mac_seen = true;
    return true;
}

static bool llps_ip_audit_scan_finalize_evidence_record(
    llps_ip_audit_evidence_scan_state_t * const state) {
    if (state == NULL) {
        return false;
    }

    if (!state->active) {
        return true;
    }

    if (state->require_mac && !state->mac_seen) {
        return false;
    }

    state->active = false;
    state->seq = 0u;
    state->crc32 = 0u;
    state->mac_seen = false;
    (void)memset(&state->event, 0, sizeof(state->event));
    return true;
}

static bool llps_ip_audit_scan_line_is_ignorable(
    const char * const line) {
    return (line != NULL) &&
           ((line[0] == '\0') ||
            (line[0] == '#') ||
            (line[0] == '@') ||
            (strcmp(line, "pxf/1") == 0));
}

static bool llps_ip_audit_scan_process_evidence_line(
    const char * const line,
    llps_ip_audit_scan_context_t * const ctx) {
    if ((line == NULL) || (ctx == NULL)) {
        return false;
    }
    if (!llps_ip_audit_scan_finalize_evidence_record(ctx->evidence_state)) {
        return false;
    }
    return llps_ip_audit_scan_evidence_row(line,
                                           ctx->evidence_state,
                                           ctx->out_evidence_seq);
}

static bool llps_ip_audit_scan_process_line(
    const char * const line,
    llps_ip_audit_scan_context_t * const ctx) {
    if ((line == NULL) || (ctx == NULL)) {
        return false;
    }
    if (strncmp(line, "+audit ", 7u) == 0) {
        return llps_ip_audit_scan_audit_row(
            line,
            ctx->audit_state,
            ctx->out_seq,
            ctx->event_counts,
            ctx->mac_key_path,
            ctx->expected_mac_key_fingerprint);
    }
    if (strncmp(line, "+audit_endpoint ", 16u) == 0) {
        return llps_ip_audit_scan_endpoint_row(line, ctx->audit_state);
    }
    if (strncmp(line, "+audit_mac ", 11u) == 0) {
        return llps_ip_audit_scan_mac_row(line, ctx->audit_state);
    }
    if (strncmp(line, "+evidence ", 10u) == 0) {
        return llps_ip_audit_scan_process_evidence_line(line, ctx);
    }
    if (strncmp(line, "+evidence_mac ", 14u) == 0) {
        return llps_ip_audit_scan_evidence_mac_row(
            line,
            ctx->evidence_state,
            ctx->mac_key_path,
            ctx->expected_mac_key_fingerprint);
    }
    return llps_ip_audit_scan_line_is_ignorable(line);
}

static bool llps_ip_audit_scan_finalize_blank_line(
    llps_ip_audit_scan_context_t * const ctx) {
    if (ctx == NULL) {
        return false;
    }
    return llps_ip_audit_scan_finalize_record(
               ctx->audit_state,
               ctx->out_seq,
               ctx->event_counts,
               ctx->mac_key_path,
               ctx->expected_mac_key_fingerprint) &&
           llps_ip_audit_scan_finalize_evidence_record(ctx->evidence_state);
}

static bool llps_ip_audit_scan_process_completed_line(
    const char * const line,
    llps_ip_audit_scan_context_t * const ctx) {
    if (!llps_ip_audit_scan_process_line(line, ctx)) {
        return false;
    }
    if ((line != NULL) && (line[0] == '\0')) {
        return llps_ip_audit_scan_finalize_blank_line(ctx);
    }
    return true;
}

static void llps_ip_audit_scan_states_init(
    const bool require_mac,
    llps_ip_audit_scan_state_t * const state,
    llps_ip_audit_evidence_scan_state_t * const evidence_state) {
    if ((state != NULL) && (evidence_state != NULL)) {
        (void)memset(state, 0, sizeof(*state));
        state->require_mac = require_mac;
        state->type = LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
        (void)memset(evidence_state, 0, sizeof(*evidence_state));
        evidence_state->require_mac = require_mac;
    }
}

static void llps_ip_audit_scan_context_init(
    llps_ip_audit_scan_context_t * const ctx,
    llps_ip_audit_scan_state_t * const state,
    llps_ip_audit_evidence_scan_state_t * const evidence_state) {
    if (ctx != NULL) {
        (void)memset(ctx, 0, sizeof(*ctx));
        ctx->audit_state = state;
        ctx->evidence_state = evidence_state;
    }
}

static void llps_ip_audit_scan_outputs_init(
    uint64_t * const out_seq,
    uint64_t * const out_evidence_seq,
    uint64_t event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    if ((out_seq != NULL) && (out_evidence_seq != NULL) &&
        (event_counts != NULL)) {
        *out_seq = 0u;
        *out_evidence_seq = 0u;
        for (uint32_t i = 0u;
             i < (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
             ++i) {
            event_counts[i] = 0u;
        }
    }
}

static bool llps_ip_audit_scan_read_lines(
    const int fd,
    llps_ip_audit_scan_context_t * const ctx) {
    char line[LLPS_IP_AUDIT_LINE_BYTES];
    size_t line_len = 0u;

    for (uint64_t scan = 0u; scan < UINT64_MAX; ++scan) {
        char ch = '\0';
        const ssize_t n = read(fd, &ch, 1u);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            if (line_len != 0u) {
                line[line_len] = '\0';
                return llps_ip_audit_scan_process_line(line, ctx);
            }
            break;
        }
        if (ch == '\n') {
            line[line_len] = '\0';
            if (!llps_ip_audit_scan_process_completed_line(line, ctx)) {
                return false;
            }
            line_len = 0u;
            continue;
        }
        if ((line_len + 1u) >= sizeof(line)) {
            return false;
        }
        line[line_len] = ch;
        ++line_len;
    }
    return true;
}

static bool llps_ip_audit_scan_finalize_existing(
    const int fd,
    llps_ip_audit_scan_context_t * const ctx) {
    if ((ctx == NULL) ||
        !llps_ip_audit_scan_finalize_record(
            ctx->audit_state,
            ctx->out_seq,
            ctx->event_counts,
            ctx->mac_key_path,
            ctx->expected_mac_key_fingerprint) ||
        !llps_ip_audit_scan_finalize_evidence_record(ctx->evidence_state)) {
        return false;
    }
    return lseek(fd, (off_t)0, SEEK_END) >= (off_t)0;
}

static bool llps_ip_audit_scan_existing_counters(
    const int fd,
    const bool require_mac,
    const char * const mac_key_path,
    const uint32_t expected_mac_key_fingerprint,
    uint64_t * const out_seq,
    uint64_t * const out_evidence_seq,
    uint64_t event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    llps_ip_audit_scan_state_t state;
    llps_ip_audit_evidence_scan_state_t evidence_state;
    llps_ip_audit_scan_context_t ctx;

    if (!llps_fd_is_valid(fd) ||
        (out_seq == NULL) ||
        (out_evidence_seq == NULL) ||
        (event_counts == NULL)) {
        return false;
    }

    llps_ip_audit_scan_outputs_init(out_seq, out_evidence_seq, event_counts);
    llps_ip_audit_scan_states_init(require_mac, &state, &evidence_state);
    llps_ip_audit_scan_context_init(&ctx, &state, &evidence_state);
    ctx.out_seq = out_seq;
    ctx.out_evidence_seq = out_evidence_seq;
    ctx.event_counts = event_counts;
    ctx.mac_key_path = mac_key_path;
    ctx.expected_mac_key_fingerprint = expected_mac_key_fingerprint;

    if (lseek(fd, (off_t)0, SEEK_SET) < (off_t)0) {
        return false;
    }

    if (!llps_ip_audit_scan_read_lines(fd, &ctx)) {
        return false;
    }

    return llps_ip_audit_scan_finalize_existing(fd, &ctx);
}

static bool llps_ip_audit_seq_is_valid(void) {
    return g_ip_audit_seq_inverse == ~g_ip_audit_seq;
}

static bool llps_ip_audit_evidence_seq_is_valid(void) {
    return g_ip_audit_evidence_seq_inverse == ~g_ip_audit_evidence_seq;
}

static bool llps_ip_audit_next_seq(uint64_t * const out_seq) {
    if (out_seq == NULL) {
        return false;
    }

    if (!llps_ip_audit_seq_is_valid()) {
        return false;
    }

    if (g_ip_audit_seq == UINT64_MAX) {
        return false;
    }

    ++g_ip_audit_seq;
    g_ip_audit_seq_inverse = ~g_ip_audit_seq;
    *out_seq = g_ip_audit_seq;
    return true;
}

static bool llps_ip_audit_next_evidence_seq(uint64_t * const out_seq) {
    if (out_seq == NULL) {
        return false;
    }

    if (!llps_ip_audit_evidence_seq_is_valid()) {
        return false;
    }

    if (g_ip_audit_evidence_seq == UINT64_MAX) {
        return false;
    }

    ++g_ip_audit_evidence_seq;
    g_ip_audit_evidence_seq_inverse = ~g_ip_audit_evidence_seq;
    *out_seq = g_ip_audit_evidence_seq;
    return true;
}

static bool llps_ip_audit_next_event_no(
    const llps_ip_audit_event_type_t type,
    uint64_t * const out_event_no) {
    const uint32_t index = (uint32_t)type;

    if ((out_event_no == NULL) ||
        (index >= (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT)) {
        return false;
    }

    if (g_ip_audit_event_counts_inverse[index] !=
        ~g_ip_audit_event_counts[index]) {
        return false;
    }

    if (g_ip_audit_event_counts[index] == UINT64_MAX) {
        return false;
    }

    ++g_ip_audit_event_counts[index];
    g_ip_audit_event_counts_inverse[index] =
        ~g_ip_audit_event_counts[index];
    *out_event_no = g_ip_audit_event_counts[index];
    return true;
}

static uint32_t llps_ip_audit_event_crc(
    const uint64_t seq,
    const uint64_t event_no,
    const uint64_t total_events,
    const llps_ip_audit_event_t * const event) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (event == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u64(crc, seq);
    crc = llps_crc32_update_u64(crc, event->request_no);
    crc = llps_crc32_update_u64(crc, event_no);
    crc = llps_crc32_update_u64(crc, total_events);
    crc = llps_crc32_update_u32(crc, (uint32_t)event->type);
    crc = llps_crc32_update_u64(crc, event->time_ns);
    crc = llps_crc32_update_u64(crc, event->duration_ns);
    crc = llps_crc32_update_u32(crc, event->session_id);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->client_ip,
                                         sizeof(event->client_ip));
    crc = llps_crc32_update_u32(crc, event->client_port);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->listen_host,
                                         sizeof(event->listen_host));
    crc = llps_crc32_update_u32(crc, event->listen_port);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->target_host,
                                         sizeof(event->target_host));
    crc = llps_crc32_update_u32(crc, event->target_port);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->backend_ip,
                                         sizeof(event->backend_ip));
    crc = llps_crc32_update_u32(crc, event->backend_port);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->reason,
                                         sizeof(event->reason));

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static uint32_t llps_ip_audit_evidence_crc(
    const uint64_t seq,
    const llps_ip_audit_evidence_event_t * const event) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (event == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u64(crc, seq);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         event->event,
                                         sizeof(event->event));
    crc = llps_crc32_update_u64(crc, event->time_ns);
    crc = llps_crc32_update_u32(crc, event->status);
    crc = llps_crc32_update_u32(crc, event->failure_mask);
    crc = llps_crc32_update_u64(crc, event->monitor_passes);
    crc = llps_crc32_update_u64(
        crc,
        event->software_evidence_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        event->synthetic_ecc_topology_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        event->synthetic_ecc_topology_patrol_failures);
    crc = llps_crc32_update_u64(crc, event->synthetic_fault_patrol_passes);
    crc = llps_crc32_update_u64(crc, event->synthetic_fault_patrol_failures);
    crc = llps_crc32_update_u64(crc, event->synthetic_numa_patrol_passes);
    crc = llps_crc32_update_u64(crc, event->synthetic_numa_patrol_failures);
    crc = llps_crc32_update_u32(crc, event->require_readiness);
    crc = llps_crc32_update_u32(crc, event->platform_evidence_mode);
    crc = llps_crc32_update_u32(crc, event->software_ecc_enabled);
    crc = llps_crc32_update_u32(crc, event->software_numa_enabled);
    crc = llps_crc32_update_u32(crc, event->software_fault_injection_mode);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static bool llps_ip_audit_mac_state_is_valid(void) {
    if (!g_ip_audit_mac_enabled) {
        return true;
    }

    return (g_ip_audit_mac_key_path[0] != '\0') &&
           (g_ip_audit_mac_key_fingerprint != 0u) &&
           (g_ip_audit_mac_key_fingerprint_inverse ==
            ~g_ip_audit_mac_key_fingerprint);
}

static bool llps_ip_audit_build_mac_message(
    const uint64_t seq,
    const uint64_t event_no,
    const uint64_t total_events,
    const uint32_t crc,
    const llps_ip_audit_event_t * const event,
    char message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES],
    size_t * const out_message_len) {
    int written = 0;

    if ((event == NULL) ||
        (message == NULL) ||
        (out_message_len == NULL)) {
        return false;
    }

    written = snprintf(
        message,
        LLPS_IP_AUDIT_MAC_MESSAGE_BYTES,
        "audit/v1|%llu|%llu|%s|%llu|%llu|%llu|%u|%s|%llu|0x%08x|"
        "%s|%u|%s|%u|%s|%u|%s|%u",
        (unsigned long long)seq,
        (unsigned long long)event->request_no,
        llps_ip_audit_event_text(event->type),
        (unsigned long long)event_no,
        (unsigned long long)total_events,
        (unsigned long long)event->time_ns,
        (unsigned)event->session_id,
        event->reason,
        (unsigned long long)event->duration_ns,
        (unsigned)crc,
        event->client_ip,
        (unsigned)event->client_port,
        event->listen_host,
        (unsigned)event->listen_port,
        event->target_host,
        (unsigned)event->target_port,
        event->backend_ip,
        (unsigned)event->backend_port);

    if ((written <= 0) ||
        ((size_t)written >= LLPS_IP_AUDIT_MAC_MESSAGE_BYTES)) {
        return false;
    }

    *out_message_len = (size_t)written;
    return true;
}

static bool llps_ip_audit_build_evidence_mac_message(
    const uint64_t seq,
    const uint32_t crc,
    const llps_ip_audit_evidence_event_t * const event,
    char message[LLPS_IP_AUDIT_MAC_MESSAGE_BYTES],
    size_t * const out_message_len) {
    int written = 0;

    if ((event == NULL) ||
        (message == NULL) ||
        (out_message_len == NULL)) {
        return false;
    }

    written = snprintf(
        message,
        LLPS_IP_AUDIT_MAC_MESSAGE_BYTES,
        "evidence/v1|%llu|%s|%llu|0x%08x|0x%08x|%llu|%llu|%llu|"
        "%llu|%llu|%llu|%llu|%llu|0x%08x|0x%08x|0x%08x|0x%08x|"
        "0x%08x|0x%08x",
        (unsigned long long)seq,
        event->event,
        (unsigned long long)event->time_ns,
        (unsigned)event->status,
        (unsigned)event->failure_mask,
        (unsigned long long)event->monitor_passes,
        (unsigned long long)event->software_evidence_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_failures,
        (unsigned long long)event->synthetic_fault_patrol_passes,
        (unsigned long long)event->synthetic_fault_patrol_failures,
        (unsigned long long)event->synthetic_numa_patrol_passes,
        (unsigned long long)event->synthetic_numa_patrol_failures,
        (unsigned)event->require_readiness,
        (unsigned)event->platform_evidence_mode,
        (unsigned)event->software_ecc_enabled,
        (unsigned)event->software_numa_enabled,
        (unsigned)event->software_fault_injection_mode,
        (unsigned)crc);

    if ((written <= 0) ||
        ((size_t)written >= LLPS_IP_AUDIT_MAC_MESSAGE_BYTES)) {
        return false;
    }

    *out_message_len = (size_t)written;
    return true;
}

static bool llps_ip_audit_hex_encode(
    const uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    char out_hex[(LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u) + 1u]) {
    static const char hex[] = "0123456789abcdef";

    if ((mac == NULL) || (out_hex == NULL)) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        out_hex[i * 2u] = hex[(mac[i] >> 4u) & 0x0fu];
        out_hex[(i * 2u) + 1u] = hex[mac[i] & 0x0fu];
    }
    out_hex[LLPS_PLATFORM_EVIDENCE_MAC_BYTES * 2u] = '\0';

    return true;
}

static void *llps_ip_audit_write_blocking(void *arg) {
    llps_ip_audit_write_job_t * const job =
        (llps_ip_audit_write_job_t *)arg;
    size_t off = 0u;

    if ((job == NULL) || !llps_fd_is_valid(job->fd) ||
        (job->line == NULL) || (job->len == 0u)) {
        return NULL;
    }

    job->rc = -1;
    for (size_t attempt = 0u;
         (off < job->len) && (attempt < LLPS_IP_AUDIT_IO_ATTEMPT_MAX);
         ++attempt) {
        const ssize_t n = write(job->fd, &job->line[off], job->len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NULL;
        }

        if (n == 0) {
            return NULL;
        }

        off += (size_t)n;
    }

    if (off != job->len) {
        return NULL;
    }

    if (fsync(job->fd) != 0) {
        return NULL;
    }

    job->rc = 0;
    return job;
}

static void llps_ip_audit_close_init_resources(const int fd) {
    if (llps_fd_is_valid(fd)) {
        (void)close(fd);
    }
    (void)llps_ip_audit_writer_mutex_destroy_checked();
}

static bool llps_ip_audit_set_fd_cloexec(const int fd) {
#ifndef O_CLOEXEC
    const int flags = fcntl(fd, F_GETFD, 0);

    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
#else
    (void)fd;
    return true;
#endif
}

static bool llps_ip_audit_open_document_fd(
    const llps_yml_config_t * const cfg,
    int * const out_fd) {
    int fd = LLPS_INVALID_FD;

    if ((cfg == NULL) || (out_fd == NULL) ||
        !llps_ip_audit_path_has_pxf_extension(cfg->ip_audit_path)) {
        return false;
    }
#ifdef O_CLOEXEC
    fd = open(cfg->ip_audit_path,
              O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#else
    fd = open(cfg->ip_audit_path,
              O_RDWR | O_APPEND | O_CREAT,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
    if (!llps_fd_is_valid(fd)) {
        return false;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        (void)close(fd);
        return false;
    }
    if (!llps_ip_audit_prepare_pxf_document(fd,
                                            cfg->audit_mac_enabled != 0u) ||
        !llps_ip_audit_set_fd_cloexec(fd)) {
        (void)close(fd);
        return false;
    }
    *out_fd = fd;
    return true;
}

static bool llps_ip_audit_load_mac_config(
    const llps_yml_config_t * const cfg,
    char mac_key_path[LLPS_YML_MAX_PATH_TEXT],
    uint32_t * const mac_key_fingerprint) {
    if ((cfg == NULL) || (mac_key_path == NULL) ||
        (mac_key_fingerprint == NULL)) {
        return false;
    }
    (void)memset(mac_key_path, 0, LLPS_YML_MAX_PATH_TEXT);
    *mac_key_fingerprint = 0u;
    if (cfg->audit_mac_enabled == 0u) {
        return true;
    }
    return llps_ip_audit_copy_text(mac_key_path,
                                   LLPS_YML_MAX_PATH_TEXT,
                                   cfg->audit_mac_key_path) &&
           llps_hmac_key_fingerprint_file(mac_key_path,
                                          mac_key_fingerprint) &&
           (*mac_key_fingerprint != 0u);
}

static bool llps_ip_audit_scan_initial_counters(
    const int fd,
    const llps_yml_config_t * const cfg,
    const char mac_key_path[LLPS_YML_MAX_PATH_TEXT],
    const uint32_t mac_key_fingerprint,
    uint64_t * const initial_seq,
    uint64_t * const initial_evidence_seq,
    uint64_t initial_event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    const bool mac_enabled = (cfg != NULL) && (cfg->audit_mac_enabled != 0u);

    return (cfg != NULL) &&
           llps_ip_audit_scan_existing_counters(
               fd,
               mac_enabled,
               mac_enabled ? mac_key_path : NULL,
               mac_key_fingerprint,
               initial_seq,
               initial_evidence_seq,
               initial_event_counts);
}

static bool llps_ip_audit_copy_runtime_hosts(
    const llps_yml_config_t * const cfg,
    const char * const resolved_backend_ip) {
    return (cfg != NULL) &&
           llps_ip_audit_copy_text(g_ip_audit_listen_host,
                                   sizeof(g_ip_audit_listen_host),
                                   cfg->listen_host) &&
           llps_ip_audit_copy_text(g_ip_audit_target_host,
                                   sizeof(g_ip_audit_target_host),
                                   cfg->target_ip) &&
           llps_ip_audit_copy_text(g_ip_audit_backend_ip,
                                   sizeof(g_ip_audit_backend_ip),
                                   (resolved_backend_ip != NULL) ?
                                       resolved_backend_ip : "0.0.0.0");
}

static void llps_ip_audit_activate_event_counts(
    const uint64_t initial_event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    for (uint32_t i = 0u;
         i < (uint32_t)LLPS_IP_AUDIT_EVENT_TYPE_COUNT;
         ++i) {
        g_ip_audit_event_counts[i] = initial_event_counts[i];
        g_ip_audit_event_counts_inverse[i] = ~initial_event_counts[i];
    }
}

static void llps_ip_audit_activate_config(
    const int fd,
    const llps_yml_config_t * const cfg,
    const char mac_key_path[LLPS_YML_MAX_PATH_TEXT],
    const uint32_t mac_key_fingerprint,
    const uint64_t initial_seq,
    const uint64_t initial_evidence_seq,
    const uint64_t initial_event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT]) {
    g_ip_audit_fd = fd;
    g_ip_audit_enabled = true;
    g_ip_audit_seq = initial_seq;
    g_ip_audit_seq_inverse = ~g_ip_audit_seq;
    g_ip_audit_evidence_seq = initial_evidence_seq;
    g_ip_audit_evidence_seq_inverse = ~g_ip_audit_evidence_seq;
    llps_ip_audit_activate_event_counts(initial_event_counts);
    g_ip_audit_listen_port = cfg->listen_port;
    g_ip_audit_target_port = cfg->target_port;
    g_ip_audit_backend_port = cfg->target_port;
    g_ip_audit_mac_enabled = cfg->audit_mac_enabled != 0u;
    if (g_ip_audit_mac_enabled) {
        (void)llps_ip_audit_copy_text(g_ip_audit_mac_key_path,
                                      sizeof(g_ip_audit_mac_key_path),
                                      mac_key_path);
    }
    g_ip_audit_mac_key_fingerprint = mac_key_fingerprint;
    g_ip_audit_mac_key_fingerprint_inverse = ~mac_key_fingerprint;
}

bool llps_ip_audit_init(const llps_yml_config_t * const cfg,
                        const char * const resolved_backend_ip) {
    int fd = LLPS_INVALID_FD;
    uint32_t mac_key_fingerprint = 0u;
    char mac_key_path[LLPS_YML_MAX_PATH_TEXT];
    uint64_t initial_seq = 0u;
    uint64_t initial_evidence_seq = 0u;
    uint64_t initial_event_counts[LLPS_IP_AUDIT_EVENT_TYPE_COUNT];

    llps_ip_audit_shutdown();

    if (cfg == NULL) { return false; }
    if (cfg->ip_audit_enabled == 0u) { return true; }
    if (!llps_ip_audit_writer_mutex_create_checked()) { return false; }

    if (!llps_ip_audit_open_document_fd(cfg, &fd)) {
        (void)llps_ip_audit_writer_mutex_destroy_checked();
        return false;
    }

    if (!llps_ip_audit_load_mac_config(cfg,
                                       mac_key_path,
                                       &mac_key_fingerprint)) {
        llps_ip_audit_close_init_resources(fd);
        return false;
    }

    if (!llps_ip_audit_scan_initial_counters(
            fd,
            cfg,
            mac_key_path,
            mac_key_fingerprint,
            &initial_seq,
            &initial_evidence_seq,
            initial_event_counts)) {
        llps_ip_audit_close_init_resources(fd);
        return false;
    }

    if (!llps_ip_audit_copy_runtime_hosts(cfg, resolved_backend_ip)) {
        llps_ip_audit_close_init_resources(fd);
        return false;
    }

    llps_ip_audit_activate_config(fd,
                                  cfg,
                                  mac_key_path,
                                  mac_key_fingerprint,
                                  initial_seq,
                                  initial_evidence_seq,
                                  initial_event_counts);
    return true;
}

void llps_ip_audit_shutdown(void) {
    if (llps_fd_is_valid(g_ip_audit_fd)) {
        (void)close(g_ip_audit_fd);
    }
    (void)llps_ip_audit_writer_mutex_destroy_checked();

    g_ip_audit_fd = LLPS_INVALID_FD;
    g_ip_audit_enabled = false;
    g_ip_audit_seq = 0u;
    g_ip_audit_seq_inverse = ~g_ip_audit_seq;
    g_ip_audit_evidence_seq = 0u;
    g_ip_audit_evidence_seq_inverse = ~g_ip_audit_evidence_seq;
    llps_ip_audit_reset_event_counts();
    (void)memset(g_ip_audit_listen_host, 0, sizeof(g_ip_audit_listen_host));
    (void)memset(g_ip_audit_target_host, 0, sizeof(g_ip_audit_target_host));
    (void)memset(g_ip_audit_backend_ip, 0, sizeof(g_ip_audit_backend_ip));
    (void)memset(g_ip_audit_mac_key_path, 0, sizeof(g_ip_audit_mac_key_path));
    g_ip_audit_listen_port = 0u;
    g_ip_audit_target_port = 0u;
    g_ip_audit_backend_port = 0u;
    g_ip_audit_mac_enabled = false;
    g_ip_audit_mac_key_fingerprint = 0u;
    g_ip_audit_mac_key_fingerprint_inverse = ~g_ip_audit_mac_key_fingerprint;
}

bool llps_ip_audit_enabled(void) {
    return g_ip_audit_enabled;
}

static void llps_ip_audit_record_apply_defaults(
    llps_ip_audit_event_t * const event) {
    if (event == NULL) {
        return;
    }
    if (event->client_ip[0] == '\0') {
        (void)llps_ip_audit_copy_text(event->client_ip,
                                      sizeof(event->client_ip),
                                      "0.0.0.0");
    }
    if (event->listen_host[0] == '\0') {
        (void)llps_ip_audit_copy_text(event->listen_host,
                                      sizeof(event->listen_host),
                                      g_ip_audit_listen_host);
        event->listen_port = g_ip_audit_listen_port;
    }
    if (event->target_host[0] == '\0') {
        (void)llps_ip_audit_copy_text(event->target_host,
                                      sizeof(event->target_host),
                                      g_ip_audit_target_host);
        event->target_port = g_ip_audit_target_port;
    }
    if (event->backend_ip[0] == '\0') {
        (void)llps_ip_audit_copy_text(event->backend_ip,
                                      sizeof(event->backend_ip),
                                      g_ip_audit_backend_ip);
        event->backend_port = g_ip_audit_backend_port;
    }
    if (event->reason[0] == '\0') {
        (void)llps_ip_audit_copy_text(event->reason,
                                      sizeof(event->reason),
                                      "ok");
    }
}

static void llps_ip_audit_record_context_init(
    llps_ip_audit_record_context_t * const ctx,
    const llps_ip_audit_event_t * const event) {
    if ((ctx != NULL) && (event != NULL)) {
        (void)memset(ctx, 0, sizeof(*ctx));
        ctx->normalized = *event;
        ctx->job.rc = -1;
        ctx->ok = true;
        llps_ip_audit_record_apply_defaults(&ctx->normalized);
    }
}

static void llps_ip_audit_record_prepare_sequence(
    llps_ip_audit_record_context_t * const ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->ok = llps_ip_audit_next_seq(&ctx->seq);
    ctx->total_events = ctx->seq;
    if (ctx->ok) {
        ctx->ok = llps_ip_audit_next_event_no(ctx->normalized.type,
                                              &ctx->event_no);
    }
    ctx->crc = llps_ip_audit_event_crc(ctx->seq,
                                       ctx->event_no,
                                       ctx->total_events,
                                       &ctx->normalized);
    ctx->ok = ctx->ok && llps_ip_audit_mac_state_is_valid();
}

static void llps_ip_audit_record_build_mac(
    llps_ip_audit_record_context_t * const ctx) {
    int mac_written = 0;

    if ((ctx == NULL) || !ctx->ok || !g_ip_audit_mac_enabled) {
        return;
    }
    if (!llps_ip_audit_build_mac_message(ctx->seq,
                                         ctx->event_no,
                                         ctx->total_events,
                                         ctx->crc,
                                         &ctx->normalized,
                                         ctx->mac_message,
                                         &ctx->mac_message_len) ||
        !llps_hmac_sha256_file_message(g_ip_audit_mac_key_path,
                                       (const uint8_t *)ctx->mac_message,
                                       ctx->mac_message_len,
                                       ctx->mac,
                                       &ctx->mac_key_fingerprint) ||
        (ctx->mac_key_fingerprint != g_ip_audit_mac_key_fingerprint) ||
        !llps_ip_audit_hex_encode(ctx->mac, ctx->mac_hex)) {
        ctx->ok = false;
    }
    if (ctx->ok) {
        mac_written = snprintf(ctx->mac_comment,
                               sizeof(ctx->mac_comment),
                               "#   mac_key_fingerprint: 0x%08x\n"
                               "#   hmac_sha256: %s\n",
                               (unsigned)ctx->mac_key_fingerprint,
                               ctx->mac_hex);
        ctx->ok = (mac_written > 0) &&
                  ((size_t)mac_written < sizeof(ctx->mac_comment));
    }
    if (ctx->ok) {
        mac_written = snprintf(ctx->mac_row,
                               sizeof(ctx->mac_row),
                               "+audit_mac %llu 0x%08x %s\n",
                               (unsigned long long)ctx->seq,
                               (unsigned)ctx->mac_key_fingerprint,
                               ctx->mac_hex);
        ctx->ok = (mac_written > 0) &&
                  ((size_t)mac_written < sizeof(ctx->mac_row));
    }
}

static void llps_ip_audit_record_format_line(
    llps_ip_audit_record_context_t * const ctx) {
    const llps_ip_audit_event_t *event = NULL;

    if ((ctx == NULL) || !ctx->ok) {
        return;
    }
    event = &ctx->normalized;
    ctx->written = snprintf(
        ctx->line,
        sizeof(ctx->line),
        llps_ip_audit_event_line_format,
        (unsigned long long)ctx->seq,
        (unsigned long long)event->request_no,
        llps_ip_audit_event_text(event->type),
        (unsigned long long)ctx->event_no,
        (unsigned long long)ctx->total_events,
        (unsigned long long)event->time_ns,
        (unsigned)event->session_id,
        event->reason,
        (unsigned long long)event->duration_ns,
        (unsigned)ctx->crc,
        ctx->mac_comment,
        event->client_ip,
        (unsigned)event->client_port,
        event->listen_host,
        (unsigned)event->listen_port,
        event->target_host,
        (unsigned)event->target_port,
        event->backend_ip,
        (unsigned)event->backend_port,
        (unsigned long long)ctx->seq,
        (unsigned long long)event->request_no,
        llps_ip_audit_event_text(event->type),
        (unsigned long long)ctx->event_no,
        (unsigned long long)ctx->total_events,
        (unsigned long long)event->time_ns,
        (unsigned)event->session_id,
        event->reason,
        (unsigned long long)event->duration_ns,
        (unsigned)ctx->crc,
        (unsigned long long)ctx->seq,
        event->client_ip,
        (unsigned)event->client_port,
        (unsigned long long)ctx->seq,
        event->listen_host,
        (unsigned)event->listen_port,
        (unsigned long long)ctx->seq,
        event->target_host,
        (unsigned)event->target_port,
        (unsigned long long)ctx->seq,
        event->backend_ip,
        (unsigned)event->backend_port,
        ctx->mac_row);
    ctx->ok = (ctx->written > 0) &&
              ((size_t)ctx->written < sizeof(ctx->line));
}

static void llps_ip_audit_record_write(
    llps_ip_audit_record_context_t * const ctx) {
    if ((ctx == NULL) || !ctx->ok) {
        return;
    }
    ctx->job.fd = g_ip_audit_fd;
    ctx->job.line = ctx->line;
    ctx->job.len = (size_t)ctx->written;
    ctx->job.rc = -1;
    ctx->ok = llps_ip_audit_call_blocking_checked(
        llps_ip_audit_write_blocking,
        &ctx->job,
        &ctx->write_result,
        "ip_audit_write_blocking");
    if (ctx->ok && (ctx->write_result != &ctx->job)) {
        LLPS_EXPECT(false, ctx->ok = false);
    }
}

static bool llps_ip_audit_record_finish(
    llps_ip_audit_record_context_t * const ctx) {
    if (ctx == NULL) {
        return false;
    }
    if (ctx->ok && (ctx->job.rc == 0)) {
        llps_ip_audit_log_detail(ctx->seq,
                                 ctx->event_no,
                                 ctx->total_events,
                                 ctx->crc,
                                 ctx->mac_key_fingerprint,
                                 &ctx->normalized);
    }
    if (!llps_ip_audit_writer_unlock_checked(ctx->writer_locked)) {
        return false;
    }
    return ctx->ok && (ctx->job.rc == 0);
}

bool llps_ip_audit_record(const llps_ip_audit_event_t * const event) {
    llps_ip_audit_record_context_t ctx;

    if (!g_ip_audit_enabled) {
        return true;
    }

    if ((event == NULL) || !llps_fd_is_valid(g_ip_audit_fd)) {
        return false;
    }

    llps_ip_audit_record_context_init(&ctx, event);
    if (!llps_ip_audit_event_tokens_are_safe(&ctx.normalized)) {
        return false;
    }

    if (!llps_ip_audit_writer_lock_checked(&ctx.writer_locked)) {
        return false;
    }

    llps_ip_audit_record_prepare_sequence(&ctx);
    llps_ip_audit_record_build_mac(&ctx);
    llps_ip_audit_record_format_line(&ctx);
    llps_ip_audit_record_write(&ctx);
    return llps_ip_audit_record_finish(&ctx);
}

static void llps_ip_audit_evidence_record_context_init(
    llps_ip_audit_evidence_record_context_t * const ctx,
    const llps_ip_audit_evidence_event_t * const event) {
    if ((ctx != NULL) && (event != NULL)) {
        (void)memset(ctx, 0, sizeof(*ctx));
        ctx->normalized = *event;
        ctx->job.rc = -1;
        ctx->ok = true;
        if (ctx->normalized.event[0] == '\0') {
            (void)llps_ip_audit_copy_text(ctx->normalized.event,
                                          sizeof(ctx->normalized.event),
                                          "readiness_monitor");
        }
    }
}

static void llps_ip_audit_evidence_prepare_sequence(
    llps_ip_audit_evidence_record_context_t * const ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->ok = llps_ip_audit_next_evidence_seq(&ctx->seq);
    ctx->crc = llps_ip_audit_evidence_crc(ctx->seq, &ctx->normalized);
    ctx->ok = ctx->ok && llps_ip_audit_mac_state_is_valid();
}

static void llps_ip_audit_evidence_build_mac(
    llps_ip_audit_evidence_record_context_t * const ctx) {
    int mac_written = 0;

    if ((ctx == NULL) || !ctx->ok || !g_ip_audit_mac_enabled) {
        return;
    }
    if (!llps_ip_audit_build_evidence_mac_message(ctx->seq,
                                                  ctx->crc,
                                                  &ctx->normalized,
                                                  ctx->mac_message,
                                                  &ctx->mac_message_len) ||
        !llps_hmac_sha256_file_message(g_ip_audit_mac_key_path,
                                       (const uint8_t *)ctx->mac_message,
                                       ctx->mac_message_len,
                                       ctx->mac,
                                       &ctx->mac_key_fingerprint) ||
        (ctx->mac_key_fingerprint != g_ip_audit_mac_key_fingerprint) ||
        !llps_ip_audit_hex_encode(ctx->mac, ctx->mac_hex)) {
        ctx->ok = false;
    }
    if (ctx->ok) {
        mac_written = snprintf(
            ctx->mac_comment,
            sizeof(ctx->mac_comment),
            "#   evidence_mac_key_fingerprint: 0x%08x\n"
            "#   evidence_hmac_sha256: %s\n",
            (unsigned)ctx->mac_key_fingerprint,
            ctx->mac_hex);
        ctx->ok = (mac_written > 0) &&
                  ((size_t)mac_written < sizeof(ctx->mac_comment));
    }
    if (ctx->ok) {
        mac_written = snprintf(ctx->mac_row,
                               sizeof(ctx->mac_row),
                               "+evidence_mac %llu 0x%08x %s\n",
                               (unsigned long long)ctx->seq,
                               (unsigned)ctx->mac_key_fingerprint,
                               ctx->mac_hex);
        ctx->ok = (mac_written > 0) &&
                  ((size_t)mac_written < sizeof(ctx->mac_row));
    }
}

static void llps_ip_audit_evidence_format_line(
    llps_ip_audit_evidence_record_context_t * const ctx) {
    const llps_ip_audit_evidence_event_t *event = NULL;

    if ((ctx == NULL) || !ctx->ok) {
        return;
    }
    event = &ctx->normalized;
    ctx->written = snprintf(
        ctx->line,
        sizeof(ctx->line),
        llps_ip_audit_evidence_line_format,
        (unsigned long long)ctx->seq,
        event->event,
        (unsigned long long)event->time_ns,
        (unsigned)event->status,
        (unsigned)event->failure_mask,
        (unsigned long long)event->monitor_passes,
        (unsigned long long)event->software_evidence_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_failures,
        (unsigned long long)event->synthetic_fault_patrol_passes,
        (unsigned long long)event->synthetic_fault_patrol_failures,
        (unsigned long long)event->synthetic_numa_patrol_passes,
        (unsigned long long)event->synthetic_numa_patrol_failures,
        (unsigned)event->require_readiness,
        (unsigned)event->platform_evidence_mode,
        (unsigned)event->software_ecc_enabled,
        (unsigned)event->software_numa_enabled,
        (unsigned)event->software_fault_injection_mode,
        (unsigned)ctx->crc,
        ctx->mac_comment,
        (unsigned long long)ctx->seq,
        event->event,
        (unsigned long long)event->time_ns,
        (unsigned)event->status,
        (unsigned)event->failure_mask,
        (unsigned long long)event->monitor_passes,
        (unsigned long long)event->software_evidence_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_passes,
        (unsigned long long)event->synthetic_ecc_topology_patrol_failures,
        (unsigned long long)event->synthetic_fault_patrol_passes,
        (unsigned long long)event->synthetic_fault_patrol_failures,
        (unsigned long long)event->synthetic_numa_patrol_passes,
        (unsigned long long)event->synthetic_numa_patrol_failures,
        (unsigned)event->require_readiness,
        (unsigned)event->platform_evidence_mode,
        (unsigned)event->software_ecc_enabled,
        (unsigned)event->software_numa_enabled,
        (unsigned)event->software_fault_injection_mode,
        (unsigned)ctx->crc,
        ctx->mac_row);
    ctx->ok = (ctx->written > 0) &&
              ((size_t)ctx->written < sizeof(ctx->line));
}

static void llps_ip_audit_evidence_write(
    llps_ip_audit_evidence_record_context_t * const ctx) {
    if ((ctx == NULL) || !ctx->ok) {
        return;
    }
    ctx->job.fd = g_ip_audit_fd;
    ctx->job.line = ctx->line;
    ctx->job.len = (size_t)ctx->written;
    ctx->job.rc = -1;
    ctx->ok = llps_ip_audit_call_blocking_checked(
        llps_ip_audit_write_blocking,
        &ctx->job,
        &ctx->write_result,
        "ip_audit_evidence_write_blocking");
    if (ctx->ok && (ctx->write_result != &ctx->job)) {
        LLPS_EXPECT(false, ctx->ok = false);
    }
}

static bool llps_ip_audit_evidence_finish(
    llps_ip_audit_evidence_record_context_t * const ctx) {
    if (ctx == NULL) {
        return false;
    }
    if (!llps_ip_audit_writer_unlock_checked(ctx->writer_locked)) {
        return false;
    }
    return ctx->ok && (ctx->job.rc == 0);
}

bool llps_ip_audit_record_evidence(
    const llps_ip_audit_evidence_event_t * const event) {
    llps_ip_audit_evidence_record_context_t ctx;

    if (!g_ip_audit_enabled) {
        return true;
    }

    if ((event == NULL) || !llps_fd_is_valid(g_ip_audit_fd)) {
        return false;
    }

    llps_ip_audit_evidence_record_context_init(&ctx, event);
    if (!llps_ip_audit_token_is_safe(ctx.normalized.event,
                                     sizeof(ctx.normalized.event),
                                     false)) {
        return false;
    }

    if (!llps_ip_audit_writer_lock_checked(&ctx.writer_locked)) {
        return false;
    }

    llps_ip_audit_evidence_prepare_sequence(&ctx);
    llps_ip_audit_evidence_build_mac(&ctx);
    llps_ip_audit_evidence_format_line(&ctx);
    llps_ip_audit_evidence_write(&ctx);
    return llps_ip_audit_evidence_finish(&ctx);
}
