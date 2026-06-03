/**
 * @file tests/test_llps.c
 * @brief Unit coverage for LLPS configuration, networking, and safety state.
 *
 * @details
 * Tests include selected implementation files with wrapped platform calls so
 * fault paths can be exercised without opening real network or memory-policy
 * resources.
 */

#include <stddef.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef LLPS_MADV_DONTDUMP
#define LLPS_MADV_DONTDUMP                (1001)
#endif
#ifndef LLPS_MADV_NOHUGEPAGE
#define LLPS_MADV_NOHUGEPAGE              (1002)
#endif
#ifndef LLPS_MADV_UNMERGEABLE
#define LLPS_MADV_UNMERGEABLE             (1003)
#endif

#define socket __wrap_socket
#define bind __wrap_bind
#define listen __wrap_listen
#define fcntl __wrap_fcntl
#ifndef mlockall
#define mlockall __wrap_mlockall
#endif
#ifndef mlock
#define mlock __wrap_mlock
#endif
#ifndef madvise
#define madvise __wrap_madvise
#endif
#define accept __wrap_accept
#define connect __wrap_connect
#define getsockopt __wrap_getsockopt
#define setsockopt __wrap_setsockopt
#define inet_pton __wrap_inet_pton
#define getaddrinfo __wrap_getaddrinfo
#define freeaddrinfo __wrap_freeaddrinfo
#define read __wrap_read
#define write __wrap_write
#define send __wrap_send
#define close __wrap_close
#define shutdown __wrap_shutdown
#define llam_now_ns __wrap_llam_now_ns
#define llam_sleep_ns __wrap_llam_sleep_ns
#define llam_yield __wrap_llam_yield
#define llam_poll_fd __wrap_llam_poll_fd
#define llam_read_when_ready __wrap_llam_read_when_ready
#define llam_spawn __wrap_llam_spawn
#define llam_detach __wrap_llam_detach
#define llam_task_group_create __wrap_llam_task_group_create
#define llam_task_group_spawn __wrap_llam_task_group_spawn
#define llam_task_group_join __wrap_llam_task_group_join
#define llam_task_group_destroy __wrap_llam_task_group_destroy
#ifndef LLPS_TEST_HOOKS
#define LLPS_TEST_HOOKS 1
#endif

int __wrap_mlock(const void *addr, size_t len);
int __wrap_mlockall(int flags);
int __wrap_madvise(void *addr, size_t len, int advice);
int __wrap_socket(int domain, int type, int protocol);
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __wrap_listen(int fd, int backlog);
int __wrap_fcntl(int fd, int cmd, ...);
int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len);
int __wrap_getsockopt(int fd,
                      int level,
                      int optname,
                      void *optval,
                      socklen_t *optlen);
int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void *optval,
                      socklen_t optlen);
int __wrap_inet_pton(int af, const char *src, void *dst);
int __wrap_getaddrinfo(const char *node,
                       const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);
void __wrap_freeaddrinfo(struct addrinfo *res);
ssize_t __wrap_read(int fd, void *buf, size_t len);
ssize_t __wrap_write(int fd, const void *buf, size_t len);
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags);
int __wrap_close(int fd);
int __wrap_shutdown(int fd, int how);

#include "../src/net/llps_net.c"
#include "../src/core/llps_state.c"

#undef socket
#undef bind
#undef listen
#undef fcntl
#undef mlockall
#undef mlock
#undef madvise
#undef accept
#undef connect
#undef getsockopt
#undef setsockopt
#undef inet_pton
#undef getaddrinfo
#undef freeaddrinfo
#undef read
#undef write
#undef send
#undef close
#undef shutdown
#undef llam_now_ns
#undef llam_sleep_ns
#undef llam_yield
#undef llam_poll_fd
#undef llam_read_when_ready
#undef llam_spawn
#undef llam_detach
#undef llam_task_group_create
#undef llam_task_group_spawn
#undef llam_task_group_join
#undef llam_task_group_destroy

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "llps_secded.h"
#include "llps_hmac.h"
#include "llps_edac.h"
#include "llps_software_evidence.h"

#define LLPS_TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            (void)fprintf(stderr, \
                          "test assertion failed at %s:%d: %s\n", \
                          __FILE__, \
                          __LINE__, \
                          #condition); \
            abort(); \
        } \
    } while (0)

static int mock_socket_ret = 100;
static uint32_t mock_socket_calls = 0u;
static int mock_bind_ret = 0;
static int mock_listen_ret = 0;
static int mock_fcntl_ret = 0;
static int mock_fcntl_getfl_ret = O_NONBLOCK;
static int mock_mlockall_ret = 0;
static int mock_mlock_ret = 0;
static int mock_madvise_ret = 0;
static int mock_accept_ret = -1;
static int mock_accept_errno_value = 0;
static uint32_t mock_accept_calls = 0u;
static uint32_t mock_accept_successes_remaining = 0u;
static uint16_t mock_accept_next_port = 30000u;
static uint32_t mock_accept_ipv4_addr = 0x7F000001u;
static int mock_connect_ret = 0;
static int mock_connect_errno_value = 0;
static int mock_getsockopt_so_error = 0;
static int mock_getaddrinfo_ret = 0;
static int mock_llam_poll_fd_ret = 1;
static int mock_llam_detach_ret = 0;
static int mock_llam_sleep_ns_ret = 0;
static short mock_llam_poll_fd_revents = 0;
static bool mock_llam_read_when_ready_delegates_read = true;
static uint32_t mock_llam_read_when_ready_calls = 0u;
static ssize_t mock_llam_read_when_ready_ret = 0;
static int mock_llam_read_when_ready_errno_value = 0;
static int mock_llam_read_when_ready_last_timeout_ms = 0;
static uint64_t mock_llam_now_ns = 1000u;

static unsigned long test_tmp_serial(void) {
    return ((unsigned long)getpid() * 1000003UL) ^
           (unsigned long)mock_llam_now_ns;
}

static bool mock_sleep_requests_shutdown = false;
static uint32_t mock_mlock_calls = 0u;
static uint32_t mock_mlockall_calls = 0u;
static uint32_t mock_madvise_calls = 0u;
static uint32_t mock_shutdown_calls = 0u;
static uint32_t mock_getaddrinfo_calls = 0u;
static uint32_t mock_freeaddrinfo_calls = 0u;
static uint32_t mock_task_group_spawn_calls = 0u;
static uint32_t mock_read_calls = 0u;
static uint32_t mock_send_calls = 0u;
static ssize_t mock_read_ret = 0;
static ssize_t mock_send_ret = 0;
static int mock_read_errno_value = 0;
static int mock_send_errno_value = 0;
static uint32_t mock_read_eof_after_calls = UINT32_MAX;
static bool mock_read_return_unbounded = false;
static uint8_t mock_read_data[256];
static size_t mock_read_data_len = 0u;
static size_t mock_read_data_off = 0u;
static size_t mock_read_chunk_max = 0u;
static uint8_t mock_send_capture[512];
static size_t mock_send_capture_len = 0u;
static size_t mock_send_last_len = 0u;
static bool mock_task_group_spawn_checks_session_integrity = false;
static bool mock_task_group_spawn_saw_active_session = true;
static char mock_getaddrinfo_node[LLPS_YML_MAX_IP_TEXT];
static char mock_getaddrinfo_service[8];
static struct sockaddr_in mock_getaddrinfo_addr;
static struct addrinfo mock_getaddrinfo_result;
static const uint32_t test_physical_memory_domains[LLPS_SESSION_TMR_BANK_COUNT] =
    { 11u, 22u, 33u };
static const uint32_t test_hardware_tmr_domains[LLPS_SESSION_TMR_BANK_COUNT] =
    { 101u, 202u, 303u };
static const uint32_t test_hardware_tmr_voter_domain = 404u;
static const uint32_t test_overlapping_hardware_tmr_domains[LLPS_SESSION_TMR_BANK_COUNT] =
    { 11u, 202u, 303u };
static char test_complete_edac_root[128];
static char test_complete_boot_id_path[128];
static char test_complete_platform_id_path[128];
static char test_complete_executable_image_path[128];
static char test_complete_numa_root[128];

#define LLPS_TEST_PATH_SLOT_COUNT (256u)
#define LLPS_TEST_PATH_SLOT_CAP   (256u)

static char test_path_slots[5u][LLPS_TEST_PATH_SLOT_COUNT][LLPS_TEST_PATH_SLOT_CAP];
static size_t test_path_slot_next[5u];

static const char *test_copy_path_slot(const size_t bank,
                                       const char * const path) {
    char *slot = NULL;
    int n = 0;

    if (path == NULL) {
        return NULL;
    }
    LLPS_TEST_ASSERT(bank < 5u);

    slot = test_path_slots[bank][test_path_slot_next[bank]];
    test_path_slot_next[bank] =
        (test_path_slot_next[bank] + 1u) % LLPS_TEST_PATH_SLOT_COUNT;
    n = snprintf(slot, LLPS_TEST_PATH_SLOT_CAP, "%s", path);
    LLPS_TEST_ASSERT(n >= 0);
    LLPS_TEST_ASSERT((size_t)n < LLPS_TEST_PATH_SLOT_CAP);
    return slot;
}

static void test_set_path_override(const size_t bank,
                                   const char ** const global_path,
                                   const char * const path) {
    LLPS_TEST_ASSERT(global_path != NULL);
    *global_path = test_copy_path_slot(bank, path);
}

static void test_set_edac_sysfs_root(const char * const path) {
    test_set_path_override(0u, &g_edac_sysfs_root, path);
}

static void test_set_boot_id_path(const char * const path) {
    test_set_path_override(1u, &g_boot_id_path, path);
}

static void test_set_platform_id_path(const char * const path) {
    test_set_path_override(2u, &g_platform_id_path, path);
}

static void test_set_executable_image_path(const char * const path) {
    test_set_path_override(3u, &g_executable_image_path, path);
}

static void test_set_numa_sysfs_root(const char * const path) {
    test_set_path_override(4u, &g_numa_sysfs_root, path);
}

static void test_prepare_boot_id_file(char *path,
                                      size_t path_cap,
                                      const char *boot_id_text);
static void test_prepare_platform_id_file(char *path,
                                          size_t path_cap,
                                          const char *platform_id_text);
static void test_prepare_executable_image_file(char *path,
                                               size_t path_cap,
                                               const char *image_text);
static void test_prepare_edac_tree(char *root,
                                   size_t root_cap,
                                   const char *ce_text,
                                   const char *ue_text);
static void test_remove_edac_tree(const char *root);
static void test_prepare_numa_tree(
    char *root,
    size_t root_cap,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]);

static llps_yml_config_t test_config(void) {
    const llps_yml_config_t cfg = {
        .max_clients = 4u,
        .buffer_size = 128u,
        .listen_host = "127.0.0.1",
        .listen_port = 25565u,
        .target_ip = "127.0.0.1",
        .target_port = 25566u,
        .listen_backlog = 4u,
        .accept_batch_max = 2u,
        .session_idle_timeout_ms = LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT,
        .max_sessions_per_client_ip = 0u,
        .max_new_sessions_per_client_ip_per_window = 0u,
        .client_ip_rate_window_ms = LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT,
        .client_preface_timeout_ms =
            LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT,
        .protocol_handshake_gate_enabled =
            LLPS_PROTOCOL_HANDSHAKE_GATE_DEFAULT,
        .software_fault_injection_mode =
            LLPS_SOFTWARE_FAULT_INJECTION_FULL
    };

    return cfg;
}

static size_t test_write_protocol_varint(uint8_t * const dst,
                                          const size_t cap,
                                          uint32_t value) {
    size_t used = 0u;

    LLPS_TEST_ASSERT(dst != NULL);
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7u;
        if (value != 0u) {
            byte |= 0x80u;
        }
        LLPS_TEST_ASSERT(used < cap);
        dst[used] = byte;
        ++used;
    } while (value != 0u);

    return used;
}

static size_t test_build_protocol_handshake(uint8_t * const dst,
                                             const size_t cap,
                                             const char * const host,
                                             const uint16_t port,
                                             const uint32_t next_state) {
    uint8_t body[LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX];
    size_t body_len = 0u;
    size_t host_len = 0u;
    size_t prefix_len = 0u;

    LLPS_TEST_ASSERT(dst != NULL);
    LLPS_TEST_ASSERT(host != NULL);
    host_len = strlen(host);
    LLPS_TEST_ASSERT(host_len > 0u);
    LLPS_TEST_ASSERT(host_len <= LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX);

    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            0u);
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            765u);
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            (uint32_t)host_len);
    LLPS_TEST_ASSERT((sizeof(body) - body_len) >= host_len);
    (void)memcpy(&body[body_len], host, host_len);
    body_len += host_len;
    LLPS_TEST_ASSERT((sizeof(body) - body_len) >= 2u);
    body[body_len] = (uint8_t)((uint32_t)port >> 8u);
    ++body_len;
    body[body_len] = (uint8_t)((uint32_t)port & 0xFFu);
    ++body_len;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            next_state);

    prefix_len = test_write_protocol_varint(dst, cap, (uint32_t)body_len);
    LLPS_TEST_ASSERT((cap - prefix_len) >= body_len);
    (void)memcpy(&dst[prefix_len], body, body_len);
    return prefix_len + body_len;
}

static size_t test_build_protocol_packet_from_body(
    uint8_t * const dst,
    const size_t cap,
    const uint8_t * const body,
    const size_t body_len) {
    size_t prefix_len = 0u;

    LLPS_TEST_ASSERT(dst != NULL);
    LLPS_TEST_ASSERT(body != NULL);
    LLPS_TEST_ASSERT(body_len > 0u);
    LLPS_TEST_ASSERT(body_len <= LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX);

    prefix_len = test_write_protocol_varint(dst, cap, (uint32_t)body_len);
    LLPS_TEST_ASSERT((cap - prefix_len) >= body_len);
    (void)memcpy(&dst[prefix_len], body, body_len);
    return prefix_len + body_len;
}

static void test_llps_observation_fingerprint_zero_is_reserved(void) {
    LLPS_TEST_ASSERT(llps_nonzero_fingerprint(0u) == UINT32_MAX);
    LLPS_TEST_ASSERT(llps_nonzero_fingerprint(0x12345678u) == 0x12345678u);

    printf("test_llps_observation_fingerprint_zero_is_reserved passed.\n");
}

static uint32_t test_expected_tmr_layout_fingerprint(void) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_BANK_COUNT);
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_ALIGNMENT_BYTES);
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
    crc = llps_crc32_update_u64(crc, llps_tmr_metadata_min_bank_distance());

    crc = llps_crc32_update_u32(crc, 0u);
    crc = llps_crc32_update_size(crc, sizeof(g_session_tmr_region0));
    crc = llps_crc32_update_u32(crc, 1u);
    crc = llps_crc32_update_size(crc, sizeof(g_session_tmr_region1));
    crc = llps_crc32_update_u32(crc, 2u);
    crc = llps_crc32_update_size(crc, sizeof(g_session_tmr_region2));
    crc = llps_crc32_update_u32(crc, 3u);
    crc = llps_crc32_update_size(crc, sizeof(g_runtime_cfg_bank0));
    crc = llps_crc32_update_u32(crc, 4u);
    crc = llps_crc32_update_size(crc, sizeof(g_runtime_cfg_bank1));
    crc = llps_crc32_update_u32(crc, 5u);
    crc = llps_crc32_update_size(crc, sizeof(g_runtime_cfg_bank2));
    crc = llps_crc32_update_u32(crc, 6u);
    crc = llps_crc32_update_size(crc, sizeof(g_free_list_bank0));
    crc = llps_crc32_update_u32(crc, 7u);
    crc = llps_crc32_update_size(crc, sizeof(g_free_list_bank1));
    crc = llps_crc32_update_u32(crc, 8u);
    crc = llps_crc32_update_size(crc, sizeof(g_free_list_bank2));
    crc = llps_crc32_update_u32(crc, 9u);
    crc = llps_crc32_update_size(crc, sizeof(g_control_flag_bank0));
    crc = llps_crc32_update_u32(crc, 10u);
    crc = llps_crc32_update_size(crc, sizeof(g_control_flag_bank1));
    crc = llps_crc32_update_u32(crc, 11u);
    crc = llps_crc32_update_size(crc, sizeof(g_control_flag_bank2));

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static void test_llps_tmr_layout_fingerprint_uses_stable_region_ids(void) {
    LLPS_TEST_ASSERT(llps_tmr_layout_fingerprint() ==
                     test_expected_tmr_layout_fingerprint());

    printf("test_llps_tmr_layout_fingerprint_uses_stable_region_ids passed.\n");
}

#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED
static void test_llps_tmr_residency_fingerprint_uses_nonxor_sum(void) {
    llps_tmr_memory_residency_probe_t probe;
    uint32_t first_sum = 0u;

    llps_tmr_memory_residency_probe_init(&probe);

    llps_tmr_memory_residency_probe_note_page(&probe,
                                              7u,
                                              (uintptr_t)0x1000u,
                                              true,
                                              true);
    first_sum = probe.page_sum;
    LLPS_TEST_ASSERT(first_sum != 0u);
    LLPS_TEST_ASSERT(probe.page_mix == first_sum);

    llps_tmr_memory_residency_probe_note_page(&probe,
                                              7u,
                                              (uintptr_t)0x1000u,
                                              true,
                                              true);
    LLPS_TEST_ASSERT(probe.pages_checked == 2u);
    LLPS_TEST_ASSERT(probe.resident_pages == 2u);
    LLPS_TEST_ASSERT(probe.nonresident_pages == 0u);
    LLPS_TEST_ASSERT(probe.probe_failures == 0u);
    LLPS_TEST_ASSERT(probe.page_mix == 0u);
    LLPS_TEST_ASSERT(probe.page_sum == (first_sum + first_sum));
    LLPS_TEST_ASSERT(probe.page_sum != probe.page_mix);

    printf("test_llps_tmr_residency_fingerprint_uses_nonxor_sum passed.\n");
}
#endif

#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
static void test_llps_tmr_physical_frame_fingerprint_uses_nonxor_sum(void) {
    llps_tmr_physical_frame_probe_t probe;
    uint32_t first_sum = 0u;

    llps_tmr_physical_frame_probe_init(&probe);

    llps_tmr_physical_frame_probe_note_page(&probe,
                                            7u,
                                            1u,
                                            (uintptr_t)0x1000u,
                                            true,
                                            0x12345u);
    first_sum = probe.page_sum;
    LLPS_TEST_ASSERT(first_sum != 0u);
    LLPS_TEST_ASSERT(probe.page_mix == first_sum);

    llps_tmr_physical_frame_probe_note_page(&probe,
                                            7u,
                                            1u,
                                            (uintptr_t)0x1000u,
                                            true,
                                            0x12345u);
    LLPS_TEST_ASSERT(probe.pages_checked == 2u);
    LLPS_TEST_ASSERT(probe.distinct_pages == 1u);
    LLPS_TEST_ASSERT(probe.duplicate_pages == 1u);
    LLPS_TEST_ASSERT(probe.probe_failures == 0u);
    LLPS_TEST_ASSERT(!probe.min_cross_bank_distance_seen);
    LLPS_TEST_ASSERT(probe.page_mix == 0u);
    LLPS_TEST_ASSERT(probe.page_sum == (first_sum + first_sum));
    LLPS_TEST_ASSERT(probe.page_sum != probe.page_mix);

    printf("test_llps_tmr_physical_frame_fingerprint_uses_nonxor_sum passed.\n");
}
#endif

#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
static void test_llps_tmr_physical_frame_tracks_cross_bank_distance(void) {
    llps_tmr_physical_frame_probe_t probe;
    const uint64_t required_distance =
        llps_tmr_physical_frame_required_distance_pages();

    llps_tmr_physical_frame_probe_init(&probe);
    llps_tmr_physical_frame_probe_note_page(&probe,
                                            1u,
                                            0u,
                                            (uintptr_t)0x1000u,
                                            true,
                                            1000u);
    llps_tmr_physical_frame_probe_note_page(&probe,
                                            2u,
                                            1u,
                                            (uintptr_t)0x2000u,
                                            true,
                                            1000u);
    LLPS_TEST_ASSERT(probe.min_cross_bank_distance_seen);
    LLPS_TEST_ASSERT(probe.min_cross_bank_distance == 0u);
    LLPS_TEST_ASSERT(probe.pair_coverage_mask == 0x1u);
    LLPS_TEST_ASSERT(probe.pair_min_distances[0] == 0u);
    LLPS_TEST_ASSERT(probe.min_cross_bank_distance < required_distance);

    llps_tmr_physical_frame_probe_init(&probe);
    llps_tmr_physical_frame_probe_note_page(&probe,
                                            1u,
                                            0u,
                                            (uintptr_t)0x3000u,
                                            true,
                                            1000u);
    llps_tmr_physical_frame_probe_note_page(&probe,
                                            2u,
                                            1u,
                                            (uintptr_t)0x4000u,
                                            true,
                                            1000u + required_distance);
    LLPS_TEST_ASSERT(probe.min_cross_bank_distance_seen);
    LLPS_TEST_ASSERT(probe.min_cross_bank_distance == required_distance);
    LLPS_TEST_ASSERT(probe.pair_coverage_mask == 0x1u);
    LLPS_TEST_ASSERT(probe.pair_min_distances[0] == required_distance);

    printf("test_llps_tmr_physical_frame_tracks_cross_bank_distance passed.\n");
}
#endif

static llps_yml_config_t test_required_readiness_config(void) {
    llps_yml_config_t cfg = test_config();

    cfg.require_readiness = 1u;
    cfg.platform_safety_flags = LLPS_PLATFORM_EVIDENCE_REQUIRED;
    cfg.platform_safety_evidence_id = 0xA5A55A5A01020304ULL;
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        cfg.platform_physical_memory_domains[i] = test_physical_memory_domains[i];
        cfg.platform_hardware_tmr_domains[i] = test_hardware_tmr_domains[i];
    }
    cfg.platform_hardware_tmr_voter_domain = test_hardware_tmr_voter_domain;
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &cfg.platform_attestation_fingerprint) == LLPS_OK);

    return cfg;
}

static void test_prepare_complete_platform_observation_roots(void) {
    test_prepare_edac_tree(test_complete_edac_root,
                           sizeof(test_complete_edac_root),
                           "0\n",
                           "0\n");
    test_set_edac_sysfs_root(test_complete_edac_root);
    test_prepare_numa_tree(test_complete_numa_root,
                           sizeof(test_complete_numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(test_complete_numa_root);
}

static llps_status_t test_make_complete_platform_evidence(
    const uint64_t evidence_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    test_prepare_complete_platform_observation_roots();
    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);
    return llps_make_platform_safety_evidence_raw(
        LLPS_PLATFORM_EVIDENCE_REQUIRED,
        LLPS_PLATFORM_EVIDENCE_ECC_MEMORY | LLPS_PLATFORM_EVIDENCE_ECC_CLEAN,
        LLPS_PLATFORM_EVIDENCE_PHYS_SEP | LLPS_PLATFORM_EVIDENCE_HW_TMR,
        evidence_id,
        test_physical_memory_domains,
        test_hardware_tmr_domains,
        test_hardware_tmr_voter_domain,
        out_evidence);
}

static void test_reseal_platform_evidence(
    llps_platform_safety_evidence_t * const evidence) {
    LLPS_TEST_ASSERT(evidence != NULL);
    evidence->crc = llps_platform_safety_evidence_compute_crc(evidence);
    evidence->crc_inverse = ~evidence->crc;
}

static llps_yml_config_t test_required_readiness_config_with_current_observation(void) {
    llps_yml_config_t cfg = test_required_readiness_config();
    llps_platform_safety_evidence_t evidence;
    llps_status_t collect_status = LLPS_OK;

    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    collect_status = llps_collect_platform_safety_evidence(
        cfg.platform_safety_flags,
        cfg.platform_safety_evidence_id,
        cfg.platform_physical_memory_domains,
        cfg.platform_hardware_tmr_domains,
        cfg.platform_hardware_tmr_voter_domain,
        &evidence);
    if (collect_status != LLPS_OK) {
        (void)fprintf(stderr,
                      "current observation evidence collection status=%d\n",
                      (int)collect_status);
    }
    LLPS_TEST_ASSERT(collect_status == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);
    cfg.platform_observation_digest = evidence.observation_digest;

    return cfg;
}

static llps_yml_config_t
test_required_software_readiness_config_with_current_observation(void) {
    llps_yml_config_t cfg = test_required_readiness_config();
    llps_platform_safety_evidence_t evidence;
    llps_status_t collect_status = LLPS_OK;

    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC;
    cfg.payload_ecc_enabled = 1u;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 1u;
    cfg.software_ecc_dimm_count = 4u;
    cfg.software_ecc_scrub_rate = LLPS_SOFTWARE_ECC_SCRUB_RATE_DEFAULT;
    cfg.software_numa_enabled = 1u;
    cfg.software_numa_memtotal_kib = 65536u;
    cfg.software_numa_local_distance = 10u;
    cfg.software_numa_remote_distance = 20u;

    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    collect_status = llps_collect_platform_safety_evidence(
        cfg.platform_safety_flags,
        cfg.platform_safety_evidence_id,
        cfg.platform_physical_memory_domains,
        cfg.platform_hardware_tmr_domains,
        cfg.platform_hardware_tmr_voter_domain,
        &evidence);
    if (collect_status != LLPS_OK) {
        (void)fprintf(stderr,
                      "software observation evidence collection status=%d\n",
                      (int)collect_status);
    }
    LLPS_TEST_ASSERT(collect_status == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);
    cfg.platform_observation_digest = evidence.observation_digest;

    return cfg;
}

static void reset_mocks(void) {
    mock_socket_ret = 100;
    mock_socket_calls = 0u;
    mock_bind_ret = 0;
    mock_listen_ret = 0;
    mock_fcntl_ret = 0;
    mock_fcntl_getfl_ret = O_NONBLOCK;
    mock_mlockall_ret = 0;
    mock_mlock_ret = 0;
    mock_madvise_ret = 0;
    mock_accept_ret = -1;
    mock_accept_errno_value = 0;
    mock_accept_calls = 0u;
    mock_accept_successes_remaining = 0u;
    mock_accept_next_port = 30000u;
    mock_accept_ipv4_addr = 0x7F000001u;
    mock_connect_ret = 0;
    mock_connect_errno_value = 0;
    mock_getsockopt_so_error = 0;
    mock_getaddrinfo_ret = 0;
    mock_llam_poll_fd_ret = 1;
    mock_llam_detach_ret = 0;
    mock_llam_sleep_ns_ret = 0;
    mock_llam_poll_fd_revents = 0;
    mock_llam_read_when_ready_delegates_read = true;
    mock_llam_read_when_ready_calls = 0u;
    mock_llam_read_when_ready_ret = 0;
    mock_llam_read_when_ready_errno_value = 0;
    mock_llam_read_when_ready_last_timeout_ms = 0;
    mock_llam_now_ns = 1000u;
    mock_sleep_requests_shutdown = false;
    mock_mlock_calls = 0u;
    mock_mlockall_calls = 0u;
    mock_madvise_calls = 0u;
    mock_shutdown_calls = 0u;
    mock_getaddrinfo_calls = 0u;
    mock_freeaddrinfo_calls = 0u;
    mock_task_group_spawn_calls = 0u;
    mock_read_calls = 0u;
    mock_send_calls = 0u;
    mock_read_ret = 0;
    mock_send_ret = 0;
    mock_read_errno_value = 0;
    mock_send_errno_value = 0;
    mock_read_eof_after_calls = UINT32_MAX;
    mock_read_return_unbounded = false;
    (void)memset(mock_read_data, 0, sizeof(mock_read_data));
    mock_read_data_len = 0u;
    mock_read_data_off = 0u;
    mock_read_chunk_max = 0u;
    (void)memset(mock_send_capture, 0, sizeof(mock_send_capture));
    mock_send_capture_len = 0u;
    mock_send_last_len = 0u;
    mock_task_group_spawn_checks_session_integrity = false;
    mock_task_group_spawn_saw_active_session = true;
    (void)memset(mock_getaddrinfo_node, 0, sizeof(mock_getaddrinfo_node));
    (void)memset(mock_getaddrinfo_service, 0, sizeof(mock_getaddrinfo_service));
    (void)memset(&mock_getaddrinfo_addr, 0, sizeof(mock_getaddrinfo_addr));
    (void)memset(&mock_getaddrinfo_result, 0, sizeof(mock_getaddrinfo_result));
    g_backend_addr_valid = false;
    (void)memset(&g_backend_addr, 0, sizeof(g_backend_addr));
    test_set_edac_sysfs_root(LLPS_EDAC_SYSFS_ROOT);
    test_set_boot_id_path(LLPS_BOOT_ID_PATH);
    test_set_platform_id_path(LLPS_PLATFORM_ID_PATH);
    test_set_executable_image_path(NULL);
    test_set_numa_sysfs_root(LLPS_NUMA_SYSFS_ROOT);
    llps_process_memory_locked_set(false);
    llps_tmr_memory_locked_set(false);
    llps_tmr_memory_prefaulted_set(false);
    llps_tmr_memory_domains_bound_set(false);
    llps_tmr_memory_hardened_set(false);
    llps_tmr_startup_self_test_passed_set(false);
    llps_tmr_startup_self_test_set_coverage(0u);
    llps_tmr_memory_prefault_pages_set(0u);
    llps_tmr_memory_domain_observation_fingerprint_set(0u);
    llps_tmr_memory_observed_domains_set(NULL);
    llps_configure_tmr_software_memory_observation(false, NULL);
    g_tmr_memory_domain_probe_override_enabled = false;
    g_tmr_memory_residency_probe_override_enabled = false;
    g_tmr_memory_residency_probe_override_resident = true;
    g_tmr_physical_frame_probe_synthetic_enabled = false;
    g_tmr_physical_frame_probe_override_alias = false;
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        g_tmr_memory_domain_probe_override_domains[i] = 0u;
    }
}

static void test_write_config_file(const char * const text,
                                   char * const path,
                                   const size_t path_cap) {
    FILE *fp = NULL;

    LLPS_TEST_ASSERT(text != NULL);
    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(path_cap > 0u);

    (void)snprintf(path,
                   path_cap,
                   "/tmp/llps_test_config_%lu.yml",
                   test_tmp_serial());
    fp = fopen(path, "w");
    LLPS_TEST_ASSERT(fp != NULL);
    LLPS_TEST_ASSERT(fputs(text, fp) >= 0);
    LLPS_TEST_ASSERT(fclose(fp) == 0);
}

static void test_remove_config_file(const char * const path) {
    if (path != NULL) {
        (void)remove(path);
    }
}

static void test_write_text_file(const char * const path,
                                 const char * const text) {
    FILE *fp = NULL;

    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(text != NULL);

    fp = fopen(path, "w");
    LLPS_TEST_ASSERT(fp != NULL);
    LLPS_TEST_ASSERT(fputs(text, fp) >= 0);
    LLPS_TEST_ASSERT(fclose(fp) == 0);
}

static void test_read_text_file(const char * const path,
                                char * const out,
                                const size_t out_cap) {
    FILE *fp = NULL;
    size_t n = 0u;

    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(out != NULL);
    LLPS_TEST_ASSERT(out_cap > 1u);

    (void)memset(out, 0, out_cap);
    fp = fopen(path, "r");
    LLPS_TEST_ASSERT(fp != NULL);
    n = fread(out, 1u, out_cap - 1u, fp);
    LLPS_TEST_ASSERT(ferror(fp) == 0);
    out[n] = '\0';
    LLPS_TEST_ASSERT(fclose(fp) == 0);
    LLPS_TEST_ASSERT(n > 0u);
}

static void test_replace_first_text(char * const text,
                                    const size_t text_cap,
                                    const char * const needle,
                                    const char * const replacement) {
    char *pos = NULL;
    const size_t needle_len = strlen(needle);
    const size_t replacement_len = strlen(replacement);

    LLPS_TEST_ASSERT(text != NULL);
    LLPS_TEST_ASSERT(text_cap > 0u);
    LLPS_TEST_ASSERT(needle != NULL);
    LLPS_TEST_ASSERT(replacement != NULL);
    LLPS_TEST_ASSERT(needle_len == replacement_len);

    pos = strstr(text, needle);
    LLPS_TEST_ASSERT(pos != NULL);
    LLPS_TEST_ASSERT((size_t)(pos - text) + replacement_len < text_cap);
    (void)memcpy(pos, replacement, replacement_len);
}

static void test_prepare_boot_id_file(char * const path,
                                      const size_t path_cap,
                                      const char * const boot_id_text) {
    int n = 0;

    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(path_cap > 0u);
    LLPS_TEST_ASSERT(boot_id_text != NULL);

    n = snprintf(path,
                 path_cap,
                 "/tmp/llps_boot_id_test_%lu",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < path_cap);

    (void)remove(path);
    test_write_text_file(path, boot_id_text);
}

static void test_prepare_platform_id_file(char * const path,
                                          const size_t path_cap,
                                          const char * const platform_id_text) {
    int n = 0;

    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(path_cap > 0u);
    LLPS_TEST_ASSERT(platform_id_text != NULL);

    n = snprintf(path,
                 path_cap,
                 "/tmp/llps_platform_id_test_%lu",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < path_cap);

    (void)remove(path);
    test_write_text_file(path, platform_id_text);
}

static void test_prepare_executable_image_file(char * const path,
                                               const size_t path_cap,
                                               const char * const image_text) {
    int n = 0;

    LLPS_TEST_ASSERT(path != NULL);
    LLPS_TEST_ASSERT(path_cap > 0u);
    LLPS_TEST_ASSERT(image_text != NULL);

    n = snprintf(path,
                 path_cap,
                 "/tmp/llps_executable_image_test_%lu",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < path_cap);

    (void)remove(path);
    test_write_text_file(path, image_text);
}

static void test_remove_boot_id_file(const char * const path) {
    if (path != NULL) {
        (void)remove(path);
    }
}

static void test_remove_platform_id_file(const char * const path) {
    if (path != NULL) {
        (void)remove(path);
    }
}

static void test_remove_executable_image_file(const char * const path) {
    if (path != NULL) {
        (void)remove(path);
    }
}

static void test_enable_tmr_memory_domain_override(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    LLPS_TEST_ASSERT(domain_ids != NULL);

    g_tmr_memory_domain_probe_override_enabled = true;
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        g_tmr_memory_domain_probe_override_domains[i] = domain_ids[i];
    }
}

static void test_prepare_edac_tree_with_mode(char * const root,
                                             const size_t root_cap,
                                             const char * const ce_text,
                                             const char * const ue_text,
                                             const char * const mode_text) {
    char mc0_path[160];
    char dimm0_path[180];
    char ce_path[200];
    char ue_path[200];
    char scrub_rate_path[220];
    char mode_path[220];
    char dimm_ce_path[220];
    char dimm_ue_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(root_cap > 0u);

    n = snprintf(root,
                 root_cap,
                 "/tmp/llps_edac_test_%lu",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < root_cap);

    test_remove_edac_tree(root);

    n = snprintf(mc0_path, sizeof(mc0_path), "%s/mc0", root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(mc0_path));
    n = snprintf(dimm0_path, sizeof(dimm0_path), "%s/dimm0", mc0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm0_path));
    n = snprintf(ce_path, sizeof(ce_path), "%s/ce_count", mc0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(ce_path));
    n = snprintf(ue_path, sizeof(ue_path), "%s/ue_count", mc0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(ue_path));
    n = snprintf(scrub_rate_path,
                 sizeof(scrub_rate_path),
                 "%s/sdram_scrub_rate",
                 mc0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(scrub_rate_path));
    n = snprintf(mode_path, sizeof(mode_path), "%s/dimm_edac_mode", dimm0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(mode_path));
    n = snprintf(dimm_ce_path,
                 sizeof(dimm_ce_path),
                 "%s/dimm_ce_count",
                 dimm0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm_ce_path));
    n = snprintf(dimm_ue_path,
                 sizeof(dimm_ue_path),
                 "%s/dimm_ue_count",
                 dimm0_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm_ue_path));

    (void)remove(mode_path);
    (void)remove(dimm_ce_path);
    (void)remove(dimm_ue_path);
    (void)remove(ce_path);
    (void)remove(ue_path);
    (void)remove(scrub_rate_path);
    (void)rmdir(dimm0_path);
    (void)rmdir(mc0_path);
    (void)rmdir(root);

    LLPS_TEST_ASSERT(mkdir(root, 0700) == 0);
    LLPS_TEST_ASSERT(mkdir(mc0_path, 0700) == 0);
    LLPS_TEST_ASSERT(mkdir(dimm0_path, 0700) == 0);
    test_write_text_file(ce_path, ce_text);
    test_write_text_file(ue_path, ue_text);
    test_write_text_file(scrub_rate_path, "1024\n");
    if (mode_text != NULL) {
        test_write_text_file(mode_path, mode_text);
    }
    test_write_text_file(dimm_ce_path, "0\n");
    test_write_text_file(dimm_ue_path, "0\n");
}

static void test_prepare_edac_tree(char * const root,
                                   const size_t root_cap,
                                   const char * const ce_text,
                                   const char * const ue_text) {
    test_prepare_edac_tree_with_mode(root,
                                     root_cap,
                                     ce_text,
                                     ue_text,
                                     "SECDED\n");
}

static void test_add_edac_dimm_mode(const char * const root,
                                    const char * const dimm_name,
                                    const char * const mode_text) {
    char mc0_path[160];
    char dimm_path[180];
    char mode_path[220];
    char dimm_ce_path[220];
    char dimm_ue_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(dimm_name != NULL);

    n = snprintf(mc0_path, sizeof(mc0_path), "%s/mc0", root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(mc0_path));
    n = snprintf(dimm_path, sizeof(dimm_path), "%s/%s", mc0_path, dimm_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm_path));
    n = snprintf(mode_path, sizeof(mode_path), "%s/dimm_edac_mode", dimm_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(mode_path));
    n = snprintf(dimm_ce_path,
                 sizeof(dimm_ce_path),
                 "%s/dimm_ce_count",
                 dimm_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm_ce_path));
    n = snprintf(dimm_ue_path,
                 sizeof(dimm_ue_path),
                 "%s/dimm_ue_count",
                 dimm_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(dimm_ue_path));

    (void)remove(mode_path);
    (void)remove(dimm_ce_path);
    (void)remove(dimm_ue_path);
    (void)rmdir(dimm_path);
    LLPS_TEST_ASSERT(mkdir(dimm_path, 0700) == 0);
    if (mode_text != NULL) {
        test_write_text_file(mode_path, mode_text);
    }
    test_write_text_file(dimm_ce_path, "0\n");
    test_write_text_file(dimm_ue_path, "0\n");
}

static void test_write_edac_dimm_counter(const char * const root,
                                         const char * const dimm_name,
                                         const char * const counter_name,
                                         const char * const counter_text) {
    char counter_path[240];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(dimm_name != NULL);
    LLPS_TEST_ASSERT(counter_name != NULL);
    LLPS_TEST_ASSERT(counter_text != NULL);

    n = snprintf(counter_path,
                 sizeof(counter_path),
                 "%s/mc0/%s/%s",
                 root,
                 dimm_name,
                 counter_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(counter_path));
    test_write_text_file(counter_path, counter_text);
}

static void test_remove_edac_dimm_counter(const char * const root,
                                          const char * const dimm_name,
                                          const char * const counter_name) {
    char counter_path[240];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(dimm_name != NULL);
    LLPS_TEST_ASSERT(counter_name != NULL);

    n = snprintf(counter_path,
                 sizeof(counter_path),
                 "%s/mc0/%s/%s",
                 root,
                 dimm_name,
                 counter_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(counter_path));
    (void)remove(counter_path);
}

static void test_write_edac_controller_counter(const char * const root,
                                               const char * const counter_name,
                                               const char * const counter_text) {
    char counter_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(counter_name != NULL);
    LLPS_TEST_ASSERT(counter_text != NULL);

    n = snprintf(counter_path,
                 sizeof(counter_path),
                 "%s/mc0/%s",
                 root,
                 counter_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(counter_path));
    test_write_text_file(counter_path, counter_text);
}

static void test_remove_edac_controller_counter(const char * const root,
                                                const char * const counter_name) {
    char counter_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(counter_name != NULL);

    n = snprintf(counter_path,
                 sizeof(counter_path),
                 "%s/mc0/%s",
                 root,
                 counter_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(counter_path));
    (void)remove(counter_path);
}

static void test_remove_edac_tree(const char * const root) {
    char mc0_path[160];
    char dimm0_path[180];
    char dimm1_path[180];
    char ce_path[200];
    char ue_path[200];
    char scrub_rate_path[220];
    char mode_path[220];
    char mode1_path[220];
    char dimm_ce_path[220];
    char dimm_ue_path[220];
    int n = 0;

    if (root == NULL) {
        return;
    }

    n = snprintf(mc0_path, sizeof(mc0_path), "%s/mc0", root);
    if ((n > 0) && ((size_t)n < sizeof(mc0_path))) {
        n = snprintf(dimm0_path, sizeof(dimm0_path), "%s/dimm0", mc0_path);
        if ((n > 0) && ((size_t)n < sizeof(dimm0_path))) {
            n = snprintf(mode_path,
                         sizeof(mode_path),
                         "%s/dimm_edac_mode",
                         dimm0_path);
            if ((n > 0) && ((size_t)n < sizeof(mode_path))) {
                (void)remove(mode_path);
            }
            n = snprintf(dimm_ce_path,
                         sizeof(dimm_ce_path),
                         "%s/dimm_ce_count",
                         dimm0_path);
            if ((n > 0) && ((size_t)n < sizeof(dimm_ce_path))) {
                (void)remove(dimm_ce_path);
            }
            n = snprintf(dimm_ue_path,
                         sizeof(dimm_ue_path),
                         "%s/dimm_ue_count",
                         dimm0_path);
            if ((n > 0) && ((size_t)n < sizeof(dimm_ue_path))) {
                (void)remove(dimm_ue_path);
            }
            (void)rmdir(dimm0_path);
        }
        n = snprintf(dimm1_path, sizeof(dimm1_path), "%s/dimm1", mc0_path);
        if ((n > 0) && ((size_t)n < sizeof(dimm1_path))) {
            n = snprintf(mode1_path,
                         sizeof(mode1_path),
                         "%s/dimm_edac_mode",
                         dimm1_path);
            if ((n > 0) && ((size_t)n < sizeof(mode1_path))) {
                (void)remove(mode1_path);
            }
            n = snprintf(dimm_ce_path,
                         sizeof(dimm_ce_path),
                         "%s/dimm_ce_count",
                         dimm1_path);
            if ((n > 0) && ((size_t)n < sizeof(dimm_ce_path))) {
                (void)remove(dimm_ce_path);
            }
            n = snprintf(dimm_ue_path,
                         sizeof(dimm_ue_path),
                         "%s/dimm_ue_count",
                         dimm1_path);
            if ((n > 0) && ((size_t)n < sizeof(dimm_ue_path))) {
                (void)remove(dimm_ue_path);
            }
            (void)rmdir(dimm1_path);
        }
        n = snprintf(ce_path, sizeof(ce_path), "%s/ce_count", mc0_path);
        if ((n > 0) && ((size_t)n < sizeof(ce_path))) {
            (void)remove(ce_path);
        }
        n = snprintf(ue_path, sizeof(ue_path), "%s/ue_count", mc0_path);
        if ((n > 0) && ((size_t)n < sizeof(ue_path))) {
            (void)remove(ue_path);
        }
        n = snprintf(scrub_rate_path,
                     sizeof(scrub_rate_path),
                     "%s/sdram_scrub_rate",
                     mc0_path);
        if ((n > 0) && ((size_t)n < sizeof(scrub_rate_path))) {
            (void)remove(scrub_rate_path);
        }
        (void)rmdir(mc0_path);
    }

    (void)rmdir(root);
}

static uint32_t test_numa_distance_value(const size_t row_index,
                                         const size_t column_index,
                                         const bool duplicate_local_peer,
                                         const uint32_t pair01_delta,
                                         const bool asymmetric_pair01) {
    uint32_t value = 99u;

    if (row_index == column_index) {
        value = 10u;
    } else {
        value = 20u + (10u * (uint32_t)(row_index + column_index));
        if (((row_index == 0u) && (column_index == 1u)) ||
            ((row_index == 1u) && (column_index == 0u))) {
            value += pair01_delta;
        }
        if (asymmetric_pair01 &&
            (row_index == 0u) &&
            (column_index == 1u)) {
            ++value;
        }
        if (duplicate_local_peer) {
            value = 10u;
        }
    }

    return value;
}

static void test_build_numa_distance_text(
    char * const out_text,
    const size_t out_text_cap,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const size_t row_index,
    const bool duplicate_local_peer,
    const uint32_t pair01_delta,
    const bool asymmetric_pair01) {
    uint32_t max_domain = 0u;
    size_t used = 0u;

    LLPS_TEST_ASSERT(out_text != NULL);
    LLPS_TEST_ASSERT(out_text_cap > 0u);
    LLPS_TEST_ASSERT(domain_ids != NULL);
    LLPS_TEST_ASSERT(row_index < LLPS_SESSION_TMR_BANK_COUNT);

    out_text[0] = '\0';
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (domain_ids[i] > max_domain) {
            max_domain = domain_ids[i];
        }
    }

    for (uint32_t column = 0u; column <= max_domain; ++column) {
        char fragment[32];
        uint32_t value = 99u;
        bool is_configured_column = false;
        int n = 0;
        size_t fragment_len = 0u;

        for (size_t domain_index = 0u;
             domain_index < LLPS_SESSION_TMR_BANK_COUNT;
             ++domain_index) {
            if (domain_ids[domain_index] == column) {
                value = test_numa_distance_value(row_index,
                                                 domain_index,
                                                 duplicate_local_peer,
                                                 pair01_delta,
                                                 asymmetric_pair01);
                is_configured_column = true;
            }
        }
        if (!is_configured_column) {
            value = 99u;
        }

        n = snprintf(fragment,
                     sizeof(fragment),
                     "%u%s",
                     (unsigned)value,
                     (column == max_domain) ? "\n" : " ");
        LLPS_TEST_ASSERT(n > 0);
        LLPS_TEST_ASSERT((size_t)n < sizeof(fragment));
        fragment_len = (size_t)n;
        LLPS_TEST_ASSERT(used < out_text_cap);
        LLPS_TEST_ASSERT(fragment_len < (out_text_cap - used));
        (void)memcpy(&out_text[used], fragment, fragment_len + 1u);
        used += fragment_len;
    }
}

static void test_prepare_numa_tree(
    char * const root,
    const size_t root_cap,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    char online_path[160];
    char has_memory_path[160];
    char has_normal_memory_path[180];
    char node_path[LLPS_SESSION_TMR_BANK_COUNT][180];
    char meminfo_path[LLPS_SESSION_TMR_BANK_COUNT][220];
    char distance_path[LLPS_SESSION_TMR_BANK_COUNT][220];
    char online_text[128];
    char meminfo_text[160];
    char distance_text[256];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(root_cap > 0u);
    LLPS_TEST_ASSERT(domain_ids != NULL);

    n = snprintf(root,
                 root_cap,
                 "/tmp/llps_numa_test_%lu",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < root_cap);

    n = snprintf(online_path, sizeof(online_path), "%s/online", root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(online_path));
    n = snprintf(has_memory_path, sizeof(has_memory_path), "%s/has_memory", root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(has_memory_path));
    n = snprintf(has_normal_memory_path,
                 sizeof(has_normal_memory_path),
                 "%s/has_normal_memory",
                 root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(has_normal_memory_path));

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        n = snprintf(node_path[i],
                     sizeof(node_path[i]),
                     "%s/node%u",
                     root,
                     (unsigned)domain_ids[i]);
        LLPS_TEST_ASSERT(n > 0);
        LLPS_TEST_ASSERT((size_t)n < sizeof(node_path[i]));
        n = snprintf(meminfo_path[i],
                     sizeof(meminfo_path[i]),
                     "%s/meminfo",
                     node_path[i]);
        LLPS_TEST_ASSERT(n > 0);
        LLPS_TEST_ASSERT((size_t)n < sizeof(meminfo_path[i]));
        n = snprintf(distance_path[i],
                     sizeof(distance_path[i]),
                     "%s/distance",
                     node_path[i]);
        LLPS_TEST_ASSERT(n > 0);
        LLPS_TEST_ASSERT((size_t)n < sizeof(distance_path[i]));
        (void)remove(meminfo_path[i]);
        (void)remove(distance_path[i]);
        (void)rmdir(node_path[i]);
    }
    (void)remove(online_path);
    (void)remove(has_memory_path);
    (void)remove(has_normal_memory_path);
    (void)rmdir(root);

    LLPS_TEST_ASSERT(mkdir(root, 0700) == 0);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        LLPS_TEST_ASSERT(mkdir(node_path[i], 0700) == 0);
        n = snprintf(meminfo_text,
                     sizeof(meminfo_text),
                     "Node %u MemTotal: %llu kB\n",
                     (unsigned)domain_ids[i],
                     (unsigned long long)(1048576ULL + ((uint64_t)i * 4096ULL)));
        LLPS_TEST_ASSERT(n > 0);
        LLPS_TEST_ASSERT((size_t)n < sizeof(meminfo_text));
        test_write_text_file(meminfo_path[i], meminfo_text);
        test_build_numa_distance_text(distance_text,
                                      sizeof(distance_text),
                                      domain_ids,
                                      i,
                                      false,
                                      0u,
                                      false);
        test_write_text_file(distance_path[i], distance_text);
    }

    n = snprintf(online_text,
                 sizeof(online_text),
                 "%u,%u,%u\n",
                 (unsigned)domain_ids[0],
                 (unsigned)domain_ids[1],
                 (unsigned)domain_ids[2]);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(online_text));
    test_write_text_file(online_path, online_text);
    test_write_text_file(has_memory_path, online_text);
    test_write_text_file(has_normal_memory_path, online_text);

    test_enable_tmr_memory_domain_override(domain_ids);
}

static void test_remove_numa_tree(
    const char * const root,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    char online_path[160];
    char has_memory_path[160];
    char has_normal_memory_path[180];
    int n = 0;

    if ((root == NULL) || (domain_ids == NULL)) {
        return;
    }

    n = snprintf(online_path, sizeof(online_path), "%s/online", root);
    if ((n > 0) && ((size_t)n < sizeof(online_path))) {
        (void)remove(online_path);
    }

    n = snprintf(has_memory_path, sizeof(has_memory_path), "%s/has_memory", root);
    if ((n > 0) && ((size_t)n < sizeof(has_memory_path))) {
        (void)remove(has_memory_path);
    }

    n = snprintf(has_normal_memory_path,
                 sizeof(has_normal_memory_path),
                 "%s/has_normal_memory",
                 root);
    if ((n > 0) && ((size_t)n < sizeof(has_normal_memory_path))) {
        (void)remove(has_normal_memory_path);
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        char node_path[180];
        char meminfo_path[220];
        char distance_path[220];

        n = snprintf(node_path,
                     sizeof(node_path),
                     "%s/node%u",
                     root,
                     (unsigned)domain_ids[i]);
        if ((n > 0) && ((size_t)n < sizeof(node_path))) {
            n = snprintf(meminfo_path,
                         sizeof(meminfo_path),
                         "%s/meminfo",
                         node_path);
            if ((n > 0) && ((size_t)n < sizeof(meminfo_path))) {
                (void)remove(meminfo_path);
            }
            n = snprintf(distance_path,
                         sizeof(distance_path),
                         "%s/distance",
                         node_path);
            if ((n > 0) && ((size_t)n < sizeof(distance_path))) {
                (void)remove(distance_path);
            }
            (void)rmdir(node_path);
        }
    }

    (void)rmdir(root);
}

static void test_write_numa_node_meminfo(const char * const root,
                                         const uint32_t domain_id,
                                         const char * const meminfo_text) {
    char meminfo_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(meminfo_text != NULL);

    n = snprintf(meminfo_path,
                 sizeof(meminfo_path),
                 "%s/node%u/meminfo",
                 root,
                 (unsigned)domain_id);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(meminfo_path));
    test_write_text_file(meminfo_path, meminfo_text);
}

static void test_remove_numa_node_meminfo(const char * const root,
                                          const uint32_t domain_id) {
    char meminfo_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);

    n = snprintf(meminfo_path,
                 sizeof(meminfo_path),
                 "%s/node%u/meminfo",
                 root,
                 (unsigned)domain_id);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(meminfo_path));
    (void)remove(meminfo_path);
}

static void test_write_numa_node_distance(const char * const root,
                                          const uint32_t domain_id,
                                          const char * const distance_text) {
    char distance_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);
    LLPS_TEST_ASSERT(distance_text != NULL);

    n = snprintf(distance_path,
                 sizeof(distance_path),
                 "%s/node%u/distance",
                 root,
                 (unsigned)domain_id);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(distance_path));
    test_write_text_file(distance_path, distance_text);
}

static void test_remove_numa_node_distance(const char * const root,
                                           const uint32_t domain_id) {
    char distance_path[220];
    int n = 0;

    LLPS_TEST_ASSERT(root != NULL);

    n = snprintf(distance_path,
                 sizeof(distance_path),
                 "%s/node%u/distance",
                 root,
                 (unsigned)domain_id);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(distance_path));
    (void)remove(distance_path);
}

static void test_llps_yml_accepts_legacy_required_config(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.ip_audit_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.ip_audit_path[0] == '\0');
    LLPS_TEST_ASSERT(cfg.audit_mac_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.audit_mac_key_path[0] == '\0');
    LLPS_TEST_ASSERT(cfg.require_readiness == 0u);
    LLPS_TEST_ASSERT(cfg.platform_safety_flags == 0u);
    LLPS_TEST_ASSERT(cfg.platform_safety_evidence_id == 0u);
    LLPS_TEST_ASSERT(cfg.platform_attestation_fingerprint == 0u);
    LLPS_TEST_ASSERT(cfg.platform_observation_digest == 0u);
    LLPS_TEST_ASSERT(cfg.platform_evidence_mode ==
                     LLPS_PLATFORM_EVIDENCE_MODE_REAL);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[0] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[1] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[2] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[0] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[1] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[2] == 0u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_voter_domain == 0u);
    LLPS_TEST_ASSERT(cfg.session_idle_timeout_ms ==
                     LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT);
    LLPS_TEST_ASSERT(cfg.max_sessions_per_client_ip == 0u);
    LLPS_TEST_ASSERT(cfg.max_new_sessions_per_client_ip_per_window == 0u);
    LLPS_TEST_ASSERT(cfg.client_ip_rate_window_ms ==
                     LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT);
    LLPS_TEST_ASSERT(cfg.client_preface_timeout_ms ==
                     LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT);
    LLPS_TEST_ASSERT(cfg.protocol_handshake_gate_enabled ==
                     LLPS_PROTOCOL_HANDSHAKE_GATE_DEFAULT);
    LLPS_TEST_ASSERT(cfg.payload_ecc_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_scrub_rate == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_numa_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.software_numa_memtotal_kib == 0u);
    LLPS_TEST_ASSERT(cfg.software_numa_local_distance == 0u);
    LLPS_TEST_ASSERT(cfg.software_numa_remote_distance == 0u);
    LLPS_TEST_ASSERT(cfg.software_fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_FULL);
    LLPS_TEST_ASSERT(cfg.evidence_mac_enabled == 0u);
    LLPS_TEST_ASSERT(cfg.evidence_mac_key_path[0] == '\0');
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_accepts_legacy_required_config passed.\n");
}

static void test_llps_yml_accepts_dns_hosts(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: localhost\n"
        "listen_port: 25565\n"
        "target_host: mc.Backend-01.example.com.\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(strcmp(cfg.listen_host, "localhost") == 0);
    LLPS_TEST_ASSERT(strcmp(cfg.target_ip, "mc.Backend-01.example.com.") == 0);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_accepts_dns_hosts passed.\n");
}

static void test_llps_yml_accepts_legacy_target_ip_alias(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: legacy-backend.example\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(strcmp(cfg.target_ip, "legacy-backend.example") == 0);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_accepts_legacy_target_ip_alias passed.\n");
}

static void test_llps_yml_rejects_duplicate_target_host_aliases(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_host: backend-a.example\n"
        "target_ip: backend-b.example\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_DUPLICATE);
    LLPS_TEST_ASSERT(error_line == 6u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_duplicate_target_host_aliases passed.\n");
}

static void test_llps_yml_parses_session_idle_timeout(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "session_idle_timeout_ms: 5000\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.session_idle_timeout_ms == 5000u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_session_idle_timeout passed.\n");
}

static void test_llps_yml_rejects_invalid_session_idle_timeout(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "session_idle_timeout_ms: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_session_idle_timeout passed.\n");
}

static void test_llps_yml_parses_max_sessions_per_client_ip(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "max_sessions_per_client_ip: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.max_sessions_per_client_ip == 2u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_max_sessions_per_client_ip passed.\n");
}

static void test_llps_yml_rejects_invalid_max_sessions_per_client_ip(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "max_sessions_per_client_ip: 5\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_max_sessions_per_client_ip passed.\n");
}

static void test_llps_yml_parses_client_ip_rate_limit(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "max_new_sessions_per_client_ip_per_window: 3\n"
        "client_ip_rate_window_ms: 500\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.max_new_sessions_per_client_ip_per_window == 3u);
    LLPS_TEST_ASSERT(cfg.client_ip_rate_window_ms == 500u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_client_ip_rate_limit passed.\n");
}

static void test_llps_yml_rejects_invalid_client_ip_rate_window(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "max_new_sessions_per_client_ip_per_window: 3\n"
        "client_ip_rate_window_ms: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_client_ip_rate_window passed.\n");
}

static void test_llps_yml_parses_client_preface_timeout(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "client_preface_timeout_ms: 2000\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.client_preface_timeout_ms == 2000u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_client_preface_timeout passed.\n");
}

static void test_llps_yml_rejects_invalid_client_preface_timeout(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "client_preface_timeout_ms: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_client_preface_timeout passed.\n");
}

static void test_llps_yml_parses_protocol_handshake_gate(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "client_preface_timeout_ms: 1000\n"
        "protocol_handshake_gate_enabled: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.client_preface_timeout_ms == 1000u);
    LLPS_TEST_ASSERT(cfg.protocol_handshake_gate_enabled == 1u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_protocol_handshake_gate passed.\n");
}

static void test_llps_yml_rejects_protocol_gate_without_preface(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "protocol_handshake_gate_enabled: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_protocol_gate_without_preface passed.\n");
}

static void test_llps_yml_parses_ip_audit_config(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "ip_audit_enabled: 1\n"
        "ip_audit_path: /tmp/llps-ip-audit-test.pxf\n"
        "audit_mac_enabled: 1\n"
        "audit_mac_key_path: /tmp/llps-audit-test.key\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.ip_audit_enabled == 1u);
    LLPS_TEST_ASSERT(strcmp(cfg.ip_audit_path,
                            "/tmp/llps-ip-audit-test.pxf") == 0);
    LLPS_TEST_ASSERT(cfg.audit_mac_enabled == 1u);
    LLPS_TEST_ASSERT(strcmp(cfg.audit_mac_key_path,
                            "/tmp/llps-audit-test.key") == 0);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_ip_audit_config passed.\n");
}

static void test_llps_yml_rejects_non_pxf_ip_audit_path(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "ip_audit_enabled: 1\n"
        "ip_audit_path: /tmp/llps-ip-audit-test.jsonl\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_SYNTAX);
    LLPS_TEST_ASSERT(error_line == 10u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_non_pxf_ip_audit_path passed.\n");
}

static void test_llps_yml_rejects_audit_mac_without_key(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "ip_audit_enabled: 1\n"
        "ip_audit_path: /tmp/llps-ip-audit-test.pxf\n"
        "audit_mac_enabled: 1\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_REQUIRED);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_audit_mac_without_key passed.\n");
}

static void test_llps_runtime_cfg_rejects_non_pxf_ip_audit_path(void) {
    llps_yml_config_t cfg = test_config();
    int n = 0;

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "/tmp/llps-ip-audit-test.jsonl");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "/tmp/llps-ip-audit-test.pxf");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_non_pxf_ip_audit_path passed.\n");
}

static void test_llps_runtime_cfg_rejects_invalid_audit_mac_config(void) {
    llps_yml_config_t cfg = test_config();
    int n = 0;

    cfg.audit_mac_enabled = 1u;
    n = snprintf(cfg.audit_mac_key_path,
                 sizeof(cfg.audit_mac_key_path),
                 "/tmp/llps-audit-test.key");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.audit_mac_key_path));
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "/tmp/llps-ip-audit-test.pxf");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_invalid_audit_mac_config passed.\n");
}

static void test_llps_runtime_cfg_rejects_invalid_client_ip_cap(void) {
    llps_yml_config_t cfg = test_config();

    cfg.max_sessions_per_client_ip = cfg.max_clients + 1u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.max_sessions_per_client_ip = cfg.max_clients;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_invalid_client_ip_cap passed.\n");
}

static void test_llps_runtime_cfg_rejects_invalid_client_ip_rate(void) {
    llps_yml_config_t cfg = test_config();

    cfg.max_new_sessions_per_client_ip_per_window =
        LLPS_CLIENT_IP_RATE_LIMIT_MAX + 1u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.max_new_sessions_per_client_ip_per_window =
        LLPS_CLIENT_IP_RATE_LIMIT_MAX;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    cfg.client_ip_rate_window_ms =
        LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN - 1u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.client_ip_rate_window_ms =
        LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_invalid_client_ip_rate passed.\n");
}

static void test_llps_runtime_cfg_rejects_invalid_client_preface(void) {
    llps_yml_config_t cfg = test_config();

    cfg.client_preface_timeout_ms =
        LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN - 1u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.client_preface_timeout_ms = 0u;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    cfg.client_preface_timeout_ms = LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_invalid_client_preface passed.\n");
}

static void test_llps_runtime_cfg_rejects_protocol_gate_without_preface(void) {
    llps_yml_config_t cfg = test_config();

    cfg.protocol_handshake_gate_enabled = 1u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    cfg.client_preface_timeout_ms = LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN;
    LLPS_TEST_ASSERT(llps_runtime_cfg_values_are_valid(&cfg));

    cfg.protocol_handshake_gate_enabled = 2u;
    LLPS_TEST_ASSERT(!llps_runtime_cfg_values_are_valid(&cfg));

    printf("test_llps_runtime_cfg_rejects_protocol_gate_without_preface passed.\n");
}

static void test_llps_ip_audit_init_rejects_non_pxf_path(void) {
    llps_yml_config_t cfg = test_config();
    char path[128];
    struct stat st;
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_init_reject_test_%lu.jsonl",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    (void)remove(path);
    LLPS_TEST_ASSERT(!llps_ip_audit_init(&cfg, "10.0.0.8"));
    LLPS_TEST_ASSERT(!llps_ip_audit_enabled());
    LLPS_TEST_ASSERT(stat(path, &st) != 0);

    printf("test_llps_ip_audit_init_rejects_non_pxf_path passed.\n");
}

static void test_llps_ip_audit_init_rejects_missing_mac_key(void) {
    llps_yml_config_t cfg = test_config();
    char audit_path[128];
    char key_path[128];
    int n = 0;

    n = snprintf(audit_path,
                 sizeof(audit_path),
                 "/tmp/llps_ip_audit_missing_mac_key_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(audit_path));

    n = snprintf(key_path,
                 sizeof(key_path),
                 "/tmp/llps_ip_audit_missing_mac_key_%lu.key",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(key_path));

    cfg.ip_audit_enabled = 1u;
    cfg.audit_mac_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 audit_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    n = snprintf(cfg.audit_mac_key_path,
                 sizeof(cfg.audit_mac_key_path),
                 "%s",
                 key_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.audit_mac_key_path));

    (void)remove(audit_path);
    (void)remove(key_path);
    LLPS_TEST_ASSERT(!llps_ip_audit_init(&cfg, "10.0.0.8"));
    LLPS_TEST_ASSERT(!llps_ip_audit_enabled());
    llps_ip_audit_shutdown();
    (void)remove(audit_path);

    printf("test_llps_ip_audit_init_rejects_missing_mac_key passed.\n");
}

static void test_llps_ip_audit_writes_pxf_record_shape(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char line[4096];
    struct stat st;
    int verify_fd = -1;
    FILE *verify_fp = NULL;
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_record_test_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    (void)remove(path);
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));

    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_ACCEPT;
    event.request_no = 77u;
    event.time_ns = 123456789u;
    event.duration_ns = 987u;
    event.session_id = 3u;
    event.client_port = 54321u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.9") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "accepted") > 0);

    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    verify_fd = open(path,
                     O_RDONLY
#ifdef O_NOFOLLOW
                     | O_NOFOLLOW
#endif
                     );
    LLPS_TEST_ASSERT(verify_fd >= 0);
    LLPS_TEST_ASSERT(fstat(verify_fd, &st) == 0);
    verify_fp = fdopen(verify_fd, "r");
    LLPS_TEST_ASSERT(verify_fp != NULL);
    verify_fd = -1;
    LLPS_TEST_ASSERT(fclose(verify_fp) == 0);
    LLPS_TEST_ASSERT((st.st_mode & S_IRUSR) != 0u);
    LLPS_TEST_ASSERT((st.st_mode & S_IRGRP) != 0u);
    LLPS_TEST_ASSERT((st.st_mode & S_IROTH) != 0u);
    LLPS_TEST_ASSERT(strncmp(line, "pxf/1\n", 6u) == 0);
    LLPS_TEST_ASSERT(strstr(line,
                            "@table audit seq:tok request_no:tok "
                            "event:tok event_no:tok total_events:tok") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "@table audit_endpoint seq:tok") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "@table audit_mac seq:tok") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "# ---- llps audit event ----") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "#   request_no: 77") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "#   event: accept") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "#     client: 203.0.113.9:54321") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 1 77 accept 1 1 123456789 3 "
                            "accepted 987 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit_endpoint 1 client "
                            "203.0.113.9 54321") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit_endpoint 1 listen "
                            "127.0.0.1 25565") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit_endpoint 1 target "
                            "127.0.0.1 25566") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit_endpoint 1 backend "
                            "10.0.0.8 25566") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "+audit_mac ") == NULL);
    LLPS_TEST_ASSERT(strstr(line, "PXF/1") == NULL);
    LLPS_TEST_ASSERT(strstr(line, "{\"") == NULL);

    (void)remove(path);

    printf("test_llps_ip_audit_writes_pxf_record_shape passed.\n");
}

static void test_llps_ip_audit_rejects_pxf_token_injection(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char line[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_injection_test_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    (void)remove(path);
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));

    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_ACCEPT;
    event.request_no = 78u;
    event.time_ns = 123456790u;
    event.session_id = 5u;
    event.client_port = 54323u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.11") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "bad\n+audit") > 0);
    LLPS_TEST_ASSERT(!llps_ip_audit_record(&event));

    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "accepted") > 0);
    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    LLPS_TEST_ASSERT(strstr(line, "bad") == NULL);
    LLPS_TEST_ASSERT(strstr(line, "+audit 99") == NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 1 78 accept 1 1 123456790 5 "
                            "accepted 0 0x") != NULL);

    (void)remove(path);

    printf("test_llps_ip_audit_rejects_pxf_token_injection passed.\n");
}

static void test_llps_ip_audit_continues_sequence_when_appending(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char line[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_append_test_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    (void)remove(path);
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));
    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_ACCEPT;
    event.request_no = 1u;
    event.time_ns = 100u;
    event.session_id = 1u;
    event.client_port = 1111u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.1") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "accepted") > 0);
    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));
    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_CLOSE;
    event.request_no = 2u;
    event.time_ns = 200u;
    event.session_id = 2u;
    event.client_port = 2222u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.2") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "closed") > 0);
    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 1 1 accept 1 1 100 1 "
                            "accepted 0 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 2 2 close 1 2 200 2 "
                            "closed 0 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "+audit 1 2 close") == NULL);

    (void)remove(path);

    printf("test_llps_ip_audit_continues_sequence_when_appending passed.\n");
}

static void test_llps_ip_audit_rejects_tampered_existing_crc(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char line[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_tampered_crc_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    (void)remove(path);
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));
    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_ACCEPT;
    event.request_no = 3u;
    event.time_ns = 300u;
    event.session_id = 3u;
    event.client_port = 3333u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.3") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "accepted") > 0);
    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    test_replace_first_text(
        line,
        sizeof(line),
        "+audit_endpoint 1 client 203.0.113.3 3333",
        "+audit_endpoint 1 client 203.0.113.9 3333");
    test_write_text_file(path, line);

    LLPS_TEST_ASSERT(!llps_ip_audit_init(&cfg, "10.0.0.8"));
    LLPS_TEST_ASSERT(!llps_ip_audit_enabled());
    llps_ip_audit_shutdown();
    (void)remove(path);

    printf("test_llps_ip_audit_rejects_tampered_existing_crc passed.\n");
}

static void test_llps_ip_audit_writes_mac_record_when_enabled(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char key_path[128];
    char line[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_mac_test_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    n = snprintf(key_path,
                 sizeof(key_path),
                 "/tmp/llps_ip_audit_mac_key_%lu.key",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(key_path));

    cfg.ip_audit_enabled = 1u;
    cfg.audit_mac_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    n = snprintf(cfg.audit_mac_key_path,
                 sizeof(cfg.audit_mac_key_path),
                 "%s",
                 key_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.audit_mac_key_path));

    (void)remove(path);
    (void)remove(key_path);
    test_write_text_file(key_path, "audit-test-key");
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));

    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_CLOSE;
    event.request_no = 88u;
    event.time_ns = 123456999u;
    event.duration_ns = 77u;
    event.session_id = 4u;
    event.client_port = 54322u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.10") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "closed") > 0);

    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    LLPS_TEST_ASSERT(strstr(line, "@table audit_mac seq:tok") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "#   mac_key_fingerprint: 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "#   hmac_sha256: ") != NULL);
    LLPS_TEST_ASSERT(strstr(line, "+audit_mac 1 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 1 88 close 1 1 123456999 4 "
                            "closed 77 0x") != NULL);

    (void)remove(path);
    (void)remove(key_path);

    printf("test_llps_ip_audit_writes_mac_record_when_enabled passed.\n");
}

static void test_llps_ip_audit_rejects_signed_log_mac_downgrade(void) {
    llps_yml_config_t cfg = test_config();
    llps_ip_audit_event_t event;
    char path[128];
    char key_path[128];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_ip_audit_mac_downgrade_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    n = snprintf(key_path,
                 sizeof(key_path),
                 "/tmp/llps_ip_audit_mac_downgrade_%lu.key",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(key_path));

    cfg.ip_audit_enabled = 1u;
    cfg.audit_mac_enabled = 1u;
    n = snprintf(cfg.ip_audit_path,
                 sizeof(cfg.ip_audit_path),
                 "%s",
                 path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    n = snprintf(cfg.audit_mac_key_path,
                 sizeof(cfg.audit_mac_key_path),
                 "%s",
                 key_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.audit_mac_key_path));

    (void)remove(path);
    (void)remove(key_path);
    test_write_text_file(key_path, "audit-test-key");
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));

    (void)memset(&event, 0, sizeof(event));
    event.type = LLPS_IP_AUDIT_CLOSE;
    event.request_no = 89u;
    event.time_ns = 123457000u;
    event.duration_ns = 78u;
    event.session_id = 5u;
    event.client_port = 54324u;
    LLPS_TEST_ASSERT(snprintf(event.client_ip,
                              sizeof(event.client_ip),
                              "203.0.113.12") > 0);
    LLPS_TEST_ASSERT(snprintf(event.reason,
                              sizeof(event.reason),
                              "closed") > 0);
    LLPS_TEST_ASSERT(llps_ip_audit_record(&event));
    llps_ip_audit_shutdown();

    cfg.audit_mac_enabled = 0u;
    LLPS_TEST_ASSERT(!llps_ip_audit_init(&cfg, "10.0.0.8"));
    LLPS_TEST_ASSERT(!llps_ip_audit_enabled());
    llps_ip_audit_shutdown();
    (void)remove(path);
    (void)remove(key_path);

    printf("test_llps_ip_audit_rejects_signed_log_mac_downgrade passed.\n");
}

static void test_llps_yml_rejects_malformed_dns_host(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: bad_host.example\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_SYNTAX);
    LLPS_TEST_ASSERT(error_line == 5u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_malformed_dns_host passed.\n");
}

static void test_llps_yml_parses_readiness_gate_config(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    uint32_t attestation_fingerprint = 0u;
    const uint32_t observation_digest = 3405691582u;
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         123456789u,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &attestation_fingerprint) == LLPS_OK);
    n = snprintf(text,
                 sizeof(text),
                 "max_clients: 4\n"
                 "buffer_size: 128\n"
                 "listen_host: 127.0.0.1\n"
                 "listen_port: 25565\n"
                 "target_ip: 127.0.0.1\n"
                 "target_port: 25566\n"
                 "listen_backlog: 4\n"
                 "accept_batch_max: 2\n"
                 "require_readiness: 1\n"
                 "platform_safety_flags: %u\n"
                 "platform_safety_evidence_id: 123456789\n"
                 "platform_attestation_fingerprint: %u\n"
                 "platform_observation_digest: %u\n"
                 "phys_mem_domain0: 11\n"
                 "phys_mem_domain1: 22\n"
                 "phys_mem_domain2: 33\n"
                 "hw_tmr_domain0: 101\n"
                 "hw_tmr_domain1: 202\n"
                 "hw_tmr_domain2: 303\n"
                 "hw_tmr_voter_domain: 404\n",
                 (unsigned)LLPS_PLATFORM_EVIDENCE_REQUIRED,
                 (unsigned)attestation_fingerprint,
                 (unsigned)observation_digest);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.require_readiness == 1u);
    LLPS_TEST_ASSERT(cfg.platform_safety_flags ==
                     LLPS_PLATFORM_EVIDENCE_REQUIRED);
    LLPS_TEST_ASSERT(cfg.platform_safety_evidence_id == 123456789u);
    LLPS_TEST_ASSERT(cfg.platform_attestation_fingerprint ==
                     attestation_fingerprint);
    LLPS_TEST_ASSERT(cfg.platform_observation_digest == observation_digest);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[0] == 11u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[1] == 22u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[2] == 33u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[0] == 101u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[1] == 202u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_domains[2] == 303u);
    LLPS_TEST_ASSERT(cfg.platform_hardware_tmr_voter_domain == 404u);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_readiness_gate_config passed.\n");
}

static void test_llps_yml_parses_software_platform_evidence_config(void) {
    char path[128];
    char text[1024];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    uint32_t attestation_fingerprint = 0u;
    const uint32_t flags = LLPS_PLATFORM_EVIDENCE_ECC_MEMORY |
                           LLPS_PLATFORM_EVIDENCE_ECC_CLEAN |
                           LLPS_PLATFORM_EVIDENCE_PHYS_SEP;
    const uint32_t zero_domains[LLPS_SESSION_TMR_BANK_COUNT] =
        { 0u, 0u, 0u };
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         flags,
                         123456789u,
                         test_physical_memory_domains,
                         zero_domains,
                         0u,
                         &attestation_fingerprint) == LLPS_OK);
    n = snprintf(text,
                 sizeof(text),
                 "max_clients: 4\n"
                 "buffer_size: 128\n"
                 "listen_host: 127.0.0.1\n"
                 "listen_port: 25565\n"
                 "target_ip: 127.0.0.1\n"
                 "target_port: 25566\n"
                 "listen_backlog: 4\n"
                 "accept_batch_max: 2\n"
                 "payload_ecc_enabled: 1\n"
                 "platform_safety_flags: %u\n"
                 "platform_safety_evidence_id: 123456789\n"
                 "platform_attestation_fingerprint: %u\n"
                 "platform_evidence_mode: hybrid\n"
                 "phys_mem_domain0: 11\n"
                 "phys_mem_domain1: 22\n"
                 "phys_mem_domain2: 33\n"
                 "software_ecc_enabled: 1\n"
                 "software_ecc_controller_count: 2\n"
                 "software_ecc_dimm_count: 4\n"
                 "software_ecc_scrub_rate: 8192\n"
                 "software_ecc_controller_corrected_error_count: 7\n"
                 "software_ecc_controller_uncorrected_error_count: 0\n"
                 "software_ecc_dimm_corrected_error_count: 3\n"
                 "software_ecc_dimm_uncorrected_error_count: 0\n"
                 "software_numa_enabled: 1\n"
                 "software_numa_memtotal_kib: 65536\n"
                 "software_numa_local_distance: 12\n"
                 "software_numa_remote_distance: 24\n"
                 "software_fault_injection_mode: full\n",
                 (unsigned)flags,
                 (unsigned)attestation_fingerprint);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(cfg.platform_safety_flags == flags);
    LLPS_TEST_ASSERT(cfg.platform_safety_evidence_id == 123456789u);
    LLPS_TEST_ASSERT(cfg.platform_attestation_fingerprint ==
                     attestation_fingerprint);
    LLPS_TEST_ASSERT(cfg.platform_evidence_mode ==
                     LLPS_PLATFORM_EVIDENCE_MODE_HYBRID);
    LLPS_TEST_ASSERT(cfg.payload_ecc_enabled == 1u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[0] == 11u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[1] == 22u);
    LLPS_TEST_ASSERT(cfg.platform_physical_memory_domains[2] == 33u);
    LLPS_TEST_ASSERT(cfg.software_ecc_enabled == 1u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_count == 2u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_count == 4u);
    LLPS_TEST_ASSERT(cfg.software_ecc_scrub_rate == 8192u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_corrected_error_count == 7u);
    LLPS_TEST_ASSERT(cfg.software_ecc_controller_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_corrected_error_count == 3u);
    LLPS_TEST_ASSERT(cfg.software_ecc_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(cfg.software_numa_enabled == 1u);
    LLPS_TEST_ASSERT(cfg.software_numa_memtotal_kib == 65536u);
    LLPS_TEST_ASSERT(cfg.software_numa_local_distance == 12u);
    LLPS_TEST_ASSERT(cfg.software_numa_remote_distance == 24u);
    LLPS_TEST_ASSERT(cfg.software_fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_FULL);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_parses_software_platform_evidence_config passed.\n");
}

static void
test_llps_yml_rejects_software_ecc_readiness_without_payload_ecc(void) {
    char path[128];
    char text[768];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    uint32_t attestation_fingerprint = 0u;
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         123456789u,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &attestation_fingerprint) == LLPS_OK);
    n = snprintf(text,
                 sizeof(text),
                 "max_clients: 4\n"
                 "buffer_size: 128\n"
                 "listen_host: 127.0.0.1\n"
                 "listen_port: 25565\n"
                 "target_ip: 127.0.0.1\n"
                 "target_port: 25566\n"
                 "listen_backlog: 4\n"
                 "accept_batch_max: 2\n"
                 "require_readiness: 1\n"
                 "platform_safety_flags: %u\n"
                 "platform_safety_evidence_id: 123456789\n"
                 "platform_attestation_fingerprint: %u\n"
                 "platform_evidence_mode: hybrid\n"
                 "phys_mem_domain0: 11\n"
                 "phys_mem_domain1: 22\n"
                 "phys_mem_domain2: 33\n"
                 "hw_tmr_domain0: 101\n"
                 "hw_tmr_domain1: 202\n"
                 "hw_tmr_domain2: 303\n"
                 "hw_tmr_voter_domain: 404\n"
                 "software_ecc_enabled: 1\n"
                 "software_ecc_controller_count: 1\n"
                 "software_ecc_dimm_count: 4\n"
                 "software_ecc_scrub_rate: 4096\n",
                 (unsigned)LLPS_PLATFORM_EVIDENCE_REQUIRED,
                 (unsigned)attestation_fingerprint);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_software_ecc_readiness_without_payload_ecc passed.\n");
}

static void test_llps_yml_rejects_software_ecc_without_scrub_rate(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "payload_ecc_enabled: 1\n"
        "platform_evidence_mode: hybrid\n"
        "software_ecc_enabled: 1\n"
        "software_ecc_controller_count: 1\n"
        "software_ecc_dimm_count: 4\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_software_ecc_without_scrub_rate passed.\n");
}

static void test_llps_yml_rejects_software_ecc_without_controller_count(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "payload_ecc_enabled: 1\n"
        "platform_evidence_mode: hybrid\n"
        "software_ecc_enabled: 1\n"
        "software_ecc_dimm_count: 4\n"
        "software_ecc_scrub_rate: 4096\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_software_ecc_without_controller_count passed.\n");
}

static void test_llps_yml_rejects_software_ecc_controller_over_dimm_count(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "payload_ecc_enabled: 1\n"
        "platform_evidence_mode: hybrid\n"
        "software_ecc_enabled: 1\n"
        "software_ecc_controller_count: 5\n"
        "software_ecc_dimm_count: 4\n"
        "software_ecc_scrub_rate: 4096\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_software_ecc_controller_over_dimm_count passed.\n");
}

static void test_llps_yml_rejects_software_numa_without_phys_sep(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "software_numa_enabled: 1\n"
        "software_numa_memtotal_kib: 65536\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_software_numa_without_phys_sep passed.\n");
}

static void test_llps_yml_rejects_invalid_software_numa_distance(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "platform_safety_flags: 4\n"
        "platform_evidence_mode: hybrid\n"
        "phys_mem_domain0: 11\n"
        "phys_mem_domain1: 22\n"
        "phys_mem_domain2: 33\n"
        "software_numa_enabled: 1\n"
        "software_numa_memtotal_kib: 65536\n"
        "software_numa_local_distance: 30\n"
        "software_numa_remote_distance: 20\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(error_line == 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_software_numa_distance passed.\n");
}

static void test_llps_yml_rejects_invalid_software_fault_injection_mode(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "software_fault_injection_mode: triple\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_SYNTAX);
    LLPS_TEST_ASSERT(error_line == 9u);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_invalid_software_fault_injection_mode passed.\n");
}

static void test_llps_yml_rejects_required_readiness_without_full_evidence(void) {
    char path[128];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const char * const text =
        "max_clients: 4\n"
        "buffer_size: 128\n"
        "listen_host: 127.0.0.1\n"
        "listen_port: 25565\n"
        "target_ip: 127.0.0.1\n"
        "target_port: 25566\n"
        "listen_backlog: 4\n"
        "accept_batch_max: 2\n"
        "require_readiness: 1\n"
        "platform_safety_flags: 1\n"
        "platform_safety_evidence_id: 0\n";

    reset_mocks();
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_required_readiness_without_full_evidence passed.\n");
}

static void test_llps_yml_attestation_loader_allows_generation_config(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    uint32_t fingerprint = 0u;
    const int n = snprintf(text,
                           sizeof(text),
                           "max_clients: 4\n"
                           "buffer_size: 128\n"
                           "listen_host: 127.0.0.1\n"
                           "listen_port: 25565\n"
                           "target_ip: 127.0.0.1\n"
                           "target_port: 25566\n"
                           "listen_backlog: 4\n"
                           "accept_batch_max: 2\n"
                           "require_readiness: 1\n"
                           "platform_safety_flags: %u\n"
                           "platform_safety_evidence_id: 123456789\n"
                           "platform_attestation_fingerprint: 0\n"
                           "phys_mem_domain0: 11\n"
                           "phys_mem_domain1: 22\n"
                           "phys_mem_domain2: 33\n"
                           "hw_tmr_domain0: 101\n"
                           "hw_tmr_domain1: 202\n"
                           "hw_tmr_domain2: 303\n"
                           "hw_tmr_voter_domain: 404\n",
                           (unsigned)LLPS_PLATFORM_EVIDENCE_REQUIRED);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(llps_yml_load_config_for_attestation_ex(path,
                                                            &cfg,
                                                            &error_line) ==
                     LLPS_YML_OK);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &fingerprint) == LLPS_OK);
    LLPS_TEST_ASSERT(fingerprint != 0u);
    test_remove_config_file(path);

    printf("test_llps_yml_attestation_loader_allows_generation_config passed.\n");
}

static void test_llps_yml_rejects_readiness_duplicate_domains(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const int n = snprintf(text,
                           sizeof(text),
                           "max_clients: 4\n"
                           "buffer_size: 128\n"
                           "listen_host: 127.0.0.1\n"
                           "listen_port: 25565\n"
                           "target_ip: 127.0.0.1\n"
                           "target_port: 25566\n"
                           "listen_backlog: 4\n"
                           "accept_batch_max: 2\n"
                           "require_readiness: 1\n"
                           "platform_safety_flags: %u\n"
                           "platform_safety_evidence_id: 987654321\n"
                           "phys_mem_domain0: 11\n"
                           "phys_mem_domain1: 11\n"
                           "phys_mem_domain2: 33\n"
                           "hw_tmr_domain0: 101\n"
                           "hw_tmr_domain1: 202\n"
                           "hw_tmr_domain2: 303\n"
                           "hw_tmr_voter_domain: 404\n",
                           (unsigned)LLPS_PLATFORM_EVIDENCE_REQUIRED);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_readiness_duplicate_domains passed.\n");
}

static void test_llps_yml_rejects_readiness_overlapping_domain_sets(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const int n = snprintf(text,
                           sizeof(text),
                           "max_clients: 4\n"
                           "buffer_size: 128\n"
                           "listen_host: 127.0.0.1\n"
                           "listen_port: 25565\n"
                           "target_ip: 127.0.0.1\n"
                           "target_port: 25566\n"
                           "listen_backlog: 4\n"
                           "accept_batch_max: 2\n"
                           "require_readiness: 1\n"
                           "platform_safety_flags: %u\n"
                           "platform_safety_evidence_id: 987654321\n"
                           "phys_mem_domain0: 11\n"
                           "phys_mem_domain1: 22\n"
                           "phys_mem_domain2: 33\n"
                           "hw_tmr_domain0: 11\n"
                           "hw_tmr_domain1: 202\n"
                           "hw_tmr_domain2: 303\n"
                           "hw_tmr_voter_domain: 404\n",
                           (unsigned)LLPS_PLATFORM_EVIDENCE_REQUIRED);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(llps_yml_load_config_for_attestation_ex(path,
                                                            &cfg,
                                                            &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_readiness_overlapping_domain_sets passed.\n");
}

static void test_llps_yml_rejects_unused_external_domain_ids(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const int n = snprintf(text,
                           sizeof(text),
                           "max_clients: 4\n"
                           "buffer_size: 128\n"
                           "listen_host: 127.0.0.1\n"
                           "listen_port: 25565\n"
                           "target_ip: 127.0.0.1\n"
                           "target_port: 25566\n"
                           "listen_backlog: 4\n"
                           "accept_batch_max: 2\n"
                           "require_readiness: 0\n"
                           "platform_safety_flags: %u\n"
                           "platform_safety_evidence_id: 987654321\n"
                           "phys_mem_domain0: 11\n"
                           "phys_mem_domain1: 22\n"
                           "phys_mem_domain2: 33\n"
                           "hw_tmr_domain0: 101\n"
                           "hw_tmr_domain1: 202\n"
                           "hw_tmr_domain2: 303\n"
                           "hw_tmr_voter_domain: 404\n",
                           (unsigned)LLPS_PLATFORM_EVIDENCE_HW_TMR);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(llps_yml_load_config_for_attestation_ex(path,
                                                            &cfg,
                                                            &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_unused_external_domain_ids passed.\n");
}

static void test_llps_yml_rejects_missing_hw_tmr_voter_domain(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    const int n = snprintf(text,
                           sizeof(text),
                           "max_clients: 4\n"
                           "buffer_size: 128\n"
                           "listen_host: 127.0.0.1\n"
                           "listen_port: 25565\n"
                           "target_ip: 127.0.0.1\n"
                           "target_port: 25566\n"
                           "listen_backlog: 4\n"
                           "accept_batch_max: 2\n"
                           "require_readiness: 0\n"
                           "platform_safety_flags: %u\n"
                           "platform_safety_evidence_id: 987654321\n"
                           "hw_tmr_domain0: 101\n"
                           "hw_tmr_domain1: 202\n"
                           "hw_tmr_domain2: 303\n",
                           (unsigned)LLPS_PLATFORM_EVIDENCE_HW_TMR);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(llps_yml_load_config_for_attestation_ex(path,
                                                            &cfg,
                                                            &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_missing_hw_tmr_voter_domain passed.\n");
}

static void test_llps_yml_rejects_hw_tmr_voter_domain_overlap(void) {
    char path[128];
    char text[640];
    llps_yml_config_t cfg;
    uint32_t error_line = 0u;
    int n = snprintf(text,
                     sizeof(text),
                     "max_clients: 4\n"
                     "buffer_size: 128\n"
                     "listen_host: 127.0.0.1\n"
                     "listen_port: 25565\n"
                     "target_ip: 127.0.0.1\n"
                     "target_port: 25566\n"
                     "listen_backlog: 4\n"
                     "accept_batch_max: 2\n"
                     "require_readiness: 0\n"
                     "platform_safety_flags: %u\n"
                     "platform_safety_evidence_id: 987654321\n"
                     "hw_tmr_domain0: 101\n"
                     "hw_tmr_domain1: 202\n"
                     "hw_tmr_domain2: 303\n"
                     "hw_tmr_voter_domain: 101\n",
                     (unsigned)LLPS_PLATFORM_EVIDENCE_HW_TMR);

    reset_mocks();
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    n = snprintf(text,
                 sizeof(text),
                 "max_clients: 4\n"
                 "buffer_size: 128\n"
                 "listen_host: 127.0.0.1\n"
                 "listen_port: 25565\n"
                 "target_ip: 127.0.0.1\n"
                 "target_port: 25566\n"
                 "listen_backlog: 4\n"
                 "accept_batch_max: 2\n"
                 "require_readiness: 0\n"
                 "platform_safety_flags: %u\n"
                 "platform_safety_evidence_id: 987654322\n"
                 "phys_mem_domain0: 11\n"
                 "phys_mem_domain1: 22\n"
                 "phys_mem_domain2: 33\n"
                 "hw_tmr_domain0: 101\n"
                 "hw_tmr_domain1: 202\n"
                 "hw_tmr_domain2: 303\n"
                 "hw_tmr_voter_domain: 22\n",
                 (unsigned)LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(text));
    test_write_config_file(text, path, sizeof(path));
    LLPS_TEST_ASSERT(llps_yml_load_config_ex(path, &cfg, &error_line) ==
                     LLPS_YML_E_RANGE);
    LLPS_TEST_ASSERT(llps_yml_load_config_for_attestation_ex(path,
                                                            &cfg,
                                                            &error_line) ==
                     LLPS_YML_E_RANGE);
    test_remove_config_file(path);

    printf("test_llps_yml_rejects_hw_tmr_voter_domain_overlap passed.\n");
}

int __wrap_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    ++mock_socket_calls;
    return mock_socket_ret;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)fd;
    (void)addr;
    (void)len;
    return mock_bind_ret;
}

int __wrap_listen(int fd, int backlog) {
    (void)fd;
    (void)backlog;
    return mock_listen_ret;
}

int __wrap_fcntl(int fd, int cmd, ...) {
    (void)fd;
    if (cmd == F_GETFL) {
        return mock_fcntl_getfl_ret;
    }
    return mock_fcntl_ret;
}

int __wrap_mlockall(int flags) {
    (void)flags;
    ++mock_mlockall_calls;
    return mock_mlockall_ret;
}

int __wrap_mlock(const void *addr, size_t len) {
    (void)addr;
    (void)len;
    ++mock_mlock_calls;
    return mock_mlock_ret;
}

int __wrap_madvise(void *addr, size_t len, int advice) {
    (void)addr;
    (void)len;
    (void)advice;
    ++mock_madvise_calls;
    return mock_madvise_ret;
}

int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    const uint32_t call_no = mock_accept_calls;
    int ret_fd = mock_accept_ret;

    (void)fd;
    ++mock_accept_calls;
    if (mock_accept_successes_remaining > 0u) {
        if (ret_fd < 0) {
            ret_fd = 600;
        }
        if ((addr != NULL) && (addrlen != NULL) &&
            (*addrlen >= (socklen_t)sizeof(struct sockaddr_in))) {
            struct sockaddr_in sin;
            (void)memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port =
                htons((uint16_t)(mock_accept_next_port + call_no));
            sin.sin_addr.s_addr = htonl(mock_accept_ipv4_addr);
            (void)memcpy(addr, &sin, sizeof(sin));
            *addrlen = (socklen_t)sizeof(sin);
        } else if (addrlen != NULL) {
            *addrlen = 0u;
        }
        --mock_accept_successes_remaining;
        return ret_fd + (int)call_no;
    }
    if (mock_accept_ret < 0) {
        errno = mock_accept_errno_value;
    }
    return mock_accept_ret;
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)fd;
    (void)addr;
    (void)len;
    if (mock_connect_ret < 0) {
        errno = mock_connect_errno_value;
    }
    return mock_connect_ret;
}

int __wrap_getsockopt(int fd,
                      int level,
                      int optname,
                      void *optval,
                      socklen_t *optlen) {
    (void)fd;
    (void)level;
    (void)optlen;
    if (optname == SO_ERROR) {
        *(int *)optval = mock_getsockopt_so_error;
    }
    return 0;
}

int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void *optval,
                      socklen_t optlen) {
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

int __wrap_inet_pton(int af, const char *src, void *dst) {
    bool numeric_or_dot = true;

    if ((af != AF_INET) || (src == NULL) || (dst == NULL)) {
        return 0;
    }

    for (size_t i = 0u; src[i] != '\0'; ++i) {
        if (((src[i] < '0') || (src[i] > '9')) && (src[i] != '.')) {
            numeric_or_dot = false;
            break;
        }
    }

    if (!numeric_or_dot) {
        return 0;
    }

    ((struct in_addr *)dst)->s_addr = htonl(0x7f000001u);
    return 1;
}

int __wrap_getaddrinfo(const char *node,
                       const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    (void)hints;
    ++mock_getaddrinfo_calls;

    if (node != NULL) {
        (void)snprintf(mock_getaddrinfo_node,
                       sizeof(mock_getaddrinfo_node),
                       "%s",
                       node);
    }
    if (service != NULL) {
        (void)snprintf(mock_getaddrinfo_service,
                       sizeof(mock_getaddrinfo_service),
                       "%s",
                       service);
    }

    if (mock_getaddrinfo_ret != 0) {
        return mock_getaddrinfo_ret;
    }

    if (res == NULL) {
        return EAI_FAIL;
    }

    (void)memset(&mock_getaddrinfo_addr, 0, sizeof(mock_getaddrinfo_addr));
    mock_getaddrinfo_addr.sin_family = AF_INET;
    mock_getaddrinfo_addr.sin_port = htons(25566u);
    mock_getaddrinfo_addr.sin_addr.s_addr = htonl(0x7f000001u);

    (void)memset(&mock_getaddrinfo_result,
                 0,
                 sizeof(mock_getaddrinfo_result));
    mock_getaddrinfo_result.ai_family = AF_INET;
    mock_getaddrinfo_result.ai_socktype = SOCK_STREAM;
    mock_getaddrinfo_result.ai_protocol = IPPROTO_TCP;
    mock_getaddrinfo_result.ai_addr =
        (struct sockaddr *)&mock_getaddrinfo_addr;
    mock_getaddrinfo_result.ai_addrlen =
        (socklen_t)sizeof(mock_getaddrinfo_addr);

    *res = &mock_getaddrinfo_result;
    return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *res) {
    (void)res;
    ++mock_freeaddrinfo_calls;
}

ssize_t __wrap_read(int fd, void *buf, size_t len) {
    (void)fd;
    ++mock_read_calls;

    if (mock_read_calls > mock_read_eof_after_calls) {
        return 0;
    }

    if (mock_read_ret < 0) {
        errno = mock_read_errno_value;
        return mock_read_ret;
    }

    if (mock_read_data_off < mock_read_data_len) {
        size_t copy_len = mock_read_data_len - mock_read_data_off;
        if ((mock_read_chunk_max != 0u) && (copy_len > mock_read_chunk_max)) {
            copy_len = mock_read_chunk_max;
        }
        if (copy_len > len) {
            copy_len = len;
        }
        if ((buf != NULL) && (copy_len > 0u)) {
            (void)memcpy(buf,
                         &mock_read_data[mock_read_data_off],
                         copy_len);
        }
        mock_read_data_off += copy_len;
        return (ssize_t)copy_len;
    }

    if ((buf != NULL) && (mock_read_ret > 0)) {
        size_t copy_len = (size_t)mock_read_ret;
        const ssize_t reported_len = mock_read_ret;

        if (copy_len > len) {
            copy_len = len;
        }
        (void)memset(buf, 'A', copy_len);
        return mock_read_return_unbounded ? reported_len : (ssize_t)copy_len;
    }

    return mock_read_ret;
}

ssize_t __wrap_llam_read_when_ready(int fd,
                                    void *buf,
                                    size_t len,
                                    int timeout_ms) {
    ++mock_llam_read_when_ready_calls;
    mock_llam_read_when_ready_last_timeout_ms = timeout_ms;
    if (mock_sleep_requests_shutdown) {
        llps_control_request_shutdown();
    }
    if (mock_llam_read_when_ready_delegates_read) {
        return __wrap_read(fd, buf, len);
    }
    if (mock_llam_read_when_ready_ret < 0) {
        errno = mock_llam_read_when_ready_errno_value;
    }
    return mock_llam_read_when_ready_ret;
}

ssize_t __wrap_write(int fd, const void *buf, size_t len) {
    (void)fd;
    (void)buf;
    (void)len;
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    size_t accepted_len = 0u;
    size_t remaining = 0u;
    size_t copy_len = 0u;

    (void)fd;
    (void)flags;
    ++mock_send_calls;
    mock_send_last_len = len;

    if (mock_send_ret < 0) {
        errno = mock_send_errno_value;
        return mock_send_ret;
    }

    accepted_len = (size_t)mock_send_ret;
    if (accepted_len > len) {
        accepted_len = len;
    }
    if ((buf != NULL) && (accepted_len > 0u) &&
        (mock_send_capture_len < sizeof(mock_send_capture))) {
        remaining = sizeof(mock_send_capture) - mock_send_capture_len;
        copy_len = accepted_len;
        if (copy_len > remaining) {
            copy_len = remaining;
        }
        (void)memcpy(&mock_send_capture[mock_send_capture_len], buf, copy_len);
        mock_send_capture_len += copy_len;
    }

    return mock_send_ret;
}

int __wrap_close(int fd) {
    (void)fd;
    return 0;
}

int __wrap_shutdown(int fd, int how) {
    (void)fd;
    (void)how;
    ++mock_shutdown_calls;
    return 0;
}

uint64_t __wrap_llam_now_ns(void) {
    return mock_llam_now_ns;
}

int __wrap_llam_sleep_ns(uint64_t duration_ns) {
    (void)duration_ns;
    if (mock_sleep_requests_shutdown) {
        llps_control_request_shutdown();
    }
    return mock_llam_sleep_ns_ret;
}

void __wrap_llam_yield(void) {
}

int __wrap_llam_poll_fd(int fd, short events, int timeout_ms, short *revents) {
    (void)fd;
    (void)events;
    (void)timeout_ms;
    if (revents != NULL) {
        *revents = mock_llam_poll_fd_revents;
    }
    if (mock_sleep_requests_shutdown) {
        llps_control_request_shutdown();
    }
    return mock_llam_poll_fd_ret;
}

llam_task_t *__wrap_llam_spawn(llam_task_fn fn,
                               void *arg,
                               const llam_spawn_opts_t *opts) {
    (void)fn;
    (void)arg;
    (void)opts;
    return (llam_task_t *)(uintptr_t)1u;
}

int __wrap_llam_detach(llam_task_t *task) {
    (void)task;
    return mock_llam_detach_ret;
}

llam_task_group_t *__wrap_llam_task_group_create(void) {
    return (llam_task_group_t *)(uintptr_t)1u;
}

llam_task_t *__wrap_llam_task_group_spawn(llam_task_group_t *group,
                                          llam_task_fn fn,
                                          void *arg,
                                          const llam_spawn_opts_t *opts) {
    (void)group;
    (void)fn;
    (void)opts;
    ++mock_task_group_spawn_calls;
    if (mock_task_group_spawn_checks_session_integrity) {
        const llps_pump_args_t * const pump = (const llps_pump_args_t *)arg;

        if ((pump == NULL) || !llps_session_is_active(pump->session)) {
            mock_task_group_spawn_saw_active_session = false;
        }
    }
    return (llam_task_t *)(uintptr_t)1u;
}

int __wrap_llam_task_group_join(llam_task_group_t *group) {
    (void)group;
    return 0;
}

int __wrap_llam_task_group_destroy(llam_task_group_t *group) {
    (void)group;
    return 0;
}

static llam_runtime_stats_t test_valid_single_worker_llam_stats(void) {
    llam_runtime_stats_t stats;

    (void)memset(&stats, 0, sizeof(stats));
    stats.active_workers = 1u;
    stats.online_workers = 1u;
    stats.online_workers_floor = 1u;
    stats.online_workers_min = 1u;
    stats.online_workers_max = 1u;
    stats.active_nodes = 1u;
    return stats;
}

static void test_llps_task_budget_reserves_readiness_monitor_task(void) {
    LLPS_TEST_ASSERT(LLPS_READINESS_MONITOR_TASKS == 1u);
    LLPS_TEST_ASSERT(
        LLPS_MAX_TASKS_REQUIRED ==
        (LLPS_MAX_SESSION_TASKS +
         LLPS_MAX_SERVER_TASKS +
         LLPS_WATCHDOG_TASKS +
         LLPS_READINESS_MONITOR_TASKS));
    LLPS_TEST_ASSERT(
        LLPS_MAX_TASKS_REQUIRED ==
        ((LLPS_MAX_CLIENTS * LLPS_TASKS_PER_SESSION) + 3u));

    printf("test_llps_task_budget_reserves_readiness_monitor_task passed.\n");
}

static void test_llps_llam_runtime_policy_rejects_worker_fanout(void) {
    llam_runtime_stats_t stats = test_valid_single_worker_llam_stats();

    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(NULL));
    LLPS_TEST_ASSERT(
        llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.active_workers = 2u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.online_workers = 2u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.online_workers_floor = 2u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.online_workers_min = 0u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.online_workers_max = 2u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.active_nodes = 2u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.dynamic_workers = 1u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.worker_rings = 1u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.worker_rings_multishot = 1u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.lockfree_normq = 1u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    stats = test_valid_single_worker_llam_stats();
    stats.sqpoll = 1u;
    LLPS_TEST_ASSERT(
        !llps_llam_runtime_stats_satisfy_single_worker_contract(&stats));

    printf("test_llps_llam_runtime_policy_rejects_worker_fanout passed.\n");
}

static void test_llps_llam_now_contract_rejects_zero_tick(void) {
    const llps_yml_config_t cfg = test_config();
    uint64_t previous_contract_violations = 0u;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    previous_contract_violations =
        g_memory_safety_counters.contract_violations;
    mock_llam_now_ns = 0u;
    llps_session_prepare_active(sess, sess_idx, 460);

    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations ==
                     (previous_contract_violations + 1u));
    LLPS_TEST_ASSERT(sess->last_activity_ns == 0u);
    LLPS_TEST_ASSERT(llps_session_is_active(sess));

    printf("test_llps_llam_now_contract_rejects_zero_tick passed.\n");
}

static void test_llps_llam_checked_wrappers_reject_bad_args(void) {
    const llps_yml_config_t cfg = test_config();
    llam_spawn_opts_t opts;
    short revents = 0;
    uint64_t previous_contract_violations = 0u;
    uint64_t now_ns = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(
        llps_llam_spawn_opts_prepare(&opts,
                                     LLAM_TASK_CLASS_DEFAULT,
                                     0u));
    previous_contract_violations =
        g_memory_safety_counters.contract_violations;

    LLPS_TEST_ASSERT(!llps_llam_spawn_opts_prepare(NULL,
                                                   LLAM_TASK_CLASS_DEFAULT,
                                                   0u));
    LLPS_TEST_ASSERT(llps_llam_poll_fd_checked(LLPS_INVALID_FD,
                                               POLLIN,
                                               0,
                                               &revents,
                                               "bad_poll") < 0);
    LLPS_TEST_ASSERT(llps_llam_read_when_ready_checked(
                         LLPS_INVALID_FD,
                         &revents,
                         sizeof(revents),
                         0,
                         "bad_read_ready") < 0);
    LLPS_TEST_ASSERT(!llps_llam_sleep_ms_checked(1, NULL));
    LLPS_TEST_ASSERT(llps_llam_spawn_checked(NULL,
                                             NULL,
                                             &opts,
                                             "bad_spawn") == NULL);
    LLPS_TEST_ASSERT(!llps_llam_detach_checked(NULL, "bad_detach"));
    LLPS_TEST_ASSERT(llps_llam_task_group_create_checked(NULL) == NULL);
    LLPS_TEST_ASSERT(!llps_llam_task_group_join_checked(
        NULL,
        "bad_group_join"));
    LLPS_TEST_ASSERT(llps_llam_task_group_spawn_checked(
                         NULL,
                         llps_task_watchdog,
                         NULL,
                         &opts,
                         "bad_group_spawn") == NULL);
    LLPS_TEST_ASSERT(!llps_llam_task_group_destroy_checked(
        NULL,
        "bad_group_destroy"));
    now_ns = llps_llam_now_ns_checked(NULL);
    LLPS_TEST_ASSERT(now_ns == mock_llam_now_ns);

    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations >=
                     (previous_contract_violations + 11u));

    printf("test_llps_llam_checked_wrappers_reject_bad_args passed.\n");
}

static void test_llps_init_sets_integrity_guards(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(g_free_sessions_count == cfg.max_clients);
    LLPS_TEST_ASSERT(llps_session_is_free(&g_sessions[0]));
    LLPS_TEST_ASSERT(g_sessions[0].magic_start == LLPS_SESSION_MAGIC_FREE);
    LLPS_TEST_ASSERT(g_sessions[0].magic_end == LLPS_SESSION_MAGIC_FREE);
    LLPS_TEST_ASSERT(g_sessions[0].state_inverse == llps_state_inverse_value(ST_FREE));
    LLPS_TEST_ASSERT(g_sessions[0].integrity_crc == llps_session_compute_crc(&g_sessions[0]));
    LLPS_TEST_ASSERT(g_sessions[0].integrity_crc_inverse ==
                     ~g_sessions[0].integrity_crc);
    LLPS_TEST_ASSERT(g_process_memory_locked);
    LLPS_TEST_ASSERT(g_tmr_memory_locked);
    LLPS_TEST_ASSERT(g_tmr_memory_prefaulted);
    LLPS_TEST_ASSERT(g_tmr_memory_prefault_pages >= 12u);
    LLPS_TEST_ASSERT(llps_tmr_memory_prefault_pages_is_valid());
    LLPS_TEST_ASSERT(g_tmr_memory_hardened);
    LLPS_TEST_ASSERT(g_tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(llps_runtime_safety_latches_are_valid());
    LLPS_TEST_ASSERT(llps_tmr_startup_self_test_coverage_is_valid());
    LLPS_TEST_ASSERT(g_tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(mock_mlockall_calls == 1u);
    LLPS_TEST_ASSERT(mock_mlock_calls == 12u);
    LLPS_TEST_ASSERT(mock_madvise_calls == 36u);
    LLPS_TEST_ASSERT(llps_session_tmr_layout_is_valid());
    LLPS_TEST_ASSERT(llps_tmr_metadata_layout_is_valid());
    LLPS_TEST_ASSERT(llps_session_tmr_region_guard_is_valid(0u));
    LLPS_TEST_ASSERT(llps_session_tmr_region_guard_is_valid(1u));
    LLPS_TEST_ASSERT(llps_session_tmr_region_guard_is_valid(2u));
    LLPS_TEST_ASSERT(g_session_tmr_region0.pre_guard_pad[17] ==
                     llps_session_tmr_guard_byte(0u, 17u, false));
    LLPS_TEST_ASSERT(g_session_tmr_region1.post_guard_pad[19] ==
                     llps_session_tmr_guard_byte(1u, 19u, true));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        llps_session_tmr_record_cref(0u, 0u), 0u, 0u));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        llps_session_tmr_record_cref(1u, 0u), 1u, 0u));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        llps_session_tmr_record_cref(2u, 0u), 2u, 0u));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank1, 1u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank2, 2u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank1, 1u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank2, 2u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank1, 1u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank2, 2u));
    LLPS_TEST_ASSERT(!llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.runtime_cfg_tmr_valid);
    LLPS_TEST_ASSERT(report.control_flag_tmr_valid);
    LLPS_TEST_ASSERT(report.free_list_tmr_valid);
    LLPS_TEST_ASSERT(!report.shutdown_requested);
    LLPS_TEST_ASSERT(report.tmr_layout_valid);
    LLPS_TEST_ASSERT(report.process_memory_locked);
    LLPS_TEST_ASSERT(report.tmr_memory_locked);
    LLPS_TEST_ASSERT(report.tmr_memory_prefaulted);
    LLPS_TEST_ASSERT(report.tmr_memory_prefault_pages_valid);
    LLPS_TEST_ASSERT(report.tmr_memory_prefault_pages >= 12u);
    LLPS_TEST_ASSERT(report.tmr_memory_resident);
    LLPS_TEST_ASSERT(report.tmr_memory_resident_pages >= 12u);
    LLPS_TEST_ASSERT(report.tmr_memory_residency_failures == 0u);
    LLPS_TEST_ASSERT(report.tmr_memory_physical_frame_faults == 0u);
    LLPS_TEST_ASSERT(report.tmr_memory_residency_fingerprint != 0u);
    LLPS_TEST_ASSERT(report.tmr_memory_hardened);
    LLPS_TEST_ASSERT(report.tmr_scrub_passes >= 1u);
    LLPS_TEST_ASSERT(report.tmr_scrub_sessions_checked >= cfg.max_clients);
    LLPS_TEST_ASSERT(report.tmr_scrub_fail_closed_sessions == 0u);
    LLPS_TEST_ASSERT(report.tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(report.tmr_startup_self_test_coverage_valid);
    LLPS_TEST_ASSERT(report.runtime_safety_latches_valid);
    LLPS_TEST_ASSERT(report.memory_safety_counters_valid);
    LLPS_TEST_ASSERT(report.memory_safety_counters_fingerprint != 0u);
    LLPS_TEST_ASSERT(report.tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(report.tmr_startup_self_test_required_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(report.tmr_bank_guard_valid[0]);
    LLPS_TEST_ASSERT(report.tmr_bank_guard_valid[1]);
    LLPS_TEST_ASSERT(report.tmr_bank_guard_valid[2]);
    LLPS_TEST_ASSERT(report.tmr_bank_distance_01 >= LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
    LLPS_TEST_ASSERT(report.tmr_bank_distance_02 >= LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
    LLPS_TEST_ASSERT(report.tmr_bank_distance_12 >= LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
    LLPS_TEST_ASSERT(report.tmr_metadata_min_bank_distance >=
                     LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);

    printf("test_llps_init_sets_integrity_guards passed.\n");
}

static void test_llps_open_close_listen(void) {
    const llps_yml_config_t cfg = test_config();
    int listen_fd = LLPS_INVALID_FD;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_open_listen_socket(&cfg, &listen_fd) == LLPS_OK);
    LLPS_TEST_ASSERT(listen_fd == 100);
    LLPS_TEST_ASSERT(llps_close_listen_socket(&listen_fd) == LLPS_OK);
    LLPS_TEST_ASSERT(listen_fd == LLPS_INVALID_FD);

    printf("test_llps_open_close_listen passed.\n");
}

static void test_llps_init_resolves_target_domain_once(void) {
    llps_yml_config_t cfg = test_config();
    struct sockaddr_in baddr;
    int n = 0;

    reset_mocks();
    n = snprintf(cfg.target_ip, sizeof(cfg.target_ip), "%s", "backend.local");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.target_ip));
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(mock_getaddrinfo_calls == 1u);
    LLPS_TEST_ASSERT(mock_freeaddrinfo_calls == 1u);
    LLPS_TEST_ASSERT(strcmp(mock_getaddrinfo_node, "backend.local") == 0);
    LLPS_TEST_ASSERT(strcmp(mock_getaddrinfo_service, "25566") == 0);
    LLPS_TEST_ASSERT(g_backend_addr_valid);
    LLPS_TEST_ASSERT(llps_build_backend_addr(&baddr) == LLPS_OK);
    LLPS_TEST_ASSERT(baddr.sin_family == AF_INET);
    LLPS_TEST_ASSERT(baddr.sin_port == htons(25566u));

    printf("test_llps_init_resolves_target_domain_once passed.\n");
}

static void test_llps_open_listen_socket_resolves_listen_domain(void) {
    llps_yml_config_t cfg = test_config();
    int listen_fd = LLPS_INVALID_FD;
    int n = 0;

    reset_mocks();
    n = snprintf(cfg.listen_host, sizeof(cfg.listen_host), "%s", "localhost");
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.listen_host));
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(mock_getaddrinfo_calls == 0u);
    LLPS_TEST_ASSERT(llps_open_listen_socket(&cfg, &listen_fd) == LLPS_OK);
    LLPS_TEST_ASSERT(mock_getaddrinfo_calls == 1u);
    LLPS_TEST_ASSERT(mock_freeaddrinfo_calls == 1u);
    LLPS_TEST_ASSERT(strcmp(mock_getaddrinfo_node, "localhost") == 0);
    LLPS_TEST_ASSERT(strcmp(mock_getaddrinfo_service, "25565") == 0);
    LLPS_TEST_ASSERT(listen_fd == 100);
    LLPS_TEST_ASSERT(llps_close_listen_socket(&listen_fd) == LLPS_OK);

    printf("test_llps_open_listen_socket_resolves_listen_domain passed.\n");
}

static void test_llps_sockaddr_ipv4_text_requires_full_addrlen(void) {
    struct sockaddr_in addr;
    char ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint16_t port = 0u;

    (void)memset(&addr, 0, sizeof(addr));
    (void)memset(ip, 0, sizeof(ip));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(25565u);
    addr.sin_addr.s_addr = htonl(0x7f000001u);

    LLPS_TEST_ASSERT(
        llps_sockaddr_ipv4_text_len((const struct sockaddr *)&addr,
                                    (socklen_t)(sizeof(addr) - 1u),
                                    ip,
                                    sizeof(ip),
                                    &port) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(port == 0u);

    LLPS_TEST_ASSERT(
        llps_sockaddr_ipv4_text_len((const struct sockaddr *)&addr,
                                    (socklen_t)sizeof(addr),
                                    ip,
                                    sizeof(ip),
                                    &port) == LLPS_OK);
    LLPS_TEST_ASSERT(strcmp(ip, "127.0.0.1") == 0);
    LLPS_TEST_ASSERT(port == 25565u);

    printf("test_llps_sockaddr_ipv4_text_requires_full_addrlen passed.\n");
}

static void test_llps_connection_refreshes_tmr_after_pump_arg_setup(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    mock_socket_ret = 401;
    mock_task_group_spawn_checks_session_integrity = true;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 2u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_saw_active_session);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_refreshes_tmr_after_pump_arg_setup passed.\n");
}

static void test_llps_connection_accepts_poll_ready_without_revents(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    mock_socket_ret = 401;
    mock_connect_ret = -1;
    mock_connect_errno_value = EINPROGRESS;
    mock_llam_poll_fd_ret = 1;
    mock_llam_poll_fd_revents = 0;
    mock_getsockopt_so_error = 0;
    mock_task_group_spawn_checks_session_integrity = true;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 2u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_saw_active_session);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_accepts_poll_ready_without_revents passed.\n");
}

static void test_llps_connection_times_out_when_poll_never_ready(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    mock_socket_ret = 401;
    mock_connect_ret = -1;
    mock_connect_errno_value = EINPROGRESS;
    mock_llam_poll_fd_ret = 0;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 0u);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_times_out_when_poll_never_ready passed.\n");
}

static void test_llps_connection_preface_timeout_avoids_backend_socket(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    char path[128];
    char log_text[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_client_preface_timeout_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.client_preface_timeout_ms = LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    mock_llam_read_when_ready_delegates_read = false;
    mock_llam_read_when_ready_ret = -1;
    mock_llam_read_when_ready_errno_value = ETIMEDOUT;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active_with_peer(sess,
                                          sess_idx,
                                          400,
                                          "203.0.113.20",
                                          25565u,
                                          77u);
    llps_task_connection(sess);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(mock_socket_calls == 0u);
    LLPS_TEST_ASSERT(mock_llam_read_when_ready_calls == 1u);
    LLPS_TEST_ASSERT(mock_llam_read_when_ready_last_timeout_ms ==
                     (int)LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 0u);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "client_preface_timeout") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: backend_fail") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: close") != NULL);
    (void)remove(path);

    printf("test_llps_connection_preface_timeout_avoids_backend_socket passed.\n");
}

static void test_llps_connection_preface_flushes_before_pumps(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    cfg.client_preface_timeout_ms = 1000u;

    reset_mocks();
    mock_socket_ret = 401;
    mock_read_ret = 5;
    mock_send_ret = 5;
    mock_task_group_spawn_checks_session_integrity = true;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_socket_calls == 1u);
    LLPS_TEST_ASSERT(mock_read_calls == 1u);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 2u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_saw_active_session);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_preface_flushes_before_pumps passed.\n");
}

static void test_llps_connection_protocol_gate_drops_invalid_preface(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    char path[128];
    char log_text[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_protocol_handshake_drop_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.client_preface_timeout_ms = 1000u;
    cfg.protocol_handshake_gate_enabled = 1u;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    mock_read_data[0] = 0x01u;
    mock_read_data[1] = 0x01u;
    mock_read_data_len = 2u;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active_with_peer(sess,
                                          sess_idx,
                                          400,
                                          "203.0.113.30",
                                          25565u,
                                          88u);
    llps_task_connection(sess);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(mock_socket_calls == 0u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 0u);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "protocol_handshake_invalid") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: backend_fail") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: close") != NULL);
    (void)remove(path);

    printf("test_llps_connection_protocol_gate_drops_invalid_preface passed.\n");
}

static void test_llps_connection_protocol_gate_times_out_idle_preface(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    char path[128];
    char log_text[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_protocol_idle_preface_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.client_preface_timeout_ms = LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN;
    cfg.protocol_handshake_gate_enabled = 1u;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    mock_llam_read_when_ready_delegates_read = false;
    mock_llam_read_when_ready_ret = -1;
    mock_llam_read_when_ready_errno_value = ETIMEDOUT;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active_with_peer(sess,
                                          sess_idx,
                                          400,
                                          "203.0.113.32",
                                          25565u,
                                          90u);
    llps_task_connection(sess);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(mock_socket_calls == 0u);
    LLPS_TEST_ASSERT(mock_llam_read_when_ready_calls == 1u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 0u);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "client_preface_timeout") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: backend_fail") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: close") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: backend_connect") == NULL);
    (void)remove(path);

    printf("test_llps_connection_protocol_gate_times_out_idle_preface passed.\n");
}

static void test_expect_protocol_gate_rejects_buffer(
    const char * const case_name,
    const uint8_t * const buf,
    const size_t len) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    char path[160];
    char log_text[4096];
    int n = 0;

    LLPS_TEST_ASSERT(case_name != NULL);
    LLPS_TEST_ASSERT(buf != NULL);
    LLPS_TEST_ASSERT(len > 0u);
    LLPS_TEST_ASSERT(len <= sizeof(mock_read_data));

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_protocol_handshake_reject_%lu_%s.pxf",
                 test_tmp_serial(),
                 case_name);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.client_preface_timeout_ms = 1000u;
    cfg.protocol_handshake_gate_enabled = 1u;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    (void)memcpy(mock_read_data, buf, len);
    mock_read_data_len = len;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active_with_peer(sess,
                                          sess_idx,
                                          400,
                                          "203.0.113.31",
                                          25565u,
                                          89u);
    llps_task_connection(sess);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(mock_socket_calls == 0u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 0u);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "protocol_handshake_invalid") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: backend_fail") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: close") != NULL);
    (void)remove(path);
}

static void test_llps_protocol_handshake_parser_covers_boundaries(void) {
    static const uint8_t trailing_payload[] = {
        0x01u, 0x02u, 0x7Fu, 0x00u, 0x55u
    };
    uint8_t packet[LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX + 16u];
    uint8_t noncanonical[LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX + 16u];
    uint8_t body[32];
    char max_host[LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX + 1u];
    size_t len = 0u;
    size_t body_len = 0u;
    size_t prefix_len = 0u;

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len) ==
                     LLPS_PROTOCOL_HANDSHAKE_VALID);

    for (size_t trunc_len = 0u; trunc_len < len; ++trunc_len) {
        LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet,
                                                           trunc_len) ==
                         LLPS_PROTOCOL_HANDSHAKE_NEED_MORE);
    }

    LLPS_TEST_ASSERT((sizeof(packet) - len) >= sizeof(trailing_payload));
    (void)memcpy(&packet[len], trailing_payload, sizeof(trailing_payload));
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(
                         packet,
                         len + sizeof(trailing_payload)) ==
                     LLPS_PROTOCOL_HANDSHAKE_VALID);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(packet[0] < 0x80u);
    noncanonical[0] = (uint8_t)(packet[0] | 0x80u);
    noncanonical[1] = 0x00u;
    (void)memcpy(&noncanonical[2], &packet[1], len - 1u);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(noncanonical,
                                                       len + 1u) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    body_len = 0u;
    body[body_len] = 0x80u;
    ++body_len;
    body[body_len] = 0x00u;
    ++body_len;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            765u);
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            1u);
    body[body_len] = (uint8_t)'a';
    ++body_len;
    body[body_len] = 0x63u;
    ++body_len;
    body[body_len] = 0xDDu;
    ++body_len;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            2u);
    len = test_build_protocol_packet_from_body(packet,
                                                sizeof(packet),
                                                body,
                                                body_len);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    body_len = 0u;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            0u);
    body[body_len] = 0xFFu;
    ++body_len;
    body[body_len] = 0xFFu;
    ++body_len;
    body[body_len] = 0xFFu;
    ++body_len;
    body[body_len] = 0xFFu;
    ++body_len;
    body[body_len] = 0x0Fu;
    ++body_len;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            1u);
    body[body_len] = (uint8_t)'a';
    ++body_len;
    body[body_len] = 0x63u;
    ++body_len;
    body[body_len] = 0xDDu;
    ++body_len;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            2u);
    len = test_build_protocol_packet_from_body(packet,
                                                sizeof(packet),
                                                body,
                                                body_len);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(packet[0] < 0x7Fu);
    packet[0] = (uint8_t)(packet[0] + 1u);
    packet[len] = 0u;
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len + 1u) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    packet[0] = 0x80u;
    packet[1] = 0x80u;
    packet[2] = 0x80u;
    packet[3] = 0x80u;
    packet[4] = 0x80u;
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, 5u) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    packet[0] = 0xFFu;
    packet[1] = 0xFFu;
    packet[2] = 0xFFu;
    packet[3] = 0xFFu;
    packet[4] = 0x10u;
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, 5u) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    prefix_len = test_write_protocol_varint(
        packet,
        sizeof(packet),
        (uint32_t)LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet,
                                                       prefix_len) ==
                     LLPS_PROTOCOL_HANDSHAKE_NEED_MORE);

    prefix_len = test_write_protocol_varint(
        packet,
        sizeof(packet),
        (uint32_t)LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX + 1u);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet,
                                                       prefix_len) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    (void)memset(max_host, 'a', LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX);
    max_host[LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX] = '\0';
    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         max_host,
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len) ==
                     LLPS_PROTOCOL_HANDSHAKE_VALID);

    body_len = 0u;
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            0u);
    body_len += test_write_protocol_varint(&body[body_len],
                                            sizeof(body) - body_len,
                                            765u);
    body_len += test_write_protocol_varint(
        &body[body_len],
        sizeof(body) - body_len,
        (uint32_t)LLPS_PROTOCOL_HANDSHAKE_ADDR_BYTES_MAX + 1u);
    len = test_build_protocol_packet_from_body(packet,
                                                sizeof(packet),
                                                body,
                                                body_len);
    LLPS_TEST_ASSERT(llps_protocol_handshake_validate(packet, len) ==
                     LLPS_PROTOCOL_HANDSHAKE_INVALID);

    printf("test_llps_protocol_handshake_parser_covers_boundaries passed.\n");
}

static void test_llps_protocol_handshake_parser_fuzz_is_bounded(void) {
    uint8_t buf[96];
    uint32_t rng = 0x4C4C5053u;

    for (uint32_t case_idx = 0u; case_idx < 512u; ++case_idx) {
        llps_protocol_handshake_status_t first =
            LLPS_PROTOCOL_HANDSHAKE_INVALID;
        llps_protocol_handshake_status_t second =
            LLPS_PROTOCOL_HANDSHAKE_INVALID;
        size_t len = 0u;

        rng ^= rng << 13u;
        rng ^= rng >> 17u;
        rng ^= rng << 5u;
        len = (size_t)(rng % (uint32_t)(sizeof(buf) + 1u));

        for (size_t i = 0u; i < sizeof(buf); ++i) {
            rng ^= rng << 13u;
            rng ^= rng >> 17u;
            rng ^= rng << 5u;
            buf[i] = (uint8_t)(rng & 0xFFu);
        }

        first = llps_protocol_handshake_validate(buf, len);
        second = llps_protocol_handshake_validate(buf, len);
        LLPS_TEST_ASSERT(first == second);
        LLPS_TEST_ASSERT((first == LLPS_PROTOCOL_HANDSHAKE_NEED_MORE) ||
                         (first == LLPS_PROTOCOL_HANDSHAKE_VALID) ||
                         (first == LLPS_PROTOCOL_HANDSHAKE_INVALID));
    }

    printf("test_llps_protocol_handshake_parser_fuzz_is_bounded passed.\n");
}

static void test_llps_connection_protocol_gate_rejects_malformed_handshakes(void) {
    uint8_t packet[128];
    uint8_t noncanonical[128];
    size_t len = 0u;
    size_t prefix_len = 0u;

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(packet[0] < 0x80u);
    packet[1] = 1u;
    test_expect_protocol_gate_rejects_buffer("wrong_packet_id",
                                              packet,
                                              len);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         0u,
                                         2u);
    test_expect_protocol_gate_rejects_buffer("zero_port", packet, len);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         3u);
    test_expect_protocol_gate_rejects_buffer("bad_next_state", packet, len);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(packet[0] < 0x80u);
    packet[4] = 0u;
    test_expect_protocol_gate_rejects_buffer("zero_addr_len", packet, len);

    packet[0] = 0x80u;
    packet[1] = 0x80u;
    packet[2] = 0x80u;
    packet[3] = 0x80u;
    packet[4] = 0x80u;
    test_expect_protocol_gate_rejects_buffer("overlong_len_varint",
                                              packet,
                                              5u);

    prefix_len = test_write_protocol_varint(
        packet,
        sizeof(packet),
        (uint32_t)LLPS_PROTOCOL_HANDSHAKE_PACKET_BYTES_MAX + 1u);
    test_expect_protocol_gate_rejects_buffer("oversized_packet_len",
                                              packet,
                                              prefix_len);

    len = test_build_protocol_handshake(packet,
                                         sizeof(packet),
                                         "mc.example",
                                         25565u,
                                         2u);
    LLPS_TEST_ASSERT(packet[0] < 0x80u);
    LLPS_TEST_ASSERT((len + 1u) <= sizeof(noncanonical));
    noncanonical[0] = (uint8_t)(packet[0] | 0x80u);
    noncanonical[1] = 0x00u;
    (void)memcpy(&noncanonical[2], &packet[1], len - 1u);
    test_expect_protocol_gate_rejects_buffer("noncanonical_packet_len",
                                              noncanonical,
                                              len + 1u);

    printf("test_llps_connection_protocol_gate_rejects_malformed_handshakes passed.\n");
}

static void test_llps_connection_protocol_gate_accepts_fragmented_handshake(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    size_t handshake_len = 0u;

    cfg.client_preface_timeout_ms = 1000u;
    cfg.protocol_handshake_gate_enabled = 1u;

    reset_mocks();
    handshake_len = test_build_protocol_handshake(mock_read_data,
                                                   sizeof(mock_read_data),
                                                   "mc.example",
                                                   25565u,
                                                   2u);
    mock_read_data_len = handshake_len;
    mock_read_chunk_max = 3u;
    mock_socket_ret = 401;
    mock_send_ret = (ssize_t)handshake_len;
    mock_task_group_spawn_checks_session_integrity = true;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_socket_calls == 1u);
    LLPS_TEST_ASSERT(mock_read_calls > 1u);
    LLPS_TEST_ASSERT(mock_read_data_off == handshake_len);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 2u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_saw_active_session);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_protocol_gate_accepts_fragmented_handshake passed.\n");
}

static void test_llps_connection_protocol_gate_preserves_trailing_preface_payload(void) {
    static const uint8_t trailing_payload[] = {
        0x01u, 0x02u, 0x7Fu, 0x00u, 0x55u
    };
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    size_t handshake_len = 0u;
    size_t preface_len = 0u;

    cfg.client_preface_timeout_ms = 1000u;
    cfg.protocol_handshake_gate_enabled = 1u;

    reset_mocks();
    handshake_len = test_build_protocol_handshake(mock_read_data,
                                                   sizeof(mock_read_data),
                                                   "mc.example",
                                                   25565u,
                                                   2u);
    LLPS_TEST_ASSERT((sizeof(mock_read_data) - handshake_len) >=
                     sizeof(trailing_payload));
    (void)memcpy(&mock_read_data[handshake_len],
                 trailing_payload,
                 sizeof(trailing_payload));
    preface_len = handshake_len + sizeof(trailing_payload);
    mock_read_data_len = preface_len;
    mock_socket_ret = 401;
    mock_send_ret = (ssize_t)preface_len;
    mock_task_group_spawn_checks_session_integrity = true;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 400);
    llps_task_connection(sess);

    LLPS_TEST_ASSERT(mock_socket_calls == 1u);
    LLPS_TEST_ASSERT(mock_read_calls == 1u);
    LLPS_TEST_ASSERT(mock_read_data_off == preface_len);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);
    LLPS_TEST_ASSERT(mock_send_last_len == preface_len);
    LLPS_TEST_ASSERT(mock_send_capture_len == preface_len);
    LLPS_TEST_ASSERT(memcmp(mock_send_capture,
                            mock_read_data,
                            preface_len) == 0);
    LLPS_TEST_ASSERT(mock_task_group_spawn_calls == 2u);
    LLPS_TEST_ASSERT(mock_task_group_spawn_saw_active_session);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));

    printf("test_llps_connection_protocol_gate_preserves_trailing_preface_payload passed.\n");
}

static void test_llps_accept_errno_policy_keeps_remote_faults_local(void) {
    reset_mocks();
    LLPS_TEST_ASSERT(llps_accept_errno_is_retryable(EAGAIN));
    LLPS_TEST_ASSERT(llps_accept_errno_is_retryable(EINTR));
    LLPS_TEST_ASSERT(llps_accept_errno_is_retryable(ECONNABORTED));
    LLPS_TEST_ASSERT(llps_accept_errno_is_resource_pressure(EMFILE));
    LLPS_TEST_ASSERT(llps_accept_errno_is_resource_pressure(ENFILE));
    LLPS_TEST_ASSERT(llps_accept_errno_is_resource_pressure(ENOMEM));
    LLPS_TEST_ASSERT(llps_accept_errno_is_listener_fault(EBADF));
    LLPS_TEST_ASSERT(llps_accept_errno_is_listener_fault(EINVAL));
    LLPS_TEST_ASSERT(llps_accept_errno_is_listener_fault(ENOTSOCK));
    LLPS_TEST_ASSERT(!llps_accept_errno_is_listener_fault(EAGAIN));
    LLPS_TEST_ASSERT(!llps_accept_errno_is_listener_fault(EMFILE));

    LLPS_TEST_ASSERT(llps_handle_accept_error(EAGAIN));
    LLPS_TEST_ASSERT(llps_handle_accept_error(EMFILE));
    LLPS_TEST_ASSERT(!llps_control_shutdown_is_requested());

    printf("test_llps_accept_errno_policy_keeps_remote_faults_local passed.\n");
}

static void test_llps_client_ip_session_limit_blocks_excess_active(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess0_idx = 0u;
    uint32_t sess1_idx = 0u;
    uint32_t active = 0u;
    uint32_t limit = 0u;
    llps_session_t *sess0 = NULL;
    llps_session_t *sess1 = NULL;

    cfg.max_sessions_per_client_ip = 2u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(!llps_client_ip_session_limit_exceeded("203.0.113.7",
                                                            &active,
                                                            &limit));
    LLPS_TEST_ASSERT(active == 0u);
    LLPS_TEST_ASSERT(limit == 2u);

    LLPS_TEST_ASSERT(llps_find_free_session(&sess0_idx) == LLPS_OK);
    sess0 = &g_sessions[sess0_idx];
    llps_session_prepare_active_with_peer(sess0,
                                          sess0_idx,
                                          500,
                                          "203.0.113.7",
                                          25565u,
                                          1u);
    LLPS_TEST_ASSERT(!llps_client_ip_session_limit_exceeded("203.0.113.7",
                                                            &active,
                                                            &limit));
    LLPS_TEST_ASSERT(active == 1u);
    LLPS_TEST_ASSERT(limit == 2u);

    LLPS_TEST_ASSERT(llps_find_free_session(&sess1_idx) == LLPS_OK);
    sess1 = &g_sessions[sess1_idx];
    llps_session_prepare_active_with_peer(sess1,
                                          sess1_idx,
                                          501,
                                          "203.0.113.7",
                                          25566u,
                                          2u);
    LLPS_TEST_ASSERT(llps_client_ip_session_limit_exceeded("203.0.113.7",
                                                           &active,
                                                           &limit));
    LLPS_TEST_ASSERT(active == 2u);
    LLPS_TEST_ASSERT(limit == 2u);
    LLPS_TEST_ASSERT(!llps_client_ip_session_limit_exceeded("198.51.100.9",
                                                            &active,
                                                            &limit));
    LLPS_TEST_ASSERT(active == 0u);
    LLPS_TEST_ASSERT(limit == 2u);

    llps_close_session(sess0);
    llps_close_session(sess1);

    printf("test_llps_client_ip_session_limit_blocks_excess_active passed.\n");
}

static void test_llps_client_ip_rate_limit_blocks_burst(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t count = 0u;
    uint32_t limit = 0u;
    uint32_t window_ms = 0u;
    const char *reason = NULL;

    cfg.max_new_sessions_per_client_ip_per_window = 2u;
    cfg.client_ip_rate_window_ms = 500u;

    reset_mocks();
    mock_llam_now_ns = 1000000u;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    LLPS_TEST_ASSERT(!llps_client_ip_rate_limit_exceeded("203.0.113.7",
                                                         &count,
                                                         &limit,
                                                         &window_ms,
                                                         &reason));
    LLPS_TEST_ASSERT(count == 1u);
    LLPS_TEST_ASSERT(limit == 2u);
    LLPS_TEST_ASSERT(window_ms == 500u);

    LLPS_TEST_ASSERT(!llps_client_ip_rate_limit_exceeded("203.0.113.7",
                                                         &count,
                                                         &limit,
                                                         &window_ms,
                                                         &reason));
    LLPS_TEST_ASSERT(count == 2u);

    LLPS_TEST_ASSERT(llps_client_ip_rate_limit_exceeded("203.0.113.7",
                                                        &count,
                                                        &limit,
                                                        &window_ms,
                                                        &reason));
    LLPS_TEST_ASSERT(count == 2u);
    LLPS_TEST_ASSERT(strcmp(reason, "client_ip_rate_limit") == 0);

    LLPS_TEST_ASSERT(!llps_client_ip_rate_limit_exceeded("198.51.100.9",
                                                         &count,
                                                         &limit,
                                                         &window_ms,
                                                         &reason));
    LLPS_TEST_ASSERT(count == 1u);

    mock_llam_now_ns += ((uint64_t)cfg.client_ip_rate_window_ms *
                         LLPS_NSEC_PER_MSEC) + 1u;
    LLPS_TEST_ASSERT(!llps_client_ip_rate_limit_exceeded("203.0.113.7",
                                                         &count,
                                                         &limit,
                                                         &window_ms,
                                                         &reason));
    LLPS_TEST_ASSERT(count == 1u);

    printf("test_llps_client_ip_rate_limit_blocks_burst passed.\n");
}

static void test_llps_run_server_audits_client_ip_limit_drop(void) {
    llps_yml_config_t cfg = test_config();
    char path[128];
    char log_text[16384];
    int listen_fd = 700;
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_client_ip_limit_audit_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.max_clients = 4u;
    cfg.accept_batch_max = 2u;
    cfg.max_sessions_per_client_ip = 1u;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    mock_accept_ret = 600;
    mock_accept_successes_remaining = 2u;
    mock_accept_next_port = 40100u;
    mock_accept_ipv4_addr = 0xCB00710Au;
    mock_llam_poll_fd_ret = 1;
    mock_sleep_requests_shutdown = true;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    llps_run_server(&listen_fd);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(listen_fd == LLPS_INVALID_FD);
    LLPS_TEST_ASSERT(mock_accept_calls == 2u);

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: accept") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: drop") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "accepted") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "client_ip_limit") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#     client: 203.0.113.10:40100") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#     client: 203.0.113.10:40101") != NULL);

    (void)remove(path);

    printf("test_llps_run_server_audits_client_ip_limit_drop passed.\n");
}

static void test_llps_run_server_audits_client_ip_rate_limit_drop(void) {
    llps_yml_config_t cfg = test_config();
    char path[128];
    char log_text[16384];
    int listen_fd = 700;
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_client_ip_rate_audit_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.max_clients = 4u;
    cfg.accept_batch_max = 2u;
    cfg.max_new_sessions_per_client_ip_per_window = 1u;
    cfg.client_ip_rate_window_ms = 1000u;
    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));

    reset_mocks();
    (void)remove(path);
    mock_accept_ret = 620;
    mock_accept_successes_remaining = 2u;
    mock_accept_next_port = 40200u;
    mock_accept_ipv4_addr = 0xCB00710Bu;
    mock_llam_now_ns = 1000000u;
    mock_llam_poll_fd_ret = 1;
    mock_sleep_requests_shutdown = true;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    llps_run_server(&listen_fd);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(listen_fd == LLPS_INVALID_FD);
    LLPS_TEST_ASSERT(mock_accept_calls == 2u);

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: accept") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "#   event: drop") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "accepted") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "client_ip_rate_limit") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#     client: 203.0.113.11:40200") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#     client: 203.0.113.11:40201") != NULL);

    (void)remove(path);

    printf("test_llps_run_server_audits_client_ip_rate_limit_drop passed.\n");
}

static void test_llps_fd_nonblocking_contract_is_checked(void) {
    reset_mocks();
    mock_fcntl_getfl_ret = O_NONBLOCK;
    LLPS_TEST_ASSERT(llps_fd_is_nonblocking(10));

    mock_fcntl_getfl_ret = 0;
    LLPS_TEST_ASSERT(!llps_fd_is_nonblocking(10));

    mock_fcntl_getfl_ret = -1;
    LLPS_TEST_ASSERT(!llps_fd_is_nonblocking(10));
    LLPS_TEST_ASSERT(!llps_fd_is_nonblocking(LLPS_INVALID_FD));

    printf("test_llps_fd_nonblocking_contract_is_checked passed.\n");
}

static void test_llps_pump_rejects_blocking_fd_before_io(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 460);
    sess->backend_fd = 461;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);

    mock_fcntl_getfl_ret = 0;
    mock_read_ret = 4;
    mock_send_ret = 4;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(mock_read_calls == 0u);
    LLPS_TEST_ASSERT(mock_send_calls == 0u);
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations > 0u);
    LLPS_TEST_ASSERT(sess->close_reason ==
                     (uint32_t)LLPS_CLOSE_REASON_CONTRACT_VIOLATION);
    LLPS_TEST_ASSERT(sess->close_reason_inverse == ~sess->close_reason);

    printf("test_llps_pump_rejects_blocking_fd_before_io passed.\n");
}

static void test_llps_pump_does_not_refresh_activity_on_empty_poll(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    uint64_t previous_activity = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 410);
    sess->backend_fd = 411;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);
    previous_activity = sess->last_activity_ns;

    mock_llam_now_ns = previous_activity + LLPS_NSEC_PER_SEC + 1000u;
    mock_read_ret = -1;
    mock_read_errno_value = EAGAIN;
    mock_llam_poll_fd_ret = 0;
    mock_sleep_requests_shutdown = true;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(sess->last_activity_ns == previous_activity);
    LLPS_TEST_ASSERT(mock_read_calls >= 1u);

    printf("test_llps_pump_does_not_refresh_activity_on_empty_poll passed.\n");
}

static void test_llps_pump_refreshes_activity_on_payload_progress(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    uint64_t expected_activity = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 420);
    sess->backend_fd = 421;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);

    expected_activity = sess->last_activity_ns + LLPS_NSEC_PER_SEC + 1000u;
    mock_llam_now_ns = expected_activity;
    mock_read_ret = 4;
    mock_read_eof_after_calls = 1u;
    mock_send_ret = 4;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(sess->last_activity_ns == expected_activity);
    LLPS_TEST_ASSERT(mock_read_calls == 2u);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);

    printf("test_llps_pump_refreshes_activity_on_payload_progress passed.\n");
}

static void test_llps_pump_uses_payload_ecc_when_enabled(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    cfg.payload_ecc_enabled = 1u;
    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 430);
    sess->backend_fd = 431;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);

    mock_read_ret = 9;
    mock_read_eof_after_calls = 1u;
    mock_send_ret = 9;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(mock_read_calls == 2u);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);
    LLPS_TEST_ASSERT(sess->c2s_payload_ecc[0] != 0u);
    LLPS_TEST_ASSERT(sess->c2s_payload_ecc[1] != 0u);
    LLPS_TEST_ASSERT(sess->c2s_payload_ecc_len == 9u);
    LLPS_TEST_ASSERT(sess->c2s_payload_ecc_len_inverse ==
                     ~sess->c2s_payload_ecc_len);
    LLPS_TEST_ASSERT(llps_secded_is_valid_u32(
                         sess->c2s_payload_ecc_len,
                         sess->c2s_payload_ecc_len_secded));
    LLPS_TEST_ASSERT(
        llps_secded_is_valid_u32(
            sess->c2s_payload_ecc_len_inverse,
            sess->c2s_payload_ecc_len_inverse_secded));
    LLPS_TEST_ASSERT(
        g_session_tmr_region0.records[sess_idx].c2s_payload_ecc_len == 9u);
    LLPS_TEST_ASSERT(sess->c2s_buf[9] == 0u);
    LLPS_TEST_ASSERT(sess->c2s_buf[15] == 0u);

    printf("test_llps_pump_uses_payload_ecc_when_enabled passed.\n");
}

static void test_llps_pump_rejects_oversized_read_result(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 440);
    sess->backend_fd = 441;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);

    mock_read_ret = (ssize_t)cfg.buffer_size + 1;
    mock_read_return_unbounded = true;
    mock_send_ret = 1;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(mock_read_calls == 1u);
    LLPS_TEST_ASSERT(mock_send_calls == 0u);
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations > 0u);
    LLPS_TEST_ASSERT(sess->close_reason ==
                     (uint32_t)LLPS_CLOSE_REASON_CONTRACT_VIOLATION);
    LLPS_TEST_ASSERT(sess->close_reason_inverse == ~sess->close_reason);

    printf("test_llps_pump_rejects_oversized_read_result passed.\n");
}

static void test_llps_pump_rejects_oversized_send_result(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 450);
    sess->backend_fd = 451;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    llps_session_refresh_crc(sess);

    mock_read_ret = 8;
    mock_read_eof_after_calls = 1u;
    mock_send_ret = 9;
    llps_task_pump(&sess->pump_c2s);

    LLPS_TEST_ASSERT(mock_read_calls == 1u);
    LLPS_TEST_ASSERT(mock_send_calls == 1u);
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations > 0u);
    LLPS_TEST_ASSERT(sess->close_reason ==
                     (uint32_t)LLPS_CLOSE_REASON_CONTRACT_VIOLATION);
    LLPS_TEST_ASSERT(sess->close_reason_inverse == ~sess->close_reason);

    printf("test_llps_pump_rejects_oversized_send_result passed.\n");
}

static void test_llps_secded_corrects_single_bit_and_detects_double_bit(void) {
    const uint64_t original = UINT64_C(0x0123456789ABCDEF);
    const uint8_t original_ecc = llps_secded_encode_u64(original, 64u);
    uint64_t damaged_data = original ^ (UINT64_C(1) << 17u);
    uint8_t damaged_ecc = original_ecc;
    uint64_t ecc_only_data = original;
    uint8_t ecc_only = (uint8_t)(original_ecc ^ 0x04u);
    uint64_t double_bit_data =
        original ^ (UINT64_C(1) << 9u) ^ (UINT64_C(1) << 23u);
    uint8_t double_bit_ecc = original_ecc;

    LLPS_TEST_ASSERT(!llps_secded_is_valid_u64(damaged_data,
                                               64u,
                                               damaged_ecc));
    LLPS_TEST_ASSERT(llps_secded_repair_u64(&damaged_data,
                                            64u,
                                            &damaged_ecc) ==
                     LLPS_SECDED_CORRECTED);
    LLPS_TEST_ASSERT(damaged_data == original);
    LLPS_TEST_ASSERT(damaged_ecc == original_ecc);
    LLPS_TEST_ASSERT(llps_secded_is_valid_u64(damaged_data,
                                              64u,
                                              damaged_ecc));

    LLPS_TEST_ASSERT(llps_secded_repair_u64(&ecc_only_data,
                                            64u,
                                            &ecc_only) ==
                     LLPS_SECDED_CORRECTED);
    LLPS_TEST_ASSERT(ecc_only_data == original);
    LLPS_TEST_ASSERT(ecc_only == original_ecc);

    LLPS_TEST_ASSERT(llps_secded_repair_u64(&double_bit_data,
                                            64u,
                                            &double_bit_ecc) ==
                     LLPS_SECDED_UNCORRECTABLE);
    LLPS_TEST_ASSERT(double_bit_data != original);

    printf("test_llps_secded_corrects_single_bit_and_detects_double_bit passed.\n");
}

static void test_llps_payload_ecc_repairs_single_bit_payload_fault(void) {
    uint8_t buf[LLPS_BUFFER_SIZE];
    uint8_t original[LLPS_BUFFER_SIZE];
    uint8_t ecc[LLPS_PAYLOAD_ECC_WORD_COUNT];
    const size_t len = 13u;
    const uint64_t previous_repairs =
        g_memory_safety_counters.secded_single_bit_repairs;

    reset_mocks();
    (void)memset(buf, 0xA5, sizeof(buf));
    (void)memset(ecc, 0, sizeof(ecc));
    for (size_t i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)('a' + (char)i);
    }
    (void)memcpy(original, buf, sizeof(original));

    LLPS_TEST_ASSERT(llps_payload_ecc_seal(buf,
                                           len,
                                           sizeof(buf),
                                           ecc,
                                           LLPS_PAYLOAD_ECC_WORD_COUNT));
    LLPS_TEST_ASSERT(buf[13] == 0u);
    LLPS_TEST_ASSERT(buf[14] == 0u);
    LLPS_TEST_ASSERT(buf[15] == 0u);

    buf[3] ^= 0x01u;
    buf[14] ^= 0x01u;
    LLPS_TEST_ASSERT(llps_payload_ecc_repair(buf,
                                             len,
                                             sizeof(buf),
                                             ecc,
                                             LLPS_PAYLOAD_ECC_WORD_COUNT));
    LLPS_TEST_ASSERT(memcmp(buf, original, len) == 0);
    LLPS_TEST_ASSERT(buf[13] == 0u);
    LLPS_TEST_ASSERT(buf[14] == 0u);
    LLPS_TEST_ASSERT(buf[15] == 0u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_single_bit_repairs >
                     previous_repairs);

    printf("test_llps_payload_ecc_repairs_single_bit_payload_fault passed.\n");
}

static void test_llps_payload_ecc_fails_closed_on_double_bit_payload_fault(void) {
    uint8_t buf[LLPS_BUFFER_SIZE];
    uint8_t ecc[LLPS_PAYLOAD_ECC_WORD_COUNT];
    const size_t len = 16u;
    const uint64_t previous_failures =
        g_memory_safety_counters.secded_double_bit_failures;

    reset_mocks();
    (void)memset(buf, 0, sizeof(buf));
    (void)memset(ecc, 0, sizeof(ecc));
    for (size_t i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)(0x10u + i);
    }

    LLPS_TEST_ASSERT(llps_payload_ecc_seal(buf,
                                           len,
                                           sizeof(buf),
                                           ecc,
                                           LLPS_PAYLOAD_ECC_WORD_COUNT));
    buf[0] ^= 0x01u;
    buf[1] ^= 0x01u;

    LLPS_TEST_ASSERT(!llps_payload_ecc_repair(buf,
                                              len,
                                              sizeof(buf),
                                              ecc,
                                              LLPS_PAYLOAD_ECC_WORD_COUNT));
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_double_bit_failures >
                     previous_failures);

    printf("test_llps_payload_ecc_fails_closed_on_double_bit_payload_fault passed.\n");
}

static void test_llps_watchdog_payload_ecc_scrub_repairs_single_bit_fault(void) {
    llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    uint8_t original[LLPS_BUFFER_SIZE];
    const size_t len = 16u;
    uint64_t previous_repairs = 0u;

    cfg.payload_ecc_enabled = 1u;
    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    previous_repairs = g_memory_safety_counters.secded_single_bit_repairs;
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 440);
    sess->backend_fd = 441;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    for (size_t i = 0u; i < len; ++i) {
        sess->c2s_buf[i] = (uint8_t)(0x80u + i);
    }
    (void)memcpy(original, sess->c2s_buf, sizeof(original));
    LLPS_TEST_ASSERT(llps_payload_ecc_seal(sess->c2s_buf,
                                           len,
                                           cfg.buffer_size,
                                           sess->c2s_payload_ecc,
                                           LLPS_PAYLOAD_ECC_WORD_COUNT));
    LLPS_TEST_ASSERT(llps_payload_ecc_set_len_for_pump(sess,
                                                       &sess->pump_c2s,
                                                       len));

    sess->c2s_buf[4] ^= 0x01u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(memcmp(sess->c2s_buf, original, len) == 0);
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_single_bit_repairs >
                     previous_repairs);
    LLPS_TEST_ASSERT(g_memory_safety_counters.payload_ecc_scrub_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.payload_ecc_scrub_sessions_checked >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.payload_ecc_scrub_fail_closed_sessions == 0u);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.payload_ecc_scrub_passes >= 1u);
    LLPS_TEST_ASSERT(report.payload_ecc_scrub_sessions_checked >= 1u);

    printf("test_llps_watchdog_payload_ecc_scrub_repairs_single_bit_fault passed.\n");
}

static void test_llps_watchdog_payload_ecc_scrub_fails_closed_on_double_bit_fault(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    const size_t len = 16u;
    uint64_t previous_failures = 0u;
    uint64_t previous_readiness_failures = 0u;

    cfg.payload_ecc_enabled = 1u;
    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    previous_failures = g_memory_safety_counters.secded_double_bit_failures;
    previous_readiness_failures =
        g_memory_safety_counters.readiness_runtime_ecc_failures;
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 442);
    sess->backend_fd = 443;
    sess->pump_c2s.session = sess;
    sess->pump_c2s.src_fd = sess->client_fd;
    sess->pump_c2s.dst_fd = sess->backend_fd;
    sess->pump_c2s.buf = sess->c2s_buf;
    sess->pump_c2s.buf_len = cfg.buffer_size;
    sess->pump_c2s.direction = LLPS_DIR_C2S;
    for (size_t i = 0u; i < len; ++i) {
        sess->c2s_buf[i] = (uint8_t)(0x20u + i);
    }
    LLPS_TEST_ASSERT(llps_payload_ecc_seal(sess->c2s_buf,
                                           len,
                                           cfg.buffer_size,
                                           sess->c2s_payload_ecc,
                                           LLPS_PAYLOAD_ECC_WORD_COUNT));
    LLPS_TEST_ASSERT(llps_payload_ecc_set_len_for_pump(sess,
                                                       &sess->pump_c2s,
                                                       len));

    sess->c2s_buf[0] ^= 0x01u;
    sess->c2s_buf[1] ^= 0x01u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_double_bit_failures >
                     previous_failures);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_ecc_failures >
        previous_readiness_failures);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.payload_ecc_scrub_fail_closed_sessions >= 1u);

    printf("test_llps_watchdog_payload_ecc_scrub_fails_closed_on_double_bit_fault passed.\n");
}

static void test_llps_hmac_sha256_matches_rfc4231_vector(void) {
    uint8_t key[20];
    const uint8_t message[] = {
        'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'
    };
    const uint8_t expected[LLPS_PLATFORM_EVIDENCE_MAC_BYTES] = {
        0xb0u, 0x34u, 0x4cu, 0x61u, 0xd8u, 0xdbu, 0x38u, 0x53u,
        0x5cu, 0xa8u, 0xafu, 0xceu, 0xafu, 0x0bu, 0xf1u, 0x2bu,
        0x88u, 0x1du, 0xc2u, 0x00u, 0xc9u, 0x83u, 0x3du, 0xa7u,
        0x26u, 0xe9u, 0x37u, 0x6cu, 0x2eu, 0x32u, 0xcfu, 0xf7u
    };
    uint8_t actual[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];

    for (uint32_t i = 0u; i < sizeof(key); ++i) {
        key[i] = 0x0bu;
    }

    LLPS_TEST_ASSERT(llps_hmac_sha256(key,
                                      sizeof(key),
                                      message,
                                      sizeof(message),
                                      actual));
    for (uint32_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        LLPS_TEST_ASSERT(actual[i] == expected[i]);
    }

    printf("test_llps_hmac_sha256_matches_rfc4231_vector passed.\n");
}

static void test_llps_software_evidence_self_test_covers_fault_model(void) {
    llps_software_evidence_observation_t observation;
    const uint32_t expected_full_coverage =
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE |
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING |
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
        LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING;
    uint32_t reference_fingerprint = 0u;

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
        true,
        1u,
        4u,
        4096u,
        true,
        65536u,
        12u,
        24u,
        LLPS_SOFTWARE_FAULT_INJECTION_FULL,
        test_physical_memory_domains,
        &observation);

    LLPS_TEST_ASSERT(observation.required);
    LLPS_TEST_ASSERT(observation.passed);
    LLPS_TEST_ASSERT(observation.schema_version ==
                     LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    LLPS_TEST_ASSERT(observation.coverage == expected_full_coverage);
    LLPS_TEST_ASSERT(
        (observation.coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB_CORRUPTION) != 0u);
    LLPS_TEST_ASSERT(
        (observation.coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_RUNTIME_PATROL) != 0u);
    LLPS_TEST_ASSERT(
        (observation.coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_STALE_METADATA_FAIL_CLOSED) !=
        0u);
    LLPS_TEST_ASSERT(observation.required_coverage == expected_full_coverage);
    LLPS_TEST_ASSERT(observation.controller_count == 1u);
    LLPS_TEST_ASSERT(observation.bank_count == 4u);
    LLPS_TEST_ASSERT(observation.scrub_rate == 4096u);
    LLPS_TEST_ASSERT(observation.generation != 0u);
    LLPS_TEST_ASSERT(observation.scrub_generation != 0u);
    LLPS_TEST_ASSERT(observation.fault_injection_coverage ==
                     observation.coverage);
    LLPS_TEST_ASSERT(observation.fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_FULL);
    LLPS_TEST_ASSERT(observation.fingerprint != 0u);
    reference_fingerprint = observation.fingerprint;
    LLPS_TEST_ASSERT(observation.numa_profile_fingerprint != 0u);
    LLPS_TEST_ASSERT(
        llps_software_evidence_observation_is_ready(&observation));

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
        true,
        2u,
        4u,
        4096u,
        true,
        65536u,
        12u,
        24u,
        LLPS_SOFTWARE_FAULT_INJECTION_FULL,
        test_physical_memory_domains,
        &observation);
    LLPS_TEST_ASSERT(observation.passed);
    LLPS_TEST_ASSERT(
        (observation.coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING) != 0u);
    LLPS_TEST_ASSERT(
        (observation.coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING) != 0u);
    LLPS_TEST_ASSERT(observation.fingerprint != 0u);
    LLPS_TEST_ASSERT(observation.fingerprint != reference_fingerprint);

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
        true,
        1u,
        4u,
        4096u,
        true,
        65536u,
        12u,
        24u,
        LLPS_SOFTWARE_FAULT_INJECTION_SINGLE,
        test_physical_memory_domains,
        &observation);
    LLPS_TEST_ASSERT(observation.passed);
    LLPS_TEST_ASSERT(observation.fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_SINGLE);
    LLPS_TEST_ASSERT(
        (observation.fault_injection_coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR) != 0u);
    LLPS_TEST_ASSERT(
        (observation.fault_injection_coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED) == 0u);

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
        true,
        1u,
        4u,
        4096u,
        true,
        65536u,
        12u,
        24u,
        LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE,
        test_physical_memory_domains,
        &observation);
    LLPS_TEST_ASSERT(observation.passed);
    LLPS_TEST_ASSERT(observation.fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE);
    LLPS_TEST_ASSERT(
        (observation.fault_injection_coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED) != 0u);
    LLPS_TEST_ASSERT(
        (observation.fault_injection_coverage &
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR) == 0u);

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
        true,
        1u,
        4u,
        4096u,
        true,
        65536u,
        12u,
        24u,
        LLPS_SOFTWARE_FAULT_INJECTION_OFF,
        test_physical_memory_domains,
        &observation);
    LLPS_TEST_ASSERT(observation.passed);
    LLPS_TEST_ASSERT(observation.fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_OFF);
    LLPS_TEST_ASSERT(observation.fault_injection_coverage == 0u);

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_REAL,
        false,
        0u,
        0u,
        0u,
        false,
        0u,
        0u,
        0u,
        LLPS_SOFTWARE_FAULT_INJECTION_FULL,
        test_physical_memory_domains,
        &observation);
    LLPS_TEST_ASSERT(!observation.required);
    LLPS_TEST_ASSERT(
        llps_software_evidence_observation_is_ready(&observation));
    LLPS_TEST_ASSERT(observation.schema_version == 0u);
    LLPS_TEST_ASSERT(observation.coverage == 0u);
    LLPS_TEST_ASSERT(observation.fingerprint == 0u);

    printf("test_llps_software_evidence_self_test_covers_fault_model passed.\n");
}

static void test_llps_software_evidence_scope_texts_are_explicit(void) {
    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_mode_text(LLPS_PLATFORM_EVIDENCE_MODE_REAL),
        "real") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_mode_text(
            LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC),
        "synthetic") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_mode_text(LLPS_PLATFORM_EVIDENCE_MODE_HYBRID),
        "hybrid") == 0);
    LLPS_TEST_ASSERT(strcmp(llps_platform_evidence_mode_text(UINT32_MAX),
                            "invalid") == 0);

    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_REAL),
        "real-linux-observation") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC),
        "software-platform-model") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_platform_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_HYBRID),
        "hybrid-linux-and-software-model") == 0);
    LLPS_TEST_ASSERT(strcmp(llps_platform_evidence_scope_text(UINT32_MAX),
                            "invalid") == 0);

    LLPS_TEST_ASSERT(strcmp(
        llps_software_fault_injection_mode_text(
            LLPS_SOFTWARE_FAULT_INJECTION_OFF),
        "off") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_software_fault_injection_mode_text(
            LLPS_SOFTWARE_FAULT_INJECTION_SINGLE),
        "single") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_software_fault_injection_mode_text(
            LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE),
        "double") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_software_fault_injection_mode_text(
            LLPS_SOFTWARE_FAULT_INJECTION_FULL),
        "full") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_software_fault_injection_mode_text(UINT32_MAX),
        "invalid") == 0);

    LLPS_TEST_ASSERT(strcmp(
        llps_ecc_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_REAL, false),
        "linux-edac-observation") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_ecc_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
                                     false),
        "linux-edac-observation") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_ecc_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
                                     true),
        "software-ecc-model") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_ecc_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC,
                                     false),
        "none") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_ecc_evidence_scope_text(LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC,
                                     true),
        "software-ecc-model") == 0);

    LLPS_TEST_ASSERT(strcmp(
        llps_physical_memory_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_REAL,
            false),
        "linux-numa-observation") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_physical_memory_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
            false),
        "linux-numa-observation") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_physical_memory_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
            true),
        "software-numa-model") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_physical_memory_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC,
            false),
        "none") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_physical_memory_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC,
            true),
        "software-numa-model") == 0);

    LLPS_TEST_ASSERT(strcmp(
        llps_independent_tmr_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_REAL),
        "operator-attested-hardware-domains") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_independent_tmr_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC),
        "software-domain-model") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_independent_tmr_evidence_scope_text(
            LLPS_PLATFORM_EVIDENCE_MODE_HYBRID),
        "operator-attested-or-software-domain-model") == 0);
    LLPS_TEST_ASSERT(strcmp(
        llps_independent_tmr_evidence_scope_text(UINT32_MAX),
        "invalid") == 0);

    printf("test_llps_software_evidence_scope_texts_are_explicit passed.\n");
}

static void test_llps_software_evidence_rejects_invalid_profile(void) {
    llps_software_evidence_observation_t observation;

    llps_software_evidence_observe(
        LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC,
        true,
        0u,
        4u,
        4096u,
        false,
        0u,
        0u,
        0u,
        LLPS_SOFTWARE_FAULT_INJECTION_FULL,
        test_physical_memory_domains,
        &observation);

    LLPS_TEST_ASSERT(observation.required);
    LLPS_TEST_ASSERT(!observation.passed);
    LLPS_TEST_ASSERT(observation.required_coverage != 0u);
    LLPS_TEST_ASSERT(observation.coverage == 0u);
    LLPS_TEST_ASSERT(observation.fingerprint == 0u);
    LLPS_TEST_ASSERT(
        !llps_software_evidence_observation_is_ready(&observation));

    printf("test_llps_software_evidence_rejects_invalid_profile passed.\n");
}

static void test_llps_session_secded_single_bit_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    uint64_t original_activity = 0u;
    uint64_t previous_repairs = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 430);
    original_activity = sess->last_activity_ns;
    previous_repairs = g_memory_safety_counters.secded_single_bit_repairs;

    sess->last_activity_ns ^= (UINT64_C(1) << 11u);
    LLPS_TEST_ASSERT(!llps_session_secded_is_valid(sess));
    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(sess->last_activity_ns == original_activity);
    LLPS_TEST_ASSERT(llps_session_secded_is_valid(sess));
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_single_bit_repairs >
                     previous_repairs);

    printf("test_llps_session_secded_single_bit_fault_is_repaired passed.\n");
}

static void test_llps_session_secded_double_bit_fault_uses_tmr(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    uint64_t previous_failures = 0u;
    uint64_t previous_readiness_failures = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 431);
    previous_failures = g_memory_safety_counters.secded_double_bit_failures;
    previous_readiness_failures =
        g_memory_safety_counters.readiness_runtime_ecc_failures;

    sess->request_no ^= (UINT64_C(1) << 3u);
    sess->request_no ^= (UINT64_C(1) << 19u);
    LLPS_TEST_ASSERT(!llps_session_secded_is_valid(sess));
    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(sess->request_no == 0u);
    LLPS_TEST_ASSERT(llps_session_secded_is_valid(sess));
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_double_bit_failures >
                     previous_failures);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_ecc_failures >
        previous_readiness_failures);

    printf("test_llps_session_secded_double_bit_fault_uses_tmr passed.\n");
}

static void test_llps_tmr_record_secded_single_bit_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    llps_session_tmr_snapshot_t voted;
    llps_session_tmr_record_t *rec = NULL;
    uint64_t previous_repairs = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 432);
    rec = &g_session_tmr_region0.records[sess_idx];
    previous_repairs = g_memory_safety_counters.secded_single_bit_repairs;

    rec->request_no ^= (UINT64_C(1) << 7u);
    LLPS_TEST_ASSERT(!llps_session_tmr_record_is_valid(rec, 0u, sess_idx));
    LLPS_TEST_ASSERT(llps_session_tmr_vote(sess_idx,
                                           g_runtime_cfg.max_clients,
                                           &voted));
    LLPS_TEST_ASSERT(voted.request_no == 0u);
    LLPS_TEST_ASSERT(rec->request_no == 0u);
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(rec, 0u, sess_idx));
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_single_bit_repairs >
                     previous_repairs);

    printf("test_llps_tmr_record_secded_single_bit_fault_is_repaired passed.\n");
}

static void test_llps_tmr_record_secded_double_bit_fault_uses_majority(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    llps_session_tmr_snapshot_t voted;
    llps_session_tmr_record_t *rec = NULL;
    uint64_t previous_failures = 0u;
    uint64_t previous_bank_repairs = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 433);
    rec = &g_session_tmr_region0.records[sess_idx];
    previous_failures = g_memory_safety_counters.secded_double_bit_failures;
    previous_bank_repairs = g_memory_safety_counters.tmr_single_bank_repairs;

    rec->last_activity_ns ^= (UINT64_C(1) << 4u);
    rec->last_activity_ns ^= (UINT64_C(1) << 29u);
    LLPS_TEST_ASSERT(!llps_session_tmr_record_is_valid(rec, 0u, sess_idx));
    LLPS_TEST_ASSERT(llps_session_tmr_vote(sess_idx,
                                           g_runtime_cfg.max_clients,
                                           &voted));
    LLPS_TEST_ASSERT(voted.last_activity_ns == sess->last_activity_ns);
    LLPS_TEST_ASSERT(rec->last_activity_ns == sess->last_activity_ns);
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(rec, 0u, sess_idx));
    LLPS_TEST_ASSERT(g_memory_safety_counters.secded_double_bit_failures >
                     previous_failures);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_single_bank_repairs >
                     previous_bank_repairs);

    printf("test_llps_tmr_record_secded_double_bit_fault_uses_majority passed.\n");
}

static void test_llps_single_session_mirror_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 200);
    sess->c2s_buf[0] = 0xA5u;
    sess->s2c_buf[0] = 0x5Au;
    LLPS_TEST_ASSERT(llps_session_is_active(sess));

    sess->magic_start = 0u;
    sess->state = ST_FREE;
    sess->state_inverse = 0u;
    sess->integrity_crc ^= 0x1u;
    sess->integrity_crc_inverse ^= 0x2u;
    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(sess->magic_start == LLPS_SESSION_MAGIC_ACTIVE);
    LLPS_TEST_ASSERT(sess->state == ST_ACTIVE);
    LLPS_TEST_ASSERT(sess->state_inverse == llps_state_inverse_value(ST_ACTIVE));
    LLPS_TEST_ASSERT(sess->integrity_crc == llps_session_compute_crc(sess));
    LLPS_TEST_ASSERT(sess->integrity_crc_inverse == ~sess->integrity_crc);

    llps_close_session(sess);
    LLPS_TEST_ASSERT(llps_session_is_free(sess));
    LLPS_TEST_ASSERT(sess->c2s_buf[0] == 0u);
    LLPS_TEST_ASSERT(sess->s2c_buf[0] == 0u);
    LLPS_TEST_ASSERT(llps_free_list_contains(sess_idx));

    printf("test_llps_single_session_mirror_fault_is_repaired passed.\n");
}

static void test_llps_single_tmr_bank_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    llps_session_tmr_snapshot_t divergent;
    llps_session_tmr_snapshot_t repaired;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 200);
    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(llps_session_tmr_snapshot_from_session(sess, &divergent));
    divergent.state = ST_FREE;
    llps_session_tmr_record_from_snapshot(&g_session_tmr_region0.records[sess_idx],
                                          0u,
                                          &divergent);

    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    llps_session_tmr_record_to_snapshot(&g_session_tmr_region0.records[sess_idx],
                                        &repaired);
    LLPS_TEST_ASSERT(repaired.state == ST_ACTIVE);
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(&g_session_tmr_region0.records[sess_idx],
                                                      0u,
                                                      sess_idx));
    LLPS_TEST_ASSERT(g_session_tmr_region0.records[sess_idx].record_crc_inverse ==
                     ~g_session_tmr_region0.records[sess_idx].record_crc);

    printf("test_llps_single_tmr_bank_fault_is_repaired passed.\n");
}

static void test_llps_single_tmr_record_crc_inverse_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 201);
    LLPS_TEST_ASSERT(llps_session_is_active(sess));

    g_session_tmr_region0.records[sess_idx].record_crc_inverse ^= 0x1u;
    LLPS_TEST_ASSERT(!llps_session_tmr_record_is_valid(
                         &g_session_tmr_region0.records[sess_idx],
                         0u,
                         sess_idx));

    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
                         &g_session_tmr_region0.records[sess_idx],
                         0u,
                         sess_idx));
    LLPS_TEST_ASSERT(g_session_tmr_region0.records[sess_idx].record_crc_inverse ==
                     ~g_session_tmr_region0.records[sess_idx].record_crc);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_single_bank_repairs >= 1u);

    printf("test_llps_single_tmr_record_crc_inverse_fault_is_repaired passed.\n");
}

static void test_llps_session_tmr_valid_no_majority_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    llps_session_tmr_snapshot_t snap0;
    llps_session_tmr_snapshot_t snap1;
    llps_session_tmr_snapshot_t snap2;
    llps_session_tmr_snapshot_t voted;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 410);
    sess->backend_fd = 411;
    llps_session_refresh_crc(sess);
    LLPS_TEST_ASSERT(llps_session_tmr_snapshot_from_session(sess, &snap0));

    snap1 = snap0;
    snap2 = snap0;
    snap0.client_fd = 410;
    snap0.backend_fd = 411;
    snap0.last_activity_ns = 1000u;
    snap1.client_fd = 412;
    snap1.backend_fd = 413;
    snap1.last_activity_ns = 2000u;
    snap2.client_fd = 414;
    snap2.backend_fd = 415;
    snap2.last_activity_ns = 3000u;

    llps_session_tmr_record_from_snapshot(&g_session_tmr_region0.records[sess_idx],
                                          0u,
                                          &snap0);
    llps_session_tmr_record_from_snapshot(&g_session_tmr_region1.records[sess_idx],
                                          1u,
                                          &snap1);
    llps_session_tmr_record_from_snapshot(&g_session_tmr_region2.records[sess_idx],
                                          2u,
                                          &snap2);

    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
                         &g_session_tmr_region0.records[sess_idx],
                         0u,
                         sess_idx));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
                         &g_session_tmr_region1.records[sess_idx],
                         1u,
                         sess_idx));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
                         &g_session_tmr_region2.records[sess_idx],
                         2u,
                         sess_idx));
    LLPS_TEST_ASSERT(!llps_session_tmr_vote(sess_idx, g_runtime_cfg.max_clients, &voted));
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_majority_failures >= 1u);

    printf("test_llps_session_tmr_valid_no_majority_fails_closed passed.\n");
}

static void test_llps_single_tmr_region_guard_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 210);
    LLPS_TEST_ASSERT(llps_session_is_active(sess));

    g_session_tmr_region0.pre_guard_pad[7] ^= 0xFFu;
    LLPS_TEST_ASSERT(!llps_session_tmr_region_guard_is_valid(0u));

    LLPS_TEST_ASSERT(llps_session_is_active(sess));
    LLPS_TEST_ASSERT(llps_session_tmr_region_guard_is_valid(0u));
    LLPS_TEST_ASSERT(g_session_tmr_region0.pre_guard_pad[7] ==
                     llps_session_tmr_guard_byte(0u, 7u, false));
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_region_guard_faults >= 1u);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.tmr_layout_valid);
    LLPS_TEST_ASSERT(report.tmr_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(report.tmr_region_guard_faults >= 1u);

    printf("test_llps_single_tmr_region_guard_fault_is_repaired passed.\n");
}

static void test_llps_tmr_startup_self_test_exercises_real_banks(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_counters_t counters;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    counters = g_memory_safety_counters;

    LLPS_TEST_ASSERT(llps_tmr_startup_self_test());
    LLPS_TEST_ASSERT(llps_tmr_startup_self_test_coverage_is_valid());
    LLPS_TEST_ASSERT(g_tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(memcmp(&counters,
                            &g_memory_safety_counters,
                            sizeof(counters)) == 0);
    LLPS_TEST_ASSERT(g_tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        &g_session_tmr_region0.records[0], 0u, 0u));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        &g_session_tmr_region1.records[0], 1u, 0u));
    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
        &g_session_tmr_region2.records[0], 2u, 0u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank1, 1u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank2, 2u));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank1, 1u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank2, 2u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank1, 1u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank2, 2u));
    LLPS_TEST_ASSERT(!llps_control_shutdown_is_requested());

    printf("test_llps_tmr_startup_self_test_exercises_real_banks passed.\n");
}

static void test_llps_single_runtime_cfg_bank_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_runtime_cfg.buffer_size = LLPS_BUFFER_SIZE + 1u;
    g_runtime_cfg_bank0.cfg.buffer_size = 64u;
    g_runtime_cfg_bank0.buffer_size_inverse = ~g_runtime_cfg_bank0.cfg.buffer_size;
    g_runtime_cfg_bank0.crc = llps_runtime_cfg_bank_compute_crc(&g_runtime_cfg_bank0);
    g_runtime_cfg_bank0.crc_inverse = ~g_runtime_cfg_bank0.crc;

    LLPS_TEST_ASSERT(llps_runtime_cfg_reconcile(&g_runtime_cfg));
    LLPS_TEST_ASSERT(g_runtime_cfg.buffer_size == cfg.buffer_size);
    LLPS_TEST_ASSERT(g_runtime_cfg_bank0.cfg.buffer_size == cfg.buffer_size);
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.runtime_cfg_tmr_valid);
    LLPS_TEST_ASSERT(report.runtime_cfg_single_bank_repairs >= 1u);

    printf("test_llps_single_runtime_cfg_bank_fault_is_repaired passed.\n");
}

static void test_llps_dual_runtime_cfg_bank_fault_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_runtime_cfg_bank0.magic_start = 0u;
    g_runtime_cfg_bank1.magic_start = 0u;

    LLPS_TEST_ASSERT(!llps_runtime_cfg_reconcile(&g_runtime_cfg));
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(!report.runtime_cfg_tmr_valid);
    LLPS_TEST_ASSERT(report.runtime_cfg_majority_failures >= 1u);

    printf("test_llps_dual_runtime_cfg_bank_fault_fails_closed passed.\n");
}

static void test_llps_runtime_cfg_valid_no_majority_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    llps_yml_config_t cfg0 = cfg;
    llps_yml_config_t cfg1 = cfg;
    llps_yml_config_t cfg2 = cfg;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    cfg0.buffer_size = 128u;
    cfg1.buffer_size = 64u;
    cfg2.buffer_size = 96u;
    llps_runtime_cfg_bank_from_config(&g_runtime_cfg_bank0, 0u, &cfg0);
    llps_runtime_cfg_bank_from_config(&g_runtime_cfg_bank1, 1u, &cfg1);
    llps_runtime_cfg_bank_from_config(&g_runtime_cfg_bank2, 2u, &cfg2);

    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank1, 1u));
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank2, 2u));
    LLPS_TEST_ASSERT(!llps_runtime_cfg_reconcile(&g_runtime_cfg));
    LLPS_TEST_ASSERT(g_memory_safety_counters.runtime_cfg_majority_failures >= 1u);

    printf("test_llps_runtime_cfg_valid_no_majority_fails_closed passed.\n");
}

static void test_llps_shutdown_request_is_tmr_replicated(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    llps_request_shutdown();

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank1, 1u));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank2, 2u));
    LLPS_TEST_ASSERT(g_control_flag_bank0.shutdown_requested == 1u);
    LLPS_TEST_ASSERT(g_control_flag_bank1.shutdown_requested == 1u);
    LLPS_TEST_ASSERT(g_control_flag_bank2.shutdown_requested == 1u);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.control_flag_tmr_valid);
    LLPS_TEST_ASSERT(report.shutdown_requested);

    printf("test_llps_shutdown_request_is_tmr_replicated passed.\n");
}

static void test_llps_single_control_flag_bank_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    llps_control_flag_bank_from_value(&g_control_flag_bank0, 0u, true);

    LLPS_TEST_ASSERT(!llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(g_control_flag_bank0.shutdown_requested == 0u);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.control_flag_tmr_valid);
    LLPS_TEST_ASSERT(!report.shutdown_requested);
    LLPS_TEST_ASSERT(report.control_flag_single_bank_repairs >= 1u);

    printf("test_llps_single_control_flag_bank_fault_is_repaired passed.\n");
}

static void test_llps_dual_control_flag_bank_fault_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_control_flag_bank0.magic_start = 0u;
    g_control_flag_bank1.magic_start = 0u;

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(!report.control_flag_tmr_valid);
    LLPS_TEST_ASSERT(report.shutdown_requested);
    LLPS_TEST_ASSERT(report.control_flag_majority_failures >= 1u);

    printf("test_llps_dual_control_flag_bank_fault_fails_closed passed.\n");
}

static void test_llps_readiness_gate_passes_with_complete_evidence(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1122334455667788ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.version == LLPS_PLATFORM_EVIDENCE_VERSION);
    LLPS_TEST_ASSERT(evidence.observed_flags ==
                     (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY |
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN));
    LLPS_TEST_ASSERT(evidence.attested_flags ==
                     (LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                      LLPS_PLATFORM_EVIDENCE_HW_TMR));
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint_inverse ==
                     ~evidence.attestation_fingerprint);
    LLPS_TEST_ASSERT(evidence.flags ==
                     (evidence.observed_flags | evidence.attested_flags));
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint_inverse ==
                     ~evidence.edac_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count_inverse ==
                     ~evidence.edac_controller_count);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count_inverse ==
                     ~evidence.edac_dimm_count);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count_inverse ==
                     ~evidence.edac_scrub_rate_count);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage_inverse ==
                     ~evidence.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage_inverse ==
                     ~evidence.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage_inverse ==
                     ~evidence.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage_inverse ==
                     ~evidence.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count_inverse ==
                     ~evidence.edac_corrected_error_count);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count_inverse ==
                     ~evidence.edac_uncorrected_error_count);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count_inverse ==
                     ~evidence.edac_dimm_corrected_error_count);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count_inverse ==
                     ~evidence.edac_dimm_uncorrected_error_count);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum == 1024u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum_inverse ==
                     ~evidence.edac_scrub_rate_sum);
    LLPS_TEST_ASSERT(evidence.platform_boot_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.platform_boot_fingerprint_inverse ==
                     ~evidence.platform_boot_fingerprint);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint_inverse ==
                     ~evidence.platform_identity_fingerprint);
    LLPS_TEST_ASSERT(evidence.executable_image_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.executable_image_fingerprint_inverse ==
                     ~evidence.executable_image_fingerprint);
    LLPS_TEST_ASSERT(evidence.process_memory_locked == 1u);
    LLPS_TEST_ASSERT(evidence.process_memory_locked_inverse ==
                     ~evidence.process_memory_locked);
    LLPS_TEST_ASSERT(evidence.tmr_memory_locked == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_locked_inverse ==
                     ~evidence.tmr_memory_locked);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefaulted == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefaulted_inverse ==
                     ~evidence.tmr_memory_prefaulted);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefault_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefault_pages_inverse ==
                     ~evidence.tmr_memory_prefault_pages);
    LLPS_TEST_ASSERT(evidence.tmr_memory_hardened == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_hardened_inverse ==
                     ~evidence.tmr_memory_hardened);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_passed == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_passed_inverse ==
                     ~evidence.tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_coverage_inverse ==
                     ~evidence.tmr_startup_self_test_coverage);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_required_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(
        evidence.tmr_startup_self_test_required_coverage_inverse ==
        ~evidence.tmr_startup_self_test_required_coverage);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint_inverse ==
                     ~evidence.physical_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage_inverse ==
                     ~evidence.physical_domain_topology_coverage);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count_inverse ==
                     ~evidence.physical_domain_observed_count);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib_inverse ==
                     ~evidence.physical_domain_memtotal_kib);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries_inverse ==
                     ~evidence.physical_domain_distance_entries);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum_inverse ==
                     ~evidence.physical_domain_distance_sum);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_pair_coverage ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(
        evidence.physical_domain_distance_pair_coverage_inverse ==
        ~evidence.physical_domain_distance_pair_coverage);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_01 == 30u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_01_inverse ==
                     ~evidence.physical_domain_distance_01);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_02 == 40u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_02_inverse ==
                     ~evidence.physical_domain_distance_02);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_12 == 50u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_12_inverse ==
                     ~evidence.physical_domain_distance_12);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint_inverse ==
                     ~evidence.tmr_memory_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_pages_checked != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_pages_checked_inverse ==
                     ~evidence.tmr_memory_domain_pages_checked);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_mismatch_count == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_mismatch_count_inverse ==
                     ~evidence.tmr_memory_domain_mismatch_count);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_probe_failures == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_probe_failures_inverse ==
                     ~evidence.tmr_memory_domain_probe_failures);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_region_coverage ==
                     LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_region_coverage_inverse ==
                     ~evidence.tmr_memory_domain_region_coverage);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident_inverse ==
                     ~evidence.tmr_memory_resident);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident_pages_inverse ==
                     ~evidence.tmr_memory_resident_pages);
    LLPS_TEST_ASSERT(evidence.tmr_memory_residency_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_residency_fingerprint_inverse ==
                     ~evidence.tmr_memory_residency_fingerprint);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_distinct == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_distinct_inverse ==
                     ~evidence.tmr_memory_physical_frames_distinct);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_spaced == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_spaced_inverse ==
                     ~evidence.tmr_memory_physical_frames_spaced);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pages_inverse ==
                     ~evidence.tmr_memory_physical_frame_pages);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_probe_failures == 0u);
    LLPS_TEST_ASSERT(
        evidence.tmr_memory_physical_frame_probe_failures_inverse ==
        ~evidence.tmr_memory_physical_frame_probe_failures);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_min_distance >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_min_distance_inverse ==
                     ~evidence.tmr_memory_physical_frame_min_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_required_distance !=
                     0u);
    LLPS_TEST_ASSERT(
        evidence.tmr_memory_physical_frame_required_distance_inverse ==
        ~evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pair_coverage ==
                     LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(
        evidence.tmr_memory_physical_frame_pair_coverage_inverse ==
        ~evidence.tmr_memory_physical_frame_pair_coverage);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_01 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_01_inverse ==
                     ~evidence.tmr_memory_physical_frame_distance_01);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_02 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_02_inverse ==
                     ~evidence.tmr_memory_physical_frame_distance_02);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_12 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_12_inverse ==
                     ~evidence.tmr_memory_physical_frame_distance_12);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_fingerprint_inverse ==
                     ~evidence.tmr_memory_physical_frame_fingerprint);
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        LLPS_TEST_ASSERT(evidence.tmr_memory_observed_domain_ids[i] ==
                         test_physical_memory_domains[i]);
        LLPS_TEST_ASSERT(evidence.tmr_memory_observed_domain_ids_inverse[i] ==
                         ~evidence.tmr_memory_observed_domain_ids[i]);
    }
    LLPS_TEST_ASSERT(evidence.tmr_layout_fingerprint ==
                     llps_tmr_layout_fingerprint());
    LLPS_TEST_ASSERT(evidence.tmr_layout_fingerprint_inverse ==
                     ~evidence.tmr_layout_fingerprint);
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);
    LLPS_TEST_ASSERT(evidence.observation_digest_inverse ==
                     ~evidence.observation_digest);
    LLPS_TEST_ASSERT(evidence.observation_digest ==
                     llps_platform_safety_evidence_compute_observation_digest(
                         &evidence));
    LLPS_TEST_ASSERT(evidence.crc != 0u);
    LLPS_TEST_ASSERT(evidence.crc_inverse == ~evidence.crc);
    LLPS_TEST_ASSERT(evidence.crc ==
                     llps_platform_safety_evidence_compute_crc(&evidence));

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.software_tmr_ready);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.platform_evidence_layout_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(report.platform_attestation_bound);
    LLPS_TEST_ASSERT(report.platform_boot_bound);
    LLPS_TEST_ASSERT(report.platform_identity_bound);
    LLPS_TEST_ASSERT(report.executable_image_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_boot_fingerprint ==
                     evidence.platform_boot_fingerprint);
    LLPS_TEST_ASSERT(report.platform_evidence_identity_fingerprint ==
                     evidence.platform_identity_fingerprint);
    LLPS_TEST_ASSERT(report.executable_image_fingerprint ==
                     evidence.executable_image_fingerprint);
    LLPS_TEST_ASSERT(report.platform_evidence_observation_digest ==
                     evidence.observation_digest);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(report.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(report.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_sum == 1024u);
    LLPS_TEST_ASSERT(report.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(report.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(report.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(report.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_pair_coverage ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(report.physical_domain_distance_01 == 30u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_02 == 40u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_12 == 50u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frames_distinct);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frames_spaced);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frame_pages >= 12u);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_probe_failures == 0u);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_min_distance >=
        report.memory.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_required_distance != 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frame_pair_coverage ==
                     LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_distance_01 >=
        report.memory.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_distance_02 >=
        report.memory.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_distance_12 >=
        report.memory.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(
        report.memory.tmr_memory_physical_frame_fingerprint != 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_domain_pages_checked != 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_domain_mismatch_count == 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_domain_probe_failures == 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_domain_region_coverage ==
                     LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
    LLPS_TEST_ASSERT(report.memory.contract_violations == 0u);
    LLPS_TEST_ASSERT(report.physical_memory_separation_ready);
    LLPS_TEST_ASSERT(report.independent_hardware_tmr_ready);
    LLPS_TEST_ASSERT(report.physical_memory_domains_distinct);
    LLPS_TEST_ASSERT(report.hardware_tmr_domains_distinct);
    LLPS_TEST_ASSERT(report.hardware_tmr_domains_independent);
    LLPS_TEST_ASSERT(report.missing_requirements == 0u);
    LLPS_TEST_ASSERT(report.gate_passed);
    LLPS_TEST_ASSERT(llps_require_readiness(&evidence) == LLPS_OK);

    printf("test_llps_readiness_gate_passes_with_complete_evidence passed.\n");
}

static void test_llps_synthetic_edac_fingerprint_binds_virtual_topology(void) {
    bool ecc_present_a = false;
    bool ecc_clean_a = false;
    bool ecc_present_b = false;
    bool ecc_clean_b = false;
    bool ecc_present_counter = false;
    bool ecc_clean_counter = false;
    bool ecc_present_topology = false;
    bool ecc_clean_topology = false;
    uint32_t fingerprint_a = 0u;
    uint32_t fingerprint_b = 0u;
    uint32_t fingerprint_counter = 0u;
    uint32_t fingerprint_topology = 0u;
    llps_edac_observation_t observation_a;
    llps_edac_observation_t observation_b;
    llps_edac_observation_t observation_counter;
    llps_edac_observation_t observation_topology;

    llps_edac_synthesize_ecc(2u,
                             4u,
                             8192u,
                             0u,
                             0u,
                             0u,
                             0u,
                             &ecc_present_a,
                             &ecc_clean_a,
                             &fingerprint_a,
                             &observation_a);
    llps_edac_synthesize_ecc(2u,
                             4u,
                             8192u,
                             0u,
                             0u,
                             0u,
                             0u,
                             &ecc_present_b,
                             &ecc_clean_b,
                             &fingerprint_b,
                             &observation_b);
    llps_edac_synthesize_ecc(2u,
                             4u,
                             8192u,
                             1u,
                             0u,
                             0u,
                             0u,
                             &ecc_present_counter,
                             &ecc_clean_counter,
                             &fingerprint_counter,
                             &observation_counter);
    llps_edac_synthesize_ecc(2u,
                             5u,
                             8192u,
                             0u,
                             0u,
                             0u,
                             0u,
                             &ecc_present_topology,
                             &ecc_clean_topology,
                             &fingerprint_topology,
                             &observation_topology);

    LLPS_TEST_ASSERT(ecc_present_a);
    LLPS_TEST_ASSERT(ecc_clean_a);
    LLPS_TEST_ASSERT(ecc_present_b);
    LLPS_TEST_ASSERT(ecc_clean_b);
    LLPS_TEST_ASSERT(fingerprint_a != 0u);
    LLPS_TEST_ASSERT(fingerprint_a == fingerprint_b);
    LLPS_TEST_ASSERT(observation_a.controller_count ==
                     observation_b.controller_count);
    LLPS_TEST_ASSERT(observation_a.dimm_count == observation_b.dimm_count);
    LLPS_TEST_ASSERT(observation_a.scrub_rate_sum ==
                     observation_b.scrub_rate_sum);

    LLPS_TEST_ASSERT(ecc_present_counter);
    LLPS_TEST_ASSERT(!ecc_clean_counter);
    LLPS_TEST_ASSERT(observation_counter.corrected_error_count == 1u);
    LLPS_TEST_ASSERT(fingerprint_counter != fingerprint_a);

    LLPS_TEST_ASSERT(ecc_present_topology);
    LLPS_TEST_ASSERT(ecc_clean_topology);
    LLPS_TEST_ASSERT(observation_topology.controller_count == 2u);
    LLPS_TEST_ASSERT(observation_topology.dimm_count == 5u);
    LLPS_TEST_ASSERT(fingerprint_topology != fingerprint_a);

    printf("test_llps_synthetic_edac_fingerprint_binds_virtual_topology passed.\n");
}

static void test_llps_software_platform_evidence_uses_configured_ecc_and_numa(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    const uint64_t memtotal_kib_per_domain = 65536u;

    reset_mocks();
    cfg = test_required_readiness_config();
    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_HYBRID;
    cfg.payload_ecc_enabled = 1u;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 2u;
    cfg.software_ecc_dimm_count = 4u;
    cfg.software_ecc_scrub_rate = 8192u;
    cfg.software_numa_enabled = 1u;
    cfg.software_numa_memtotal_kib = memtotal_kib_per_domain;
    cfg.software_numa_local_distance = 12u;
    cfg.software_numa_remote_distance = 24u;
    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);
    cfg.platform_observation_digest = evidence.observation_digest;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observed_flags ==
                     (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY |
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN));
    LLPS_TEST_ASSERT(evidence.edac_controller_count ==
                     cfg.software_ecc_controller_count);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 4u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count ==
                     cfg.software_ecc_controller_count);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum ==
                     (cfg.software_ecc_scrub_rate *
                      (uint64_t)cfg.software_ecc_controller_count));
    LLPS_TEST_ASSERT(evidence.platform_evidence_mode ==
                     LLPS_PLATFORM_EVIDENCE_MODE_HYBRID);
    LLPS_TEST_ASSERT(evidence.software_evidence_schema_version ==
                     LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    LLPS_TEST_ASSERT(evidence.software_evidence_self_test_passed == 1u);
    LLPS_TEST_ASSERT(
        evidence.software_evidence_self_test_coverage ==
        (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING));
    LLPS_TEST_ASSERT(
        evidence.software_evidence_self_test_required_coverage ==
        (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING));
    LLPS_TEST_ASSERT(evidence.software_ecc_controller_count ==
                     cfg.software_ecc_controller_count);
    LLPS_TEST_ASSERT(evidence.software_dimm_bank_count == 4u);
    LLPS_TEST_ASSERT(evidence.software_ecc_scrub_rate ==
                     cfg.software_ecc_scrub_rate);
    LLPS_TEST_ASSERT(
        evidence.software_dimm_fault_injection_coverage ==
        (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING));
    LLPS_TEST_ASSERT(evidence.software_fault_injection_mode ==
                     LLPS_SOFTWARE_FAULT_INJECTION_FULL);
    LLPS_TEST_ASSERT(evidence.software_dimm_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.software_numa_profile_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib ==
                     (memtotal_kib_per_domain *
                      (uint64_t)LLPS_SESSION_TMR_BANK_COUNT));
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum == 180u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_pair_coverage ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_01 == 24u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_02 == 24u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_12 == 24u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_distinct == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_spaced == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_mismatch_count == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_probe_failures == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_region_coverage ==
                     LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        LLPS_TEST_ASSERT(evidence.tmr_memory_observed_domain_ids[i] ==
                         cfg.platform_physical_memory_domains[i]);
    }

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.software_tmr_ready);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.software_evidence_self_test_ready);
    LLPS_TEST_ASSERT(report.payload_ecc_ready);
    LLPS_TEST_ASSERT(report.platform_evidence_mode ==
                     LLPS_PLATFORM_EVIDENCE_MODE_HYBRID);
    LLPS_TEST_ASSERT(report.software_evidence_schema_version ==
                     LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    LLPS_TEST_ASSERT(
        report.software_evidence_self_test_coverage ==
        (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
         LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING));
    LLPS_TEST_ASSERT(report.software_dimm_observation_fingerprint ==
                     evidence.software_dimm_observation_fingerprint);
    LLPS_TEST_ASSERT(report.software_ecc_controller_count ==
                     cfg.software_ecc_controller_count);
    LLPS_TEST_ASSERT(report.software_dimm_bank_count ==
                     cfg.software_ecc_dimm_count);
    LLPS_TEST_ASSERT(report.software_ecc_scrub_rate ==
                     cfg.software_ecc_scrub_rate);
    LLPS_TEST_ASSERT(report.software_dimm_generation ==
                     evidence.software_dimm_generation);
    LLPS_TEST_ASSERT(report.software_dimm_scrub_generation ==
                     evidence.software_dimm_scrub_generation);
    LLPS_TEST_ASSERT(report.software_dimm_fault_injection_coverage ==
                     evidence.software_dimm_fault_injection_coverage);
    LLPS_TEST_ASSERT(report.software_fault_injection_mode ==
                     evidence.software_fault_injection_mode);
    LLPS_TEST_ASSERT(report.software_numa_profile_fingerprint ==
                     evidence.software_numa_profile_fingerprint);
    LLPS_TEST_ASSERT(report.physical_domain_memtotal_kib ==
                     (memtotal_kib_per_domain *
                      (uint64_t)LLPS_SESSION_TMR_BANK_COUNT));
    LLPS_TEST_ASSERT(report.physical_domain_distance_entries ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(report.physical_domain_distance_sum == 180u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_01 == 24u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_02 == 24u);
    LLPS_TEST_ASSERT(report.physical_domain_distance_12 == 24u);
    LLPS_TEST_ASSERT(report.physical_memory_separation_ready);
    LLPS_TEST_ASSERT(report.independent_hardware_tmr_ready);
    LLPS_TEST_ASSERT(report.missing_requirements == 0u);
    LLPS_TEST_ASSERT(report.gate_passed);

    printf("test_llps_software_platform_evidence_uses_configured_ecc_and_numa passed.\n");
}

static void test_llps_software_platform_evidence_rejects_dirty_ecc_counter(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    const uint64_t memtotal_kib_per_domain = 65536u;

    reset_mocks();
    cfg = test_required_readiness_config();
    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_HYBRID;
    cfg.payload_ecc_enabled = 1u;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 2u;
    cfg.software_ecc_dimm_count = 4u;
    cfg.software_ecc_scrub_rate = 8192u;
    cfg.software_ecc_controller_corrected_error_count = 1u;
    cfg.software_numa_enabled = 1u;
    cfg.software_numa_memtotal_kib = memtotal_kib_per_domain;
    cfg.software_numa_local_distance = 12u;
    cfg.software_numa_remote_distance = 24u;
    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count ==
                     cfg.software_ecc_controller_count);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum ==
                     (cfg.software_ecc_scrub_rate *
                      (uint64_t)cfg.software_ecc_controller_count));
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);

    cfg.platform_observation_digest = evidence.observation_digest;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_STATE);

    printf("test_llps_software_platform_evidence_rejects_dirty_ecc_counter passed.\n");
}

static void test_llps_software_platform_evidence_rejects_stale_profile(void) {
    llps_yml_config_t cfg;
    llps_yml_config_t stale_cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    const uint64_t memtotal_kib_per_domain = 65536u;

    reset_mocks();
    cfg = test_required_readiness_config();
    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_HYBRID;
    cfg.payload_ecc_enabled = 1u;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 2u;
    cfg.software_ecc_dimm_count = 4u;
    cfg.software_ecc_scrub_rate = 8192u;
    cfg.software_numa_enabled = 1u;
    cfg.software_numa_memtotal_kib = memtotal_kib_per_domain;
    cfg.software_numa_local_distance = 12u;
    cfg.software_numa_remote_distance = 24u;
    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    test_prepare_platform_id_file(test_complete_platform_id_path,
                                  sizeof(test_complete_platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(test_complete_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observation_digest != 0u);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.software_evidence_self_test_ready);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.configured_platform_observation_digest_bound);
    LLPS_TEST_ASSERT(report.gate_passed);

    cfg.platform_observation_digest = evidence.observation_digest;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    stale_cfg = cfg;
    stale_cfg.software_ecc_controller_count = 3u;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    stale_cfg = cfg;
    stale_cfg.software_ecc_dimm_count = 5u;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    stale_cfg = cfg;
    stale_cfg.software_ecc_scrub_rate = 16384u;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    stale_cfg = cfg;
    stale_cfg.software_numa_memtotal_kib = memtotal_kib_per_domain * 2u;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_SEP) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    stale_cfg = cfg;
    stale_cfg.software_numa_remote_distance = 32u;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_SEP) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    stale_cfg = cfg;
    stale_cfg.software_fault_injection_mode =
        LLPS_SOFTWARE_FAULT_INJECTION_SINGLE;
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING) !=
                     0u);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    printf("test_llps_software_platform_evidence_rejects_stale_profile passed.\n");
}

static void
test_llps_software_platform_evidence_rejects_tampered_schema_version(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.software_evidence_schema_version ==
                     LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.software_evidence_self_test_ready);
    LLPS_TEST_ASSERT(report.gate_passed);

    evidence.software_evidence_schema_version =
        LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION + 1u;
    evidence.software_evidence_schema_version_inverse =
        ~evidence.software_evidence_schema_version;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_evidence_self_test_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);

    printf("test_llps_software_platform_evidence_rejects_tampered_schema_"
           "version passed.\n");
}

static void
test_llps_software_platform_evidence_rejects_missing_numa_profile_fingerprint(
    void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.software_numa_profile_fingerprint != 0u);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.gate_passed);

    evidence.software_numa_profile_fingerprint = 0u;
    evidence.software_numa_profile_fingerprint_inverse =
        ~evidence.software_numa_profile_fingerprint;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_evidence_self_test_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST) !=
                     0u);

    printf("test_llps_software_platform_evidence_rejects_missing_numa_"
           "profile_fingerprint passed.\n");
}

static void test_llps_readiness_report_marks_stale_evidence_request(void) {
    llps_yml_config_t cfg;
    llps_yml_config_t stale_cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    uint32_t stale_attestation = 0u;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(report.configured_platform_observation_digest_bound);
    LLPS_TEST_ASSERT(report.gate_passed);

    stale_cfg = cfg;
    stale_cfg.platform_safety_evidence_id ^= UINT64_C(0x100);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         stale_cfg.platform_safety_flags,
                         stale_cfg.platform_safety_evidence_id,
                         stale_cfg.platform_physical_memory_domains,
                         stale_cfg.platform_hardware_tmr_domains,
                         stale_cfg.platform_hardware_tmr_voter_domain,
                         &stale_attestation) == LLPS_OK);
    stale_cfg.platform_attestation_fingerprint = stale_attestation;

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&stale_cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.configured_evidence_request_bound);
    LLPS_TEST_ASSERT(report.configured_platform_observation_digest_bound);
    LLPS_TEST_ASSERT(report.gate_passed);
    LLPS_TEST_ASSERT(llps_init(&stale_cfg) == LLPS_E_STATE);

    printf("test_llps_readiness_report_marks_stale_evidence_request passed.\n");
}

static void test_llps_synthetic_platform_identity_replaces_missing_dmi(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    const char * const missing_platform_id_path =
        "/tmp/llps_missing_platform_identity_for_synthetic";

    reset_mocks();
    cfg = test_required_readiness_config();
    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC;
    cfg.payload_ecc_enabled = 1u;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 1u;
    cfg.software_ecc_dimm_count = 8u;
    cfg.software_ecc_scrub_rate = LLPS_SOFTWARE_ECC_SCRUB_RATE_DEFAULT;
    cfg.software_numa_enabled = 1u;
    cfg.software_numa_memtotal_kib = 65536u;

    test_prepare_boot_id_file(test_complete_boot_id_path,
                              sizeof(test_complete_boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(test_complete_boot_id_path);
    (void)remove(missing_platform_id_path);
    test_set_platform_id_path(missing_platform_id_path);
    test_prepare_executable_image_file(test_complete_executable_image_path,
                                       sizeof(test_complete_executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(test_complete_executable_image_path);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint_inverse ==
                     ~evidence.platform_identity_fingerprint);
    LLPS_TEST_ASSERT(llps_platform_identity_fingerprint(
                         missing_platform_id_path) == 0u);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_identity_bound);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PLATFORM_ID_BINDING) == 0u);

    test_remove_boot_id_file(test_complete_boot_id_path);
    test_remove_executable_image_file(test_complete_executable_image_path);

    printf("test_llps_synthetic_platform_identity_replaces_missing_dmi passed.\n");
}

static void test_llps_evidence_mac_authenticates_platform_evidence(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    llps_status_t collect_status = LLPS_OK;
    char key_path[128];
    int n = 0;
    bool mac_has_nonzero_byte = false;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    n = snprintf(key_path,
                 sizeof(key_path),
                 "/tmp/llps_evidence_mac_key_%lu.key",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(key_path));
    (void)remove(key_path);
    test_write_text_file(key_path, "llps-test-evidence-key");

    cfg = test_required_readiness_config();
    cfg.evidence_mac_enabled = 1u;
    n = snprintf(cfg.evidence_mac_key_path,
                 sizeof(cfg.evidence_mac_key_path),
                 "%s",
                 key_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.evidence_mac_key_path));

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    collect_status = test_make_complete_platform_evidence(
        cfg.platform_safety_evidence_id,
        &evidence);
    if (collect_status != LLPS_OK) {
        (void)fprintf(stderr,
                      "mac evidence collection status=%d\n",
                      (int)collect_status);
    }
    LLPS_TEST_ASSERT(collect_status == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.evidence_mac_enabled == 1u);
    LLPS_TEST_ASSERT(evidence.evidence_mac_key_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.evidence_mac_key_fingerprint_inverse ==
                     ~evidence.evidence_mac_key_fingerprint);
    for (uint32_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        mac_has_nonzero_byte =
            mac_has_nonzero_byte || (evidence.evidence_mac[i] != 0u);
        LLPS_TEST_ASSERT(evidence.evidence_mac_inverse[i] ==
                         (uint8_t)(~evidence.evidence_mac[i]));
    }
    LLPS_TEST_ASSERT(mac_has_nonzero_byte);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.evidence_mac_valid);

    evidence.evidence_mac[0] ^= 0x1u;
    evidence.evidence_mac_inverse[0] = (uint8_t)(~evidence.evidence_mac[0]);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.evidence_mac_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_MAC) != 0u);

    (void)remove(key_path);

    printf("test_llps_evidence_mac_authenticates_platform_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_disabled_runtime_monitor(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x123456789ABCDEF0ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.memory.readiness_runtime_monitor_enabled);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_RUNTIME_MONITOR) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_disabled_runtime_monitor passed.\n");
}

static void
test_llps_init_rejects_software_ecc_readiness_without_payload_ecc(void) {
    llps_yml_config_t cfg;

    reset_mocks();
    cfg = test_required_readiness_config();
    cfg.platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_HYBRID;
    cfg.software_ecc_enabled = 1u;
    cfg.software_ecc_controller_count = 1u;
    cfg.software_ecc_dimm_count = 4u;
    cfg.software_ecc_scrub_rate = LLPS_SOFTWARE_ECC_SCRUB_RATE_DEFAULT;
    cfg.payload_ecc_enabled = 0u;

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_RANGE);

    printf("test_llps_init_rejects_software_ecc_readiness_without_payload_ecc passed.\n");
}

static void test_llps_readiness_gate_rejects_missing_platform_evidence(void) {
    llps_yml_config_t cfg;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(NULL, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_SEP) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_LAYOUT_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_BOOT_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PLATFORM_ID_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EXECUTABLE_BINDING) != 0u);
    LLPS_TEST_ASSERT(llps_require_readiness(NULL) == LLPS_E_STATE);

    printf("test_llps_readiness_gate_rejects_missing_platform_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_broken_software_tmr(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x8877665544332211ULL,
                         &evidence) == LLPS_OK);

    g_runtime_cfg_bank0.magic_start = 0u;
    g_runtime_cfg_bank1.magic_start = 0u;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);
    LLPS_TEST_ASSERT(llps_require_readiness(&evidence) == LLPS_E_STATE);

    printf("test_llps_readiness_gate_rejects_broken_software_tmr passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x123456789ABCDEF0ULL,
                         &evidence) == LLPS_OK);

    evidence.flags &= ~LLPS_PLATFORM_EVIDENCE_ECC_MEMORY;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) == LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_evidence_crc_inverse(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x3141592653589793ULL,
                         &evidence) == LLPS_OK);

    evidence.crc_inverse ^= 0x1u;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_evidence_crc_inverse passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_observation_digest(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1020304050607080ULL,
                         &evidence) == LLPS_OK);

    evidence.observation_digest ^= 0x1u;
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_observation_digest passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_boot_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char stale_boot_id_path[128];
    const char *saved_boot_id_path = g_boot_id_path;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x2030405060708090ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.platform_boot_fingerprint != 0u);

    ++mock_llam_now_ns;
    test_prepare_boot_id_file(stale_boot_id_path,
                              sizeof(stale_boot_id_path),
                              "99999999-8888-7777-6666-555555555555\n");
    test_set_boot_id_path(stale_boot_id_path);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_boot_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_BOOT_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    test_set_boot_id_path(saved_boot_id_path);
    test_remove_boot_id_file(stale_boot_id_path);

    printf("test_llps_readiness_gate_rejects_stale_boot_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_platform_identity_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char stale_platform_id_path[128];
    const char *saved_platform_id_path = g_platform_id_path;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x30405060708090A0ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint != 0u);

    ++mock_llam_now_ns;
    test_prepare_platform_id_file(stale_platform_id_path,
                                  sizeof(stale_platform_id_path),
                                  "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb\n");
    test_set_platform_id_path(stale_platform_id_path);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_identity_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PLATFORM_ID_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    test_set_platform_id_path(saved_platform_id_path);
    test_remove_platform_id_file(stale_platform_id_path);

    printf("test_llps_readiness_gate_rejects_stale_platform_identity_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_executable_image_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char stale_executable_image_path[128];
    const char *saved_executable_image_path = g_executable_image_path;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x405060708090A0B0ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.executable_image_fingerprint != 0u);

    ++mock_llam_now_ns;
    test_prepare_executable_image_file(stale_executable_image_path,
                                       sizeof(stale_executable_image_path),
                                       "llps-test-image-v2\n");
    test_set_executable_image_path(stale_executable_image_path);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.executable_image_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EXECUTABLE_BINDING) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    test_set_executable_image_path(saved_executable_image_path);
    test_remove_executable_image_file(stale_executable_image_path);

    printf("test_llps_readiness_gate_rejects_stale_executable_image_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_layout_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0A0B0C0D0E0F0102ULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_layout_fingerprint ^= 0x1u;
    evidence.tmr_layout_fingerprint_inverse =
        ~evidence.tmr_layout_fingerprint;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_layout_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_LAYOUT_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_layout_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_edac_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char ce_path[200];
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0xF0E0D0C0B0A09080ULL,
                         &evidence) == LLPS_OK);

    n = snprintf(ce_path,
                 sizeof(ce_path),
                 "%s/mc0/ce_count",
                 test_complete_edac_root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(ce_path));
    test_write_text_file(ce_path, "1\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_edac_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_edac_scrub_rate_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0xCAFEBABE01020304ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum == 1024u);

    test_write_edac_controller_counter(test_complete_edac_root,
                                       "sdram_scrub_rate",
                                       "0\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_edac_scrub_rate_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_dimm_edac_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x200E0D0C0B0A0908ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);

    test_write_edac_dimm_counter(test_complete_edac_root,
                                 "dimm0",
                                 "dimm_ce_count",
                                 "1\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_dimm_edac_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_added_clean_dimm_edac_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x210E0D0C0B0A0908ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);

    test_add_edac_dimm_mode(test_complete_edac_root, "dimm1", "SECDED\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    test_remove_edac_tree(test_complete_edac_root);

    printf("test_llps_readiness_gate_rejects_added_clean_dimm_edac_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_edac_stats(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0xCAFEBABE11223344ULL,
                         &evidence) == LLPS_OK);

    evidence.edac_controller_count = 2u;
    evidence.edac_controller_count_inverse = ~evidence.edac_controller_count;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_edac_stats passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_physical_domain_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char online_path[160];
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0D0C0B0A09080706ULL,
                         &evidence) == LLPS_OK);

    n = snprintf(online_path,
                 sizeof(online_path),
                 "%s/online",
                 test_complete_numa_root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(online_path));
    test_write_text_file(online_path, "11,33\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_physical_domain_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_physical_domain_has_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char has_memory_path[160];
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x160D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    n = snprintf(has_memory_path,
                 sizeof(has_memory_path),
                 "%s/has_memory",
                 test_complete_numa_root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(has_memory_path));
    test_write_text_file(has_memory_path, "11,33\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_physical_domain_has_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_physical_domain_has_normal_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char has_normal_memory_path[180];
    int n = 0;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x190D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    n = snprintf(has_normal_memory_path,
                 sizeof(has_normal_memory_path),
                 "%s/has_normal_memory",
                 test_complete_numa_root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(has_normal_memory_path));
    test_write_text_file(has_normal_memory_path, "11,33\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_physical_domain_has_normal_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_physical_domain_meminfo(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x230D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_write_numa_node_meminfo(test_complete_numa_root,
                                 test_physical_memory_domains[1],
                                 "Node 22 MemTotal: 0 kB\n");

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_physical_domain_meminfo passed.\n");
}

static void test_llps_readiness_gate_rejects_missing_physical_domain_meminfo(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x240D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_remove_numa_node_meminfo(test_complete_numa_root,
                                  test_physical_memory_domains[2]);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_missing_physical_domain_meminfo passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_physical_domain_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char distance_text[256];

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x250D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_build_numa_distance_text(distance_text,
                                  sizeof(distance_text),
                                  test_physical_memory_domains,
                                  0u,
                                  false,
                                  1u,
                                  false);
    test_write_numa_node_distance(test_complete_numa_root,
                                  test_physical_memory_domains[0],
                                  distance_text);
    test_build_numa_distance_text(distance_text,
                                  sizeof(distance_text),
                                  test_physical_memory_domains,
                                  1u,
                                  false,
                                  1u,
                                  false);
    test_write_numa_node_distance(test_complete_numa_root,
                                  test_physical_memory_domains[1],
                                  distance_text);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_physical_domain_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_asymmetric_physical_domain_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char distance_text[256];

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x270D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_build_numa_distance_text(distance_text,
                                  sizeof(distance_text),
                                  test_physical_memory_domains,
                                  0u,
                                  false,
                                  0u,
                                  true);
    test_write_numa_node_distance(test_complete_numa_root,
                                  test_physical_memory_domains[0],
                                  distance_text);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_asymmetric_physical_domain_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_flat_physical_domain_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char distance_text[256];

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x280D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_build_numa_distance_text(distance_text,
                                  sizeof(distance_text),
                                  test_physical_memory_domains,
                                  2u,
                                  true,
                                  0u,
                                  false);
    test_write_numa_node_distance(test_complete_numa_root,
                                  test_physical_memory_domains[2],
                                  distance_text);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_flat_physical_domain_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_missing_physical_domain_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x260D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);

    test_remove_numa_node_distance(test_complete_numa_root,
                                   test_physical_memory_domains[1]);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_missing_physical_domain_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_physical_domain_topology_stats(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x290D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);

    evidence.physical_domain_topology_coverage = 0u;
    evidence.physical_domain_topology_coverage_inverse =
        ~evidence.physical_domain_topology_coverage;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_physical_domain_topology_stats passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_physical_domain_pair_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x2A0D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_pair_coverage ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_01 == 30u);

    evidence.physical_domain_distance_01 = 31u;
    evidence.physical_domain_distance_01_inverse =
        ~evidence.physical_domain_distance_01;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_physical_domain_pair_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_physical_domain_distance_sum(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x2B0D0C0B0A090807ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_pair_coverage ==
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum >
                     ((evidence.physical_domain_distance_01 +
                       evidence.physical_domain_distance_02 +
                       evidence.physical_domain_distance_12) * 2u));

    evidence.physical_domain_distance_sum = 1u;
    evidence.physical_domain_distance_sum_inverse =
        ~evidence.physical_domain_distance_sum;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_physical_domain_distance_sum passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_tmr_memory_domain_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0BADC0DE0BADC0DEULL,
                         &evidence) == LLPS_OK);

    g_tmr_memory_domain_probe_override_domains[1] =
        test_physical_memory_domains[2];

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_tmr_memory_domain_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_tmr_observed_domains(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0102030405060708ULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_memory_observed_domain_ids[1] =
        test_physical_memory_domains[2];
    evidence.tmr_memory_observed_domain_ids_inverse[1] =
        ~evidence.tmr_memory_observed_domain_ids[1];
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_observed_domains passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_tmr_domain_probe_stats(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0102030405060709ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_pages_checked != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_mismatch_count == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_probe_failures == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_region_coverage ==
                     LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);

    evidence.tmr_memory_domain_region_coverage = 0u;
    evidence.tmr_memory_domain_region_coverage_inverse =
        ~evidence.tmr_memory_domain_region_coverage;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_domain_probe_stats passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_tmr_residency_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1123581321345589ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_residency_fingerprint != 0u);

    g_tmr_memory_residency_probe_override_enabled = true;
    g_tmr_memory_residency_probe_override_resident = false;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_resident);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_tmr_residency_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_tmr_residency_fingerprint(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1223344556677889ULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_memory_residency_fingerprint ^= 0x1u;
    evidence.tmr_memory_residency_fingerprint_inverse =
        ~evidence.tmr_memory_residency_fingerprint;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_residency_fingerprint passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_tmr_physical_frame_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x2233445566778899ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_distinct == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_spaced == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_fingerprint != 0u);

    g_tmr_physical_frame_probe_override_alias = true;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_physical_frames_distinct);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_physical_frames_spaced);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_tmr_physical_frame_evidence passed.\n");
}

static void
test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_fingerprint(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x33445566778899AAULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_memory_physical_frame_fingerprint ^= 0x1u;
    evidence.tmr_memory_physical_frame_fingerprint_inverse =
        ~evidence.tmr_memory_physical_frame_fingerprint;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frames_distinct);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frames_spaced);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_"
           "fingerprint passed.\n");
}

static void
test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x445566778899AABBULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_min_distance >=
                     evidence.tmr_memory_physical_frame_required_distance);

    evidence.tmr_memory_physical_frame_min_distance = 0u;
    evidence.tmr_memory_physical_frame_min_distance_inverse =
        ~evidence.tmr_memory_physical_frame_min_distance;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frames_spaced);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_"
           "distance passed.\n");
}

static void
test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_pair_distance(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x5566778899AABBCCULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pair_coverage ==
                     LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);

    evidence.tmr_memory_physical_frame_distance_01 = 0u;
    evidence.tmr_memory_physical_frame_distance_01_inverse =
        ~evidence.tmr_memory_physical_frame_distance_01;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_physical_frame_pair_coverage ==
                     LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_"
           "pair_distance passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_memory_hardening_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x13579BDF2468ACE0ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_memory_hardened == 1u);

    llps_tmr_memory_hardened_set(false);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_hardened);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_memory_hardening_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_prefault_page_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x02468ACE13579BDFULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_memory_prefault_pages ^= 0x1u;
    evidence.tmr_memory_prefault_pages_inverse =
        ~evidence.tmr_memory_prefault_pages;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_prefault_page_evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_tmr_self_test_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0xABCDEF0123456789ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_passed == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);

    llps_tmr_startup_self_test_passed_set(false);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_tmr_self_test_evidence passed.\n");
}

static void
test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage_evidence(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1029384756ABCDEFULL,
                         &evidence) == LLPS_OK);

    evidence.tmr_startup_self_test_coverage ^=
        LLPS_TMR_SELF_TEST_SESSION_NO_MAJORITY_FAIL_CLOSED;
    evidence.tmr_startup_self_test_coverage_inverse =
        ~evidence.tmr_startup_self_test_coverage;
    evidence.observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(&evidence);
    evidence.observation_digest_inverse = ~evidence.observation_digest;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(report.memory.tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(report.memory.tmr_startup_self_test_coverage_valid);
    LLPS_TEST_ASSERT(report.memory.tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_EVIDENCE_VALID) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage_"
           "evidence passed.\n");
}

static void test_llps_readiness_gate_rejects_stale_attestation(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0101010102020202ULL,
                         &evidence) == LLPS_OK);

    evidence.attestation_fingerprint ^= 0x1u;
    evidence.attestation_fingerprint_inverse =
        ~evidence.attestation_fingerprint;
    test_reseal_platform_evidence(&evidence);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_attestation_bound);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ATTESTATION_BINDING) != 0u);

    printf("test_llps_readiness_gate_rejects_stale_attestation passed.\n");
}

static void test_llps_public_evidence_builder_rejects_manual_ecc_claims(void) {
    llps_platform_safety_evidence_t evidence;
    char numa_root[128];
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x8899AABBCCDDEEFFULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_ECC_MEMORY,
                         0x0101010102020202ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x1020304050607080ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.observed_flags == 0u);
    LLPS_TEST_ASSERT(evidence.attested_flags ==
                     (LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                      LLPS_PLATFORM_EVIDENCE_HW_TMR));
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint_inverse ==
                     ~evidence.attestation_fingerprint);
    LLPS_TEST_ASSERT(evidence.hardware_tmr_voter_domain_id ==
                     test_hardware_tmr_voter_domain);
    LLPS_TEST_ASSERT(evidence.hardware_tmr_voter_domain_id_inverse ==
                     ~evidence.hardware_tmr_voter_domain_id);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint_inverse ==
                     ~evidence.physical_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint_inverse ==
                     ~evidence.tmr_memory_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x1020304050607081ULL,
                         test_physical_memory_domains,
                         test_overlapping_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_E_RANGE);

    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_public_evidence_builder_rejects_manual_ecc_claims passed.\n");
}

static void test_llps_platform_evidence_rejects_missing_domain_attestation(void) {
    llps_platform_safety_evidence_t evidence;
    uint32_t fingerprint = 0u;
    const uint32_t duplicate_domains[LLPS_SESSION_TMR_BANK_COUNT] =
        { 11u, 11u, 33u };
    const uint32_t zero_domains[LLPS_SESSION_TMR_BANK_COUNT] =
        { 0u, 0u, 0u };
    const uint32_t hw_voter_overlaps_hardware = 101u;
    const uint32_t hw_voter_overlaps_physical = 11u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0xABCDEF0123456789ULL,
                         &evidence) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x0123456789ABCDEFULL,
                         duplicate_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDEFULL,
                         test_physical_memory_domains,
                         test_overlapping_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &fingerprint) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(fingerprint == 0u);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF4ULL,
                         zero_domains,
                         test_hardware_tmr_domains,
                         hw_voter_overlaps_hardware,
                         &fingerprint) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(fingerprint == 0u);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF5ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         hw_voter_overlaps_physical,
                         &fingerprint) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(fingerprint == 0u);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF0ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &fingerprint) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(fingerprint == 0u);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP,
                         0x0123456789ABCDF1ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &fingerprint) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(fingerprint == 0u);
    LLPS_TEST_ASSERT(llps_compute_platform_attestation_fingerprint(
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF2ULL,
                         zero_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &fingerprint) == LLPS_OK);
    LLPS_TEST_ASSERT(fingerprint != 0u);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF3ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_E_RANGE);
    LLPS_TEST_ASSERT(llps_make_platform_safety_evidence_ex(
                         LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                         LLPS_PLATFORM_EVIDENCE_HW_TMR,
                         0x0123456789ABCDF6ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         hw_voter_overlaps_hardware,
                         &evidence) == LLPS_E_RANGE);

    printf("test_llps_platform_evidence_rejects_missing_domain_attestation passed.\n");
}

static void test_llps_readiness_gate_rejects_unlocked_process_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    mock_mlockall_ret = -1;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(!g_process_memory_locked);
    LLPS_TEST_ASSERT(g_memory_safety_counters.process_memory_lock_failures == 1u);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0xBADC0FFEE0DDF00DULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.process_memory_locked);
    LLPS_TEST_ASSERT(report.memory.process_memory_lock_failures == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_unlocked_process_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_unlocked_tmr_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    mock_mlock_ret = -1;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(!g_tmr_memory_locked);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_memory_lock_failures == 1u);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0F0E0D0C0B0A0908ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_locked);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_lock_failures == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_unlocked_tmr_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_unhardened_tmr_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    mock_madvise_ret = -1;
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(g_tmr_memory_locked);
    LLPS_TEST_ASSERT(!g_tmr_memory_hardened);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_memory_harden_failures == 1u);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x1020304050607080ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_hardened);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_harden_failures == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_unhardened_tmr_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_unprefaulted_tmr_memory(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    g_tmr_memory_prefaulted = false;
    g_tmr_memory_prefault_pages = 0u;
    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_prefault_failures);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x8877665544332200ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_prefaulted);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_prefault_pages_valid);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_prefault_pages == 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_prefault_failures == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_unprefaulted_tmr_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_tmr_prefault_pages(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    g_tmr_memory_prefault_pages ^= 1u;
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x4776655443322110ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.runtime_safety_latches_valid);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_prefault_pages_valid);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_prefault_pages == 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_prefault_pages passed.\n");
}

static void test_llps_readiness_gate_rejects_nonresident_tmr_memory(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0102030405060709ULL,
                         &evidence) == LLPS_OK);

    g_tmr_memory_residency_probe_override_enabled = true;
    g_tmr_memory_residency_probe_override_resident = false;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_resident);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_resident_pages == 0u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_residency_failures >= 1u);
    LLPS_TEST_ASSERT(report.memory.tmr_memory_residency_fingerprint != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_nonresident_tmr_memory passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_runtime_safety_latch(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    g_tmr_memory_locked_inverse ^= 1u;
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0102030405060708ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.runtime_safety_latches_valid);
    LLPS_TEST_ASSERT(!report.memory.tmr_memory_locked);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_runtime_safety_latch passed.\n");
}

static void test_llps_readiness_gate_rejects_contract_violation(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    LLPS_EXPECT(false, (void)0);
    LLPS_TEST_ASSERT(g_memory_safety_counters.contract_violations == 1u);
    LLPS_TEST_ASSERT(llps_memory_safety_counters_are_valid());

    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x0102030405060710ULL,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(report.memory.contract_violations == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_contract_violation passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_memory_safety_counter_seal(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x010203040506070AULL,
                         &evidence) == LLPS_OK);

    g_memory_safety_counters_crc ^= 1u;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.memory_safety_counters_valid);
    LLPS_TEST_ASSERT(report.memory.memory_safety_counters_fingerprint != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_memory_safety_counter_seal passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_memory_safety_counter_value(void) {
    llps_yml_config_t cfg;
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x010203040506070BULL,
                         &evidence) == LLPS_OK);

    g_memory_safety_counters.tmr_single_bank_repairs ^= 1u;

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.memory_safety_counters_valid);
    LLPS_TEST_ASSERT(report.memory.tmr_single_bank_repairs == 1u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_memory_safety_counter_value passed.\n");
}

static void test_llps_readiness_gate_rejects_failed_tmr_self_test(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    g_tmr_startup_self_test_passed = false;
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x9988776655443322ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_failed_tmr_self_test passed.\n");
}

static void test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    g_tmr_startup_self_test_coverage ^=
        LLPS_TMR_SELF_TEST_SESSION_NO_MAJORITY_FAIL_CLOSED;
    LLPS_TEST_ASSERT(test_make_complete_platform_evidence(
                         0x8877665544332211ULL,
                         &evidence) == LLPS_OK);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(!report.software_tmr_ready);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT(!report.memory.tmr_startup_self_test_coverage_valid);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_SOFTWARE_TMR) != 0u);

    printf("test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage passed.\n");
}

static void test_llps_init_enforces_required_readiness_with_clean_edac(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(g_tmr_startup_self_test_passed);
    LLPS_TEST_ASSERT(g_tmr_memory_domains_bound);
    LLPS_TEST_ASSERT(g_tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(llps_tmr_memory_observed_domains_are_valid());
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        LLPS_TEST_ASSERT(g_tmr_memory_observed_domain_ids[i] ==
                         test_physical_memory_domains[i]);
    }

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_init_enforces_required_readiness_with_clean_edac passed.\n");
}

static void test_llps_init_rejects_required_readiness_without_ecc_evidence(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    test_set_edac_sysfs_root("/tmp/llps_missing_edac_root_for_required_init");

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_STATE);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_init_rejects_required_readiness_without_ecc_evidence passed.\n");
}

static void test_llps_init_rejects_required_readiness_without_tmr_memory_domain_binding(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    g_tmr_memory_domain_probe_override_domains[1] =
        test_physical_memory_domains[2];

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_STATE);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_init_rejects_required_readiness_without_tmr_memory_domain_binding passed.\n");
}

static void test_llps_memory_report_refreshes_tmr_memory_domain_binding_fault(void) {
    llps_yml_config_t cfg;
    llps_memory_safety_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;
    uint32_t initial_fingerprint = 0u;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.readiness_runtime_monitor_enabled);
    LLPS_TEST_ASSERT(report.tmr_memory_domains_bound);
    LLPS_TEST_ASSERT(report.tmr_memory_observed_domains_valid);
    LLPS_TEST_ASSERT(report.tmr_memory_domain_bind_failures == 0u);
    LLPS_TEST_ASSERT(report.tmr_memory_domain_observation_fingerprint != 0u);
    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        LLPS_TEST_ASSERT(report.tmr_memory_observed_domain_ids[i] ==
                         test_physical_memory_domains[i]);
    }
    initial_fingerprint = report.tmr_memory_domain_observation_fingerprint;

    g_tmr_memory_domain_probe_override_domains[1] =
        test_physical_memory_domains[2];

    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.readiness_runtime_monitor_enabled);
    LLPS_TEST_ASSERT(!report.tmr_memory_domains_bound);
    LLPS_TEST_ASSERT(report.tmr_memory_observed_domains_valid);
    LLPS_TEST_ASSERT(report.tmr_memory_domain_bind_failures >= 1u);
    LLPS_TEST_ASSERT(report.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(report.tmr_memory_domain_observation_fingerprint !=
                     initial_fingerprint);
    LLPS_TEST_ASSERT(report.tmr_memory_observed_domain_ids[0] ==
                     test_physical_memory_domains[0]);
    LLPS_TEST_ASSERT(report.tmr_memory_observed_domain_ids[1] ==
                     test_physical_memory_domains[2]);
    LLPS_TEST_ASSERT(report.tmr_memory_observed_domain_ids[2] ==
                     test_physical_memory_domains[2]);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_memory_report_refreshes_tmr_memory_domain_binding_fault passed.\n");
}

static void test_llps_init_for_diagnostics_reports_missing_ecc_without_gate_failure(void) {
    const llps_yml_config_t cfg = test_required_readiness_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_set_edac_sysfs_root("/tmp/llps_missing_edac_root_for_diag_init");
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_STATE);

    reset_mocks();
    test_set_edac_sysfs_root("/tmp/llps_missing_edac_root_for_diag_init");
    test_set_numa_sysfs_root(numa_root);
    test_enable_tmr_memory_domain_override(test_physical_memory_domains);

    LLPS_TEST_ASSERT(llps_init_for_diagnostics(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         cfg.platform_safety_flags,
                         cfg.platform_safety_evidence_id,
                         cfg.platform_physical_memory_domains,
                         cfg.platform_hardware_tmr_domains,
                         cfg.platform_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.memory.readiness_runtime_monitor_enabled);
    LLPS_TEST_ASSERT(report.software_tmr_ready);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_init_for_diagnostics_reports_missing_ecc_without_gate_failure passed.\n");
}

static void test_llps_init_rejects_required_readiness_with_stale_attestation(void) {
    llps_yml_config_t cfg = test_required_readiness_config();

    reset_mocks();
    cfg.platform_attestation_fingerprint ^= 0x1u;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_RANGE);

    printf("test_llps_init_rejects_required_readiness_with_stale_attestation passed.\n");
}

static void test_llps_init_rejects_required_readiness_with_stale_observation_digest(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(cfg.platform_observation_digest != 0u);
    cfg.platform_observation_digest ^= 0x1u;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_E_STATE);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_init_rejects_required_readiness_with_stale_observation_digest passed.\n");
}

static void test_llps_collect_platform_evidence_from_clean_edac(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char boot_id_path[128];
    char platform_id_path[128];
    char executable_image_path[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_boot_id_path = g_boot_id_path;
    const char *saved_platform_id_path = g_platform_id_path;
    const char *saved_executable_image_path = g_executable_image_path;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_boot_id_file(boot_id_path,
                              sizeof(boot_id_path),
                              "11111111-2222-3333-4444-555555555555\n");
    test_set_boot_id_path(boot_id_path);
    test_prepare_platform_id_file(platform_id_path,
                                  sizeof(platform_id_path),
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    test_set_platform_id_path(platform_id_path);
    test_prepare_executable_image_file(executable_image_path,
                                       sizeof(executable_image_path),
                                       "llps-test-image-v1\n");
    test_set_executable_image_path(executable_image_path);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x0102030405060708ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT(evidence.flags == LLPS_PLATFORM_EVIDENCE_REQUIRED);
    LLPS_TEST_ASSERT(evidence.observed_flags ==
                     (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY |
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN));
    LLPS_TEST_ASSERT(evidence.attested_flags ==
                     (LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                      LLPS_PLATFORM_EVIDENCE_HW_TMR));
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint_inverse ==
                     ~evidence.attestation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint_inverse ==
                     ~evidence.edac_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum == 1024u);
    LLPS_TEST_ASSERT(evidence.platform_boot_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.platform_identity_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.executable_image_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint_inverse ==
                     ~evidence.physical_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint_inverse ==
                     ~evidence.tmr_memory_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_pages_checked != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_mismatch_count == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_probe_failures == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_region_coverage ==
                     LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_resident_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_residency_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_residency_fingerprint_inverse ==
                     ~evidence.tmr_memory_residency_fingerprint);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_distinct == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frames_spaced == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_probe_failures == 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_min_distance >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_pair_coverage ==
                     LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_01 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_02 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_distance_12 >=
                     evidence.tmr_memory_physical_frame_required_distance);
    LLPS_TEST_ASSERT(evidence.tmr_memory_physical_frame_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.process_memory_locked == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_locked == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefaulted == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_prefault_pages >= 12u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_hardened == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_passed == 1u);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(evidence.tmr_startup_self_test_required_coverage ==
                     LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(report.platform_attestation_bound);
    LLPS_TEST_ASSERT(report.platform_boot_bound);
    LLPS_TEST_ASSERT(report.platform_identity_bound);
    LLPS_TEST_ASSERT(report.executable_image_bound);
    LLPS_TEST_ASSERT(report.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(report.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_count == 1u);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(report.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_sum == 1024u);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_RUNTIME_MONITOR) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_boot_id_path(saved_boot_id_path);
    test_set_platform_id_path(saved_platform_id_path);
    test_set_executable_image_path(saved_executable_image_path);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_boot_id_file(boot_id_path);
    test_remove_platform_id_file(platform_id_path);
    test_remove_executable_image_file(executable_image_path);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_from_clean_edac passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_dirty_edac(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "1\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x0807060504030201ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.attested_flags ==
                     (LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                      LLPS_PLATFORM_EVIDENCE_HW_TMR));
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint_inverse ==
                     ~evidence.attestation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint_inverse ==
                     ~evidence.edac_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint_inverse ==
                     ~evidence.physical_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint_inverse ==
                     ~evidence.tmr_memory_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(report.platform_attestation_bound);
    LLPS_TEST_ASSERT(report.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(report.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(report.edac_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(report.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_dimm_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_dirty_edac passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_dirty_dimm_edac(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_write_edac_dimm_counter(edac_root, "dimm0", "dimm_ce_count", "1\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2008070605040302ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_uncorrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(report.edac_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(report.edac_dimm_corrected_error_count == 1u);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_dirty_dimm_edac passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_missing_dimm_counter(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_remove_edac_dimm_counter(edac_root, "dimm0", "dimm_ue_count");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2118070605040302ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage_inverse ==
                     ~evidence.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_corrected_error_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_uncorrected_error_count == 0u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(!report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_missing_dimm_counter passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_missing_controller_counter(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_remove_edac_controller_counter(edac_root, "ue_count");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2128070605040302ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage_inverse ==
                     ~evidence.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(!report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_missing_controller_counter passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_missing_edac_scrub_rate(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_remove_edac_controller_counter(edac_root, "sdram_scrub_rate");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2138070605040302ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_count == 0u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_sum == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 0u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(!report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_CLEAN) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_missing_edac_scrub_rate passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_none_ecc_mode(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree_with_mode(edac_root,
                                     sizeof(edac_root),
                                     "0\n",
                                     "0\n",
                                     "None\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x1112131415161718ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.attested_flags ==
                     (LLPS_PLATFORM_EVIDENCE_PHYS_SEP |
                      LLPS_PLATFORM_EVIDENCE_HW_TMR));
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.attestation_fingerprint_inverse ==
                     ~evidence.attestation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint_inverse ==
                     ~evidence.edac_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_observation_fingerprint_inverse ==
                     ~evidence.physical_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(evidence.physical_domain_topology_coverage ==
                     LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK);
    LLPS_TEST_ASSERT(evidence.physical_domain_observed_count ==
                     LLPS_SESSION_TMR_BANK_COUNT);
    LLPS_TEST_ASSERT(evidence.physical_domain_memtotal_kib != 0u);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_entries >=
                     LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    LLPS_TEST_ASSERT(evidence.physical_domain_distance_sum != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.tmr_memory_domain_observation_fingerprint_inverse ==
                     ~evidence.tmr_memory_domain_observation_fingerprint);
    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_physical_domain_bound);
    LLPS_TEST_ASSERT(report.platform_evidence_tmr_memory_domain_bound);
    LLPS_TEST_ASSERT(report.platform_attestation_bound);
    LLPS_TEST_ASSERT(report.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(report.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_none_ecc_mode passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_unrecognized_ecc_mode(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree_with_mode(edac_root,
                                     sizeof(edac_root),
                                     "0\n",
                                     "0\n",
                                     "Parity\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2122232425262728ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_unrecognized_ecc_mode passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_negated_ecc_modes(void) {
    const char * const mode_texts[2] = { "non-ecc\n", "ECC disabled\n" };
    const uint64_t evidence_ids[2] = {
        0x3132333435363738ULL,
        0x4142434445464748ULL
    };

    for (size_t i = 0u; i < 2u; ++i) {
        const llps_yml_config_t cfg = test_config();
        llps_platform_safety_evidence_t evidence;
        llps_readiness_report_t report;
        char edac_root[128];
        char numa_root[128];

        reset_mocks();
        mock_llam_now_ns += (uint64_t)i;
        test_prepare_edac_tree_with_mode(edac_root,
                                         sizeof(edac_root),
                                         "0\n",
                                         "0\n",
                                         mode_texts[i]);
        test_set_edac_sysfs_root(edac_root);
        test_prepare_numa_tree(numa_root,
                               sizeof(numa_root),
                               test_physical_memory_domains);
        test_set_numa_sysfs_root(numa_root);

        LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
        LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                             LLPS_PLATFORM_EVIDENCE_REQUIRED,
                             evidence_ids[i],
                             test_physical_memory_domains,
                             test_hardware_tmr_domains,
                             test_hardware_tmr_voter_domain,
                             &evidence) == LLPS_OK);
        LLPS_TEST_ASSERT((evidence.observed_flags &
                          LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
        LLPS_TEST_ASSERT((evidence.observed_flags &
                          LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
        LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
        LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
        LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
        LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 1u);
        LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
        LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);

        LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                         LLPS_OK);
        LLPS_TEST_ASSERT(report.platform_evidence_valid);
        LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
        LLPS_TEST_ASSERT(!report.ecc_memory_ready);
        LLPS_TEST_ASSERT(!report.ecc_counters_clean);
        LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
        LLPS_TEST_ASSERT(report.edac_dimm_mode_coverage);
        LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
        LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
        LLPS_TEST_ASSERT(!report.gate_passed);
        LLPS_TEST_ASSERT((report.missing_requirements &
                          LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);

        test_remove_edac_tree(edac_root);
        test_remove_numa_tree(numa_root, test_physical_memory_domains);
    }

    reset_mocks();
    printf("test_llps_collect_platform_evidence_rejects_negated_ecc_modes passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_missing_ecc_mode(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree_with_mode(edac_root,
                                     sizeof(edac_root),
                                     "0\n",
                                     "0\n",
                                     NULL);
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x1817161514131211ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(!report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_missing_ecc_mode passed.\n");
}

static void test_llps_collect_platform_evidence_rejects_partial_missing_ecc_mode(void) {
    const llps_yml_config_t cfg = test_config();
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_add_edac_dimm_mode(edac_root, "dimm1", NULL);
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_collect_platform_safety_evidence(
                         LLPS_PLATFORM_EVIDENCE_REQUIRED,
                         0x2112131415161718ULL,
                         test_physical_memory_domains,
                         test_hardware_tmr_domains,
                         test_hardware_tmr_voter_domain,
                         &evidence) == LLPS_OK);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u);
    LLPS_TEST_ASSERT((evidence.observed_flags &
                      LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_count == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_count == 2u);
    LLPS_TEST_ASSERT(evidence.edac_observation_fingerprint != 0u);
    LLPS_TEST_ASSERT(evidence.edac_controller_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_mode_coverage == 0u);
    LLPS_TEST_ASSERT(evidence.edac_dimm_counter_coverage == 1u);
    LLPS_TEST_ASSERT(evidence.edac_scrub_rate_coverage == 1u);

    LLPS_TEST_ASSERT(llps_get_readiness_report(&evidence, &report) ==
                     LLPS_OK);
    LLPS_TEST_ASSERT(report.platform_evidence_valid);
    LLPS_TEST_ASSERT(!report.platform_evidence_edac_bound);
    LLPS_TEST_ASSERT(!report.ecc_memory_ready);
    LLPS_TEST_ASSERT(!report.ecc_counters_clean);
    LLPS_TEST_ASSERT(report.edac_dimm_count == 2u);
    LLPS_TEST_ASSERT(report.edac_controller_counter_coverage);
    LLPS_TEST_ASSERT(!report.edac_dimm_mode_coverage);
    LLPS_TEST_ASSERT(report.edac_dimm_counter_coverage);
    LLPS_TEST_ASSERT(report.edac_scrub_rate_coverage);
    LLPS_TEST_ASSERT(!report.gate_passed);
    LLPS_TEST_ASSERT((report.missing_requirements &
                      LLPS_READINESS_MISSING_ECC_MEMORY) != 0u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_collect_platform_evidence_rejects_partial_missing_ecc_mode passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_dirty_edac(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char ce_path[200];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    int n = 0;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 320);
    sess->backend_fd = 321;
    llps_session_refresh_crc(sess);

    n = snprintf(ce_path, sizeof(ce_path), "%s/mc0/ce_count", edac_root);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(ce_path));
    test_write_text_file(ce_path, "1\n");

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_ecc_failures >= 1u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_watchdog_fails_closed_on_runtime_dirty_edac passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_tmr_memory_domain_fault(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 325);
    sess->backend_fd = 326;
    llps_session_refresh_crc(sess);

    g_tmr_memory_domain_probe_override_domains[1] =
        test_physical_memory_domains[2];

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_tmr_memory_domain_failures >= 1u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_watchdog_fails_closed_on_runtime_tmr_memory_domain_fault passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_nonresident_tmr_memory(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 327);
    sess->backend_fd = 328;
    llps_session_refresh_crc(sess);

    g_tmr_memory_residency_probe_override_enabled = true;
    g_tmr_memory_residency_probe_override_resident = false;

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_software_tmr_failures >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_memory_residency_failures >= 1u);

    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_watchdog_fails_closed_on_runtime_nonresident_tmr_memory passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_tmr_physical_frame_alias(void) {
    llps_yml_config_t cfg;
    char edac_root[128];
    char numa_root[128];
    const char *saved_edac_root = g_edac_sysfs_root;
    const char *saved_numa_root = g_numa_sysfs_root;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_edac_tree(edac_root, sizeof(edac_root), "0\n", "0\n");
    test_set_edac_sysfs_root(edac_root);
    test_prepare_numa_tree(numa_root,
                           sizeof(numa_root),
                           test_physical_memory_domains);
    test_set_numa_sysfs_root(numa_root);
    cfg = test_required_readiness_config_with_current_observation();

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 329);
    sess->backend_fd = 330;
    llps_session_refresh_crc(sess);

    g_tmr_physical_frame_probe_override_alias = true;

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_software_tmr_failures >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_memory_physical_frame_faults >= 1u);

    g_tmr_physical_frame_probe_override_alias = false;
    test_set_edac_sysfs_root(saved_edac_root);
    test_set_numa_sysfs_root(saved_numa_root);
    test_remove_edac_tree(edac_root);
    test_remove_numa_tree(numa_root, test_physical_memory_domains);

    printf("test_llps_watchdog_fails_closed_on_runtime_tmr_physical_frame_alias passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_stale_boot_binding(void) {
    llps_yml_config_t cfg;
    char stale_boot_id_path[128];
    const char *saved_boot_id_path = NULL;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    saved_boot_id_path = g_boot_id_path;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 329);
    sess->backend_fd = 330;
    llps_session_refresh_crc(sess);

    ++mock_llam_now_ns;
    test_prepare_boot_id_file(stale_boot_id_path,
                              sizeof(stale_boot_id_path),
                              "99999999-8888-7777-6666-555555555555\n");
    test_set_boot_id_path(stale_boot_id_path);

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_observation_digest_failures >= 1u);

    test_set_boot_id_path(saved_boot_id_path);
    test_remove_boot_id_file(stale_boot_id_path);

    printf("test_llps_watchdog_fails_closed_on_runtime_stale_boot_binding passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_stale_platform_identity(void) {
    llps_yml_config_t cfg;
    char stale_platform_id_path[128];
    const char *saved_platform_id_path = NULL;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    saved_platform_id_path = g_platform_id_path;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 331);
    sess->backend_fd = 332;
    llps_session_refresh_crc(sess);

    ++mock_llam_now_ns;
    test_prepare_platform_id_file(stale_platform_id_path,
                                  sizeof(stale_platform_id_path),
                                  "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb\n");
    test_set_platform_id_path(stale_platform_id_path);

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_observation_digest_failures >= 1u);

    test_set_platform_id_path(saved_platform_id_path);
    test_remove_platform_id_file(stale_platform_id_path);

    printf("test_llps_watchdog_fails_closed_on_runtime_stale_platform_identity passed.\n");
}

static void test_llps_watchdog_fails_closed_on_runtime_stale_executable_image(void) {
    llps_yml_config_t cfg;
    char stale_executable_image_path[128];
    const char *saved_executable_image_path = NULL;
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    test_prepare_complete_platform_observation_roots();
    cfg = test_required_readiness_config_with_current_observation();
    saved_executable_image_path = g_executable_image_path;

    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 333);
    sess->backend_fd = 334;
    llps_session_refresh_crc(sess);

    ++mock_llam_now_ns;
    test_prepare_executable_image_file(stale_executable_image_path,
                                       sizeof(stale_executable_image_path),
                                       "llps-test-image-v2\n");
    test_set_executable_image_path(stale_executable_image_path);

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_observation_digest_failures >= 1u);

    test_set_executable_image_path(saved_executable_image_path);
    test_remove_executable_image_file(stale_executable_image_path);

    printf("test_llps_watchdog_fails_closed_on_runtime_stale_executable_image passed.\n");
}

static void test_llps_watchdog_repairs_single_metadata_bank_faults(void) {
    const llps_yml_config_t cfg = test_config();

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_runtime_cfg_bank0.cfg.buffer_size = 64u;
    g_runtime_cfg_bank0.buffer_size_inverse =
        ~g_runtime_cfg_bank0.cfg.buffer_size;
    g_runtime_cfg_bank0.crc =
        llps_runtime_cfg_bank_compute_crc(&g_runtime_cfg_bank0);
    g_runtime_cfg_bank0.crc_inverse = ~g_runtime_cfg_bank0.crc;

    g_free_list_bank0.count = 0u;
    g_free_list_bank0.count_inverse = ~g_free_list_bank0.count;
    g_free_list_bank0.crc = llps_free_list_bank_compute_crc(&g_free_list_bank0);
    g_free_list_bank0.crc_inverse = ~g_free_list_bank0.crc;

    llps_control_flag_bank_from_value(&g_control_flag_bank0, 0u, true);

    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(g_runtime_cfg.buffer_size == cfg.buffer_size);
    LLPS_TEST_ASSERT(g_runtime_cfg_bank0.cfg.buffer_size == cfg.buffer_size);
    LLPS_TEST_ASSERT(g_free_list_bank0.count == g_free_sessions_count);
    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(g_memory_safety_counters.runtime_cfg_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.free_list_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.control_flag_single_bank_repairs >= 1u);

    printf("test_llps_watchdog_repairs_single_metadata_bank_faults passed.\n");
}

static void test_llps_watchdog_scrubs_single_session_bank_fault(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 350);
    sess->backend_fd = 351;
    llps_session_refresh_crc(sess);

    g_session_tmr_region0.records[sess_idx].record_crc_inverse ^= 0x1u;
    LLPS_TEST_ASSERT(!llps_session_tmr_record_is_valid(
                         &g_session_tmr_region0.records[sess_idx],
                         0u,
                         sess_idx));

    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_session_tmr_record_is_valid(
                         &g_session_tmr_region0.records[sess_idx],
                         0u,
                         sess_idx));
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_scrub_passes >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_scrub_sessions_checked >=
                     (2u * cfg.max_clients));
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_scrub_fail_closed_sessions == 0u);
    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());

    printf("test_llps_watchdog_scrubs_single_session_bank_fault passed.\n");
}

static void test_llps_metadata_bank_crc_inverse_faults_are_repaired(void) {
    const llps_yml_config_t cfg = test_config();

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_runtime_cfg_bank0.crc_inverse ^= 0x1u;
    g_free_list_bank0.crc_inverse ^= 0x1u;
    g_control_flag_bank0.crc_inverse ^= 0x1u;

    LLPS_TEST_ASSERT(!llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(!llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(!llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));

    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_runtime_cfg_bank_is_valid(&g_runtime_cfg_bank0, 0u));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_control_flag_bank_is_valid(&g_control_flag_bank0, 0u));
    LLPS_TEST_ASSERT(g_runtime_cfg.buffer_size == cfg.buffer_size);
    LLPS_TEST_ASSERT(g_free_list_bank0.count == g_free_sessions_count);
    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(g_memory_safety_counters.runtime_cfg_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.free_list_single_bank_repairs >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.control_flag_single_bank_repairs >= 1u);

    printf("test_llps_metadata_bank_crc_inverse_faults_are_repaired passed.\n");
}

static void test_llps_watchdog_fails_closed_on_dual_runtime_cfg_fault(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 330);
    sess->backend_fd = 331;
    llps_session_refresh_crc(sess);

    g_runtime_cfg_bank0.magic_start = 0u;
    g_runtime_cfg_bank1.magic_start = 0u;

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.runtime_cfg_majority_failures >= 1u);

    printf("test_llps_watchdog_fails_closed_on_dual_runtime_cfg_fault passed.\n");
}

static void test_llps_watchdog_fails_closed_on_dual_control_flag_fault(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];
    llps_session_prepare_active(sess, sess_idx, 340);
    sess->backend_fd = 341;
    llps_session_refresh_crc(sess);

    g_control_flag_bank0.magic_start = 0u;
    g_control_flag_bank1.magic_start = 0u;

    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.control_flag_majority_failures >= 1u);

    printf("test_llps_watchdog_fails_closed_on_dual_control_flag_fault passed.\n");
}

static void test_llps_single_free_list_bank_fault_is_repaired(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;
    uint32_t sess_idx = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_free_list_bank0.count = 0u;
    g_free_list_bank0.count_inverse = ~g_free_list_bank0.count;
    g_free_list_bank0.crc = llps_free_list_bank_compute_crc(&g_free_list_bank0);
    g_free_list_bank0.crc_inverse = ~g_free_list_bank0.crc;

    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    LLPS_TEST_ASSERT(sess_idx == 0u);
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(g_free_list_bank0.count == g_free_sessions_count);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.free_list_single_bank_repairs >= 1u);

    printf("test_llps_single_free_list_bank_fault_is_repaired passed.\n");
}

static void test_llps_dual_free_list_bank_fault_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    llps_memory_safety_report_t report;
    uint32_t sess_idx = 0u;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_free_list_bank0.magic_start = 0u;
    g_free_list_bank1.magic_start = 0u;

    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_E_STATE);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.free_list_majority_failures >= 1u);

    printf("test_llps_dual_free_list_bank_fault_fails_closed passed.\n");
}

static void test_llps_free_list_valid_no_majority_fails_closed(void) {
    const llps_yml_config_t cfg = test_config();
    llps_free_list_snapshot_t snap0;
    llps_free_list_snapshot_t snap1;
    llps_free_list_snapshot_t snap2;
    llps_free_list_snapshot_t voted;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(g_free_sessions_count >= 3u);

    llps_free_list_snapshot_from_canonical(&snap0, g_free_sessions, g_free_sessions_count);
    snap1 = snap0;
    snap2 = snap0;
    snap1.entries[0] = snap0.entries[1];
    snap1.entries[1] = snap0.entries[0];
    snap2.entries[0] = snap0.entries[2];
    snap2.entries[2] = snap0.entries[0];

    llps_free_list_bank_from_snapshot(&g_free_list_bank0, 0u, &snap0);
    llps_free_list_bank_from_snapshot(&g_free_list_bank1, 1u, &snap1);
    llps_free_list_bank_from_snapshot(&g_free_list_bank2, 2u, &snap2);

    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank0, 0u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank1, 1u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(llps_free_list_bank_is_valid(&g_free_list_bank2, 2u, g_runtime_cfg.max_clients));
    LLPS_TEST_ASSERT(!llps_free_list_vote(&voted, &g_runtime_cfg));
    LLPS_TEST_ASSERT(g_memory_safety_counters.free_list_majority_failures >= 1u);

    printf("test_llps_free_list_valid_no_majority_fails_closed passed.\n");
}

static void test_llps_dual_tmr_bank_fault_forces_shutdown(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 300);
    sess->backend_fd = 301;
    llps_session_refresh_crc(sess);

    g_session_tmr_region0.records[sess_idx].magic_start = 0u;
    g_session_tmr_region1.records[sess_idx].magic_start = 0u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_majority_failures >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_scrub_fail_closed_sessions >= 1u);

    printf("test_llps_dual_tmr_bank_fault_forces_shutdown passed.\n");
}

static void test_llps_dual_tmr_region_guard_fault_forces_shutdown(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 310);
    sess->backend_fd = 311;
    llps_session_refresh_crc(sess);

    g_session_tmr_region0.magic_start = 0u;
    g_session_tmr_region1.magic_end = 0u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_majority_failures >= 1u);
    LLPS_TEST_ASSERT(g_memory_safety_counters.tmr_scrub_fail_closed_sessions >= 1u);

    printf("test_llps_dual_tmr_region_guard_fault_forces_shutdown passed.\n");
}

static void test_llps_watchdog_shutdowns_idle_session(void) {
    const llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 300);
    sess->backend_fd = 301;
    llps_session_refresh_crc(sess);

    mock_llam_now_ns = LLPS_SESSION_IDLE_TIMEOUT_NS + 2000u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);

    printf("test_llps_watchdog_shutdowns_idle_session passed.\n");
}

static void test_llps_watchdog_uses_configured_idle_timeout(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;

    cfg.session_idle_timeout_ms = LLPS_SESSION_IDLE_TIMEOUT_MS_MIN;

    reset_mocks();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 300);
    sess->backend_fd = 301;
    llps_session_refresh_crc(sess);

    mock_llam_now_ns =
        sess->last_activity_ns +
        ((uint64_t)LLPS_SESSION_IDLE_TIMEOUT_MS_MIN * LLPS_NSEC_PER_MSEC) +
        2000u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(mock_shutdown_calls >= 2u);

    printf("test_llps_watchdog_uses_configured_idle_timeout passed.\n");
}

static void test_llps_watchdog_audits_idle_timeout_reason(void) {
    llps_yml_config_t cfg = test_config();
    uint32_t sess_idx = 0u;
    llps_session_t *sess = NULL;
    char path[128];
    char line[4096];
    int n = 0;

    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_idle_timeout_audit_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));

    cfg.ip_audit_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    cfg.session_idle_timeout_ms = LLPS_SESSION_IDLE_TIMEOUT_MS_MIN;

    reset_mocks();
    (void)remove(path);
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_find_free_session(&sess_idx) == LLPS_OK);
    sess = &g_sessions[sess_idx];

    llps_session_prepare_active(sess, sess_idx, 300);
    sess->backend_fd = 301;
    sess->request_no = 123u;
    sess->request_no_inverse = ~sess->request_no;
    llps_session_refresh_crc(sess);

    mock_llam_now_ns =
        sess->last_activity_ns +
        ((uint64_t)LLPS_SESSION_IDLE_TIMEOUT_MS_MIN * LLPS_NSEC_PER_MSEC) +
        2000u;
    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);
    llps_close_session(sess);
    llps_ip_audit_shutdown();

    test_read_text_file(path, line, sizeof(line));
    LLPS_TEST_ASSERT(strstr(line,
                            "+audit 1 123 close 1 1 ") != NULL);
    LLPS_TEST_ASSERT(strstr(line, " idle_timeout 0 0x") != NULL);
    (void)remove(path);

    printf("test_llps_watchdog_audits_idle_timeout_reason passed.\n");
}

static void test_llps_watchdog_counts_runtime_software_evidence_patrol(void) {
    llps_yml_config_t cfg;
    llps_memory_safety_report_t report;
    char path[128];
    char key_path[128];
    char log_text[4096];
    int n = 0;

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    n = snprintf(path,
                 sizeof(path),
                 "/tmp/llps_readiness_evidence_audit_%lu.pxf",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(path));
    n = snprintf(key_path,
                 sizeof(key_path),
                 "/tmp/llps_readiness_evidence_audit_key_%lu.key",
                 test_tmp_serial());
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(key_path));
    cfg.ip_audit_enabled = 1u;
    cfg.audit_mac_enabled = 1u;
    n = snprintf(cfg.ip_audit_path, sizeof(cfg.ip_audit_path), "%s", path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.ip_audit_path));
    n = snprintf(cfg.audit_mac_key_path,
                 sizeof(cfg.audit_mac_key_path),
                 "%s",
                 key_path);
    LLPS_TEST_ASSERT(n > 0);
    LLPS_TEST_ASSERT((size_t)n < sizeof(cfg.audit_mac_key_path));
    (void)remove(path);
    (void)remove(key_path);
    test_write_text_file(key_path, "readiness-evidence-audit-key");
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);
    llps_ip_audit_shutdown();

    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_monitor_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_software_evidence_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_failures == 0u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_fault_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_fault_patrol_failures == 0u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_failures == 0u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_monitor_failures == 0u);
    LLPS_TEST_ASSERT(llps_get_memory_safety_report(&report) == LLPS_OK);
    LLPS_TEST_ASSERT(report.readiness_runtime_monitor_passes >= 1u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_software_evidence_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_ecc_topology_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_ecc_topology_patrol_failures == 0u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_fault_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_fault_patrol_failures == 0u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_numa_patrol_passes >= 1u);
    LLPS_TEST_ASSERT(
        report.readiness_runtime_synthetic_numa_patrol_failures == 0u);

    test_read_text_file(path, log_text, sizeof(log_text));
    LLPS_TEST_ASSERT(strstr(log_text, "@table evidence seq:tok") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "# ---- llps readiness evidence ----") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#   event: readiness_monitor_pass") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "+evidence 1 readiness_monitor_pass") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, "+evidence_mac 1 0x") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text,
                            "#   evidence_hmac_sha256: ") != NULL);
    LLPS_TEST_ASSERT(strstr(log_text, " 0x00000000 0x00000000 ") != NULL);
    LLPS_TEST_ASSERT(llps_ip_audit_init(&cfg, "10.0.0.8"));
    llps_ip_audit_shutdown();
    (void)remove(path);
    (void)remove(key_path);

    printf("test_llps_watchdog_counts_runtime_software_evidence_patrol passed.\n");
}

static void test_llps_runtime_synthetic_ecc_topology_patrol_rejects_dirty_counter(
    void) {
    llps_yml_config_t cfg;
    uint64_t previous_failures = 0u;
    struct dirty_counter_case {
        uint64_t *counter;
    };

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_runtime_synthetic_ecc_topology_patrol(&cfg));
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_passes >= 1u);

    previous_failures =
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_failures;

    {
        llps_yml_config_t dirty_cfg = cfg;
        struct dirty_counter_case cases[] = {
            { &dirty_cfg.software_ecc_controller_corrected_error_count },
            { &dirty_cfg.software_ecc_controller_uncorrected_error_count },
            { &dirty_cfg.software_ecc_dimm_corrected_error_count },
            { &dirty_cfg.software_ecc_dimm_uncorrected_error_count },
        };

        for (uint32_t i = 0u;
             i < (uint32_t)(sizeof(cases) / sizeof(cases[0]));
             ++i) {
            dirty_cfg = cfg;
            *cases[i].counter = 1u;
            LLPS_TEST_ASSERT(
                !llps_runtime_synthetic_ecc_topology_patrol(&dirty_cfg));
        }
    }

    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_failures >=
        (previous_failures + 4u));

    cfg.software_ecc_controller_corrected_error_count = 1u;
    LLPS_TEST_ASSERT(!llps_runtime_synthetic_ecc_topology_patrol(&cfg));
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_failures >= 1u);

    printf("test_llps_runtime_synthetic_ecc_topology_patrol_rejects_dirty_counter passed.\n");
}

static void test_llps_runtime_synthetic_numa_patrol_rejects_bad_profile(void) {
    llps_yml_config_t cfg;

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);
    LLPS_TEST_ASSERT(llps_runtime_synthetic_numa_patrol(&cfg));
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_passes >= 1u);

    cfg.software_numa_remote_distance = cfg.software_numa_local_distance;
    LLPS_TEST_ASSERT(!llps_runtime_synthetic_numa_patrol(&cfg));
    LLPS_TEST_ASSERT(
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_failures >= 1u);

    printf("test_llps_runtime_synthetic_numa_patrol_rejects_bad_profile passed.\n");
}

static void
test_llps_watchdog_fails_closed_on_software_ecc_without_payload_ecc(void) {
    llps_yml_config_t cfg;

    reset_mocks();
    cfg = test_required_software_readiness_config_with_current_observation();
    LLPS_TEST_ASSERT(cfg.payload_ecc_enabled == 1u);
    LLPS_TEST_ASSERT(llps_init(&cfg) == LLPS_OK);

    g_runtime_cfg.payload_ecc_enabled = 0u;
    llps_runtime_cfg_write_all(&g_runtime_cfg);

    mock_sleep_requests_shutdown = true;
    llps_task_watchdog(NULL);

    LLPS_TEST_ASSERT(llps_control_shutdown_is_requested());
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_monitor_failures >= 1u);
    LLPS_TEST_ASSERT(
        g_memory_safety_counters.readiness_runtime_software_tmr_failures >= 1u);

    printf("test_llps_watchdog_fails_closed_on_software_ecc_without_payload_ecc passed.\n");
}

int main(void) {
    test_llps_observation_fingerprint_zero_is_reserved();
    test_llps_tmr_layout_fingerprint_uses_stable_region_ids();
#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED
    test_llps_tmr_residency_fingerprint_uses_nonxor_sum();
#endif
#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
    test_llps_tmr_physical_frame_fingerprint_uses_nonxor_sum();
    test_llps_tmr_physical_frame_tracks_cross_bank_distance();
#endif
    test_llps_synthetic_edac_fingerprint_binds_virtual_topology();
    test_llps_yml_accepts_legacy_required_config();
    test_llps_yml_accepts_dns_hosts();
    test_llps_yml_accepts_legacy_target_ip_alias();
    test_llps_yml_rejects_duplicate_target_host_aliases();
    test_llps_yml_parses_session_idle_timeout();
    test_llps_yml_rejects_invalid_session_idle_timeout();
    test_llps_yml_parses_max_sessions_per_client_ip();
    test_llps_yml_rejects_invalid_max_sessions_per_client_ip();
    test_llps_yml_parses_client_ip_rate_limit();
    test_llps_yml_rejects_invalid_client_ip_rate_window();
    test_llps_yml_parses_client_preface_timeout();
    test_llps_yml_rejects_invalid_client_preface_timeout();
    test_llps_yml_parses_protocol_handshake_gate();
    test_llps_yml_rejects_protocol_gate_without_preface();
    test_llps_yml_parses_ip_audit_config();
    test_llps_yml_rejects_non_pxf_ip_audit_path();
    test_llps_yml_rejects_audit_mac_without_key();
    test_llps_runtime_cfg_rejects_non_pxf_ip_audit_path();
    test_llps_runtime_cfg_rejects_invalid_audit_mac_config();
    test_llps_runtime_cfg_rejects_invalid_client_ip_cap();
    test_llps_runtime_cfg_rejects_invalid_client_ip_rate();
    test_llps_runtime_cfg_rejects_invalid_client_preface();
    test_llps_runtime_cfg_rejects_protocol_gate_without_preface();
    test_llps_ip_audit_init_rejects_non_pxf_path();
    test_llps_ip_audit_init_rejects_missing_mac_key();
    test_llps_ip_audit_writes_pxf_record_shape();
    test_llps_ip_audit_rejects_pxf_token_injection();
    test_llps_ip_audit_continues_sequence_when_appending();
    test_llps_ip_audit_rejects_tampered_existing_crc();
    test_llps_ip_audit_writes_mac_record_when_enabled();
    test_llps_ip_audit_rejects_signed_log_mac_downgrade();
    test_llps_yml_rejects_malformed_dns_host();
    test_llps_yml_parses_readiness_gate_config();
    test_llps_yml_parses_software_platform_evidence_config();
    test_llps_yml_rejects_software_numa_without_phys_sep();
    test_llps_yml_rejects_invalid_software_numa_distance();
    test_llps_yml_rejects_invalid_software_fault_injection_mode();
    test_llps_yml_rejects_required_readiness_without_full_evidence();
    test_llps_yml_attestation_loader_allows_generation_config();
    test_llps_yml_rejects_readiness_duplicate_domains();
    test_llps_yml_rejects_readiness_overlapping_domain_sets();
    test_llps_yml_rejects_unused_external_domain_ids();
    test_llps_yml_rejects_missing_hw_tmr_voter_domain();
    test_llps_yml_rejects_hw_tmr_voter_domain_overlap();
    test_llps_yml_rejects_software_ecc_readiness_without_payload_ecc();
    test_llps_yml_rejects_software_ecc_without_scrub_rate();
    test_llps_yml_rejects_software_ecc_without_controller_count();
    test_llps_yml_rejects_software_ecc_controller_over_dimm_count();
    test_llps_task_budget_reserves_readiness_monitor_task();
    test_llps_llam_runtime_policy_rejects_worker_fanout();
    test_llps_llam_now_contract_rejects_zero_tick();
    test_llps_llam_checked_wrappers_reject_bad_args();
    test_llps_init_sets_integrity_guards();
    test_llps_open_close_listen();
    test_llps_init_resolves_target_domain_once();
    test_llps_open_listen_socket_resolves_listen_domain();
    test_llps_sockaddr_ipv4_text_requires_full_addrlen();
    test_llps_connection_refreshes_tmr_after_pump_arg_setup();
    test_llps_connection_accepts_poll_ready_without_revents();
    test_llps_connection_times_out_when_poll_never_ready();
    test_llps_connection_preface_timeout_avoids_backend_socket();
    test_llps_connection_preface_flushes_before_pumps();
    test_llps_connection_protocol_gate_drops_invalid_preface();
    test_llps_connection_protocol_gate_times_out_idle_preface();
    test_llps_protocol_handshake_parser_covers_boundaries();
    test_llps_protocol_handshake_parser_fuzz_is_bounded();
    test_llps_connection_protocol_gate_rejects_malformed_handshakes();
    test_llps_connection_protocol_gate_accepts_fragmented_handshake();
    test_llps_connection_protocol_gate_preserves_trailing_preface_payload();
    test_llps_accept_errno_policy_keeps_remote_faults_local();
    test_llps_client_ip_session_limit_blocks_excess_active();
    test_llps_client_ip_rate_limit_blocks_burst();
    test_llps_run_server_audits_client_ip_limit_drop();
    test_llps_run_server_audits_client_ip_rate_limit_drop();
    test_llps_fd_nonblocking_contract_is_checked();
    test_llps_pump_rejects_blocking_fd_before_io();
    test_llps_pump_does_not_refresh_activity_on_empty_poll();
    test_llps_pump_refreshes_activity_on_payload_progress();
    test_llps_pump_uses_payload_ecc_when_enabled();
    test_llps_pump_rejects_oversized_read_result();
    test_llps_pump_rejects_oversized_send_result();
    test_llps_secded_corrects_single_bit_and_detects_double_bit();
    test_llps_payload_ecc_repairs_single_bit_payload_fault();
    test_llps_payload_ecc_fails_closed_on_double_bit_payload_fault();
    test_llps_watchdog_payload_ecc_scrub_repairs_single_bit_fault();
    test_llps_watchdog_payload_ecc_scrub_fails_closed_on_double_bit_fault();
    test_llps_hmac_sha256_matches_rfc4231_vector();
    test_llps_software_evidence_self_test_covers_fault_model();
    test_llps_software_evidence_scope_texts_are_explicit();
    test_llps_software_evidence_rejects_invalid_profile();
    test_llps_session_secded_single_bit_fault_is_repaired();
    test_llps_session_secded_double_bit_fault_uses_tmr();
    test_llps_tmr_record_secded_single_bit_fault_is_repaired();
    test_llps_tmr_record_secded_double_bit_fault_uses_majority();
    test_llps_single_session_mirror_fault_is_repaired();
    test_llps_single_tmr_bank_fault_is_repaired();
    test_llps_single_tmr_record_crc_inverse_fault_is_repaired();
    test_llps_session_tmr_valid_no_majority_fails_closed();
    test_llps_single_tmr_region_guard_fault_is_repaired();
    test_llps_tmr_startup_self_test_exercises_real_banks();
    test_llps_single_runtime_cfg_bank_fault_is_repaired();
    test_llps_dual_runtime_cfg_bank_fault_fails_closed();
    test_llps_runtime_cfg_valid_no_majority_fails_closed();
    test_llps_shutdown_request_is_tmr_replicated();
    test_llps_single_control_flag_bank_fault_is_repaired();
    test_llps_dual_control_flag_bank_fault_fails_closed();
    test_llps_readiness_gate_passes_with_complete_evidence();
    test_llps_software_platform_evidence_uses_configured_ecc_and_numa();
    test_llps_software_platform_evidence_rejects_dirty_ecc_counter();
    test_llps_software_platform_evidence_rejects_stale_profile();
    test_llps_software_platform_evidence_rejects_tampered_schema_version();
    test_llps_software_platform_evidence_rejects_missing_numa_profile_fingerprint();
    test_llps_readiness_report_marks_stale_evidence_request();
    test_llps_synthetic_platform_identity_replaces_missing_dmi();
    test_llps_evidence_mac_authenticates_platform_evidence();
    test_llps_readiness_gate_rejects_disabled_runtime_monitor();
    test_llps_init_rejects_software_ecc_readiness_without_payload_ecc();
    test_llps_readiness_gate_rejects_missing_platform_evidence();
    test_llps_readiness_gate_rejects_broken_software_tmr();
    test_llps_readiness_gate_rejects_tampered_evidence();
    test_llps_readiness_gate_rejects_tampered_evidence_crc_inverse();
    test_llps_readiness_gate_rejects_tampered_observation_digest();
    test_llps_readiness_gate_rejects_stale_boot_evidence();
    test_llps_readiness_gate_rejects_stale_platform_identity_evidence();
    test_llps_readiness_gate_rejects_stale_executable_image_evidence();
    test_llps_readiness_gate_rejects_stale_layout_evidence();
    test_llps_readiness_gate_rejects_stale_edac_evidence();
    test_llps_readiness_gate_rejects_stale_edac_scrub_rate_evidence();
    test_llps_readiness_gate_rejects_stale_dimm_edac_evidence();
    test_llps_readiness_gate_rejects_added_clean_dimm_edac_evidence();
    test_llps_readiness_gate_rejects_tampered_edac_stats();
    test_llps_readiness_gate_rejects_stale_physical_domain_evidence();
    test_llps_readiness_gate_rejects_stale_physical_domain_has_memory();
    test_llps_readiness_gate_rejects_stale_physical_domain_has_normal_memory();
    test_llps_readiness_gate_rejects_stale_physical_domain_meminfo();
    test_llps_readiness_gate_rejects_missing_physical_domain_meminfo();
    test_llps_readiness_gate_rejects_stale_physical_domain_distance();
    test_llps_readiness_gate_rejects_asymmetric_physical_domain_distance();
    test_llps_readiness_gate_rejects_flat_physical_domain_distance();
    test_llps_readiness_gate_rejects_missing_physical_domain_distance();
    test_llps_readiness_gate_rejects_tampered_physical_domain_topology_stats();
    test_llps_readiness_gate_rejects_tampered_physical_domain_pair_distance();
    test_llps_readiness_gate_rejects_tampered_physical_domain_distance_sum();
    test_llps_readiness_gate_rejects_stale_tmr_memory_domain_evidence();
    test_llps_readiness_gate_rejects_tampered_tmr_observed_domains();
    test_llps_readiness_gate_rejects_tampered_tmr_domain_probe_stats();
    test_llps_readiness_gate_rejects_stale_tmr_residency_evidence();
    test_llps_readiness_gate_rejects_tampered_tmr_residency_fingerprint();
    test_llps_readiness_gate_rejects_stale_tmr_physical_frame_evidence();
    test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_fingerprint();
    test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_distance();
    test_llps_readiness_gate_rejects_tampered_tmr_physical_frame_pair_distance();
    test_llps_readiness_gate_rejects_stale_memory_hardening_evidence();
    test_llps_readiness_gate_rejects_tampered_prefault_page_evidence();
    test_llps_readiness_gate_rejects_stale_tmr_self_test_evidence();
    test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage_evidence();
    test_llps_readiness_gate_rejects_stale_attestation();
    test_llps_init_rejects_required_readiness_with_stale_observation_digest();
    test_llps_public_evidence_builder_rejects_manual_ecc_claims();
    test_llps_platform_evidence_rejects_missing_domain_attestation();
    test_llps_readiness_gate_rejects_unlocked_process_memory();
    test_llps_readiness_gate_rejects_unlocked_tmr_memory();
    test_llps_readiness_gate_rejects_unhardened_tmr_memory();
    test_llps_readiness_gate_rejects_unprefaulted_tmr_memory();
    test_llps_readiness_gate_rejects_tampered_tmr_prefault_pages();
    test_llps_readiness_gate_rejects_nonresident_tmr_memory();
    test_llps_readiness_gate_rejects_tampered_runtime_safety_latch();
    test_llps_readiness_gate_rejects_contract_violation();
    test_llps_readiness_gate_rejects_tampered_memory_safety_counter_seal();
    test_llps_readiness_gate_rejects_tampered_memory_safety_counter_value();
    test_llps_readiness_gate_rejects_failed_tmr_self_test();
    test_llps_readiness_gate_rejects_tampered_tmr_self_test_coverage();
    test_llps_init_enforces_required_readiness_with_clean_edac();
    test_llps_init_rejects_required_readiness_without_ecc_evidence();
    test_llps_init_rejects_required_readiness_without_tmr_memory_domain_binding();
    test_llps_memory_report_refreshes_tmr_memory_domain_binding_fault();
    test_llps_init_for_diagnostics_reports_missing_ecc_without_gate_failure();
    test_llps_init_rejects_required_readiness_with_stale_attestation();
    test_llps_collect_platform_evidence_from_clean_edac();
    test_llps_collect_platform_evidence_rejects_dirty_edac();
    test_llps_collect_platform_evidence_rejects_dirty_dimm_edac();
    test_llps_collect_platform_evidence_rejects_missing_dimm_counter();
    test_llps_collect_platform_evidence_rejects_missing_controller_counter();
    test_llps_collect_platform_evidence_rejects_missing_edac_scrub_rate();
    test_llps_collect_platform_evidence_rejects_none_ecc_mode();
    test_llps_collect_platform_evidence_rejects_unrecognized_ecc_mode();
    test_llps_collect_platform_evidence_rejects_negated_ecc_modes();
    test_llps_collect_platform_evidence_rejects_missing_ecc_mode();
    test_llps_collect_platform_evidence_rejects_partial_missing_ecc_mode();
    test_llps_watchdog_fails_closed_on_runtime_dirty_edac();
    test_llps_watchdog_fails_closed_on_runtime_tmr_memory_domain_fault();
    test_llps_watchdog_fails_closed_on_runtime_nonresident_tmr_memory();
    test_llps_watchdog_fails_closed_on_runtime_tmr_physical_frame_alias();
    test_llps_watchdog_fails_closed_on_runtime_stale_boot_binding();
    test_llps_watchdog_fails_closed_on_runtime_stale_platform_identity();
    test_llps_watchdog_fails_closed_on_runtime_stale_executable_image();
    test_llps_watchdog_repairs_single_metadata_bank_faults();
    test_llps_watchdog_scrubs_single_session_bank_fault();
    test_llps_metadata_bank_crc_inverse_faults_are_repaired();
    test_llps_watchdog_fails_closed_on_dual_runtime_cfg_fault();
    test_llps_watchdog_fails_closed_on_dual_control_flag_fault();
    test_llps_single_free_list_bank_fault_is_repaired();
    test_llps_dual_free_list_bank_fault_fails_closed();
    test_llps_free_list_valid_no_majority_fails_closed();
    test_llps_dual_tmr_bank_fault_forces_shutdown();
    test_llps_dual_tmr_region_guard_fault_forces_shutdown();
    test_llps_watchdog_shutdowns_idle_session();
    test_llps_watchdog_uses_configured_idle_timeout();
    test_llps_watchdog_audits_idle_timeout_reason();
    test_llps_watchdog_counts_runtime_software_evidence_patrol();
    test_llps_runtime_synthetic_ecc_topology_patrol_rejects_dirty_counter();
    test_llps_runtime_synthetic_numa_patrol_rejects_bad_profile();
    test_llps_watchdog_fails_closed_on_software_ecc_without_payload_ecc();
    printf("All LLPS hardening tests passed.\n");
    return 0;
}
