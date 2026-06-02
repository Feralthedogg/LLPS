/**
 * @file src/config/yml_parser.c
 * @brief Configuration parsing and validation for LLPS runtime options.
 *
 * @details
 * Configuration code owns text input normalization before values cross into
 * the runtime state.
 */

#define _POSIX_C_SOURCE 200809L

#include "yml_parser.h"
#include "llps_config.h"
#include "llps.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define LLPS_YML_MAX_LINE_LEN             (320u)
#define LLPS_YML_MAX_LINES                (128u)
#define LLPS_YML_READ_CHUNK               (128u)
#define LLPS_YML_MAX_PATH_LEN             LLPS_YML_MAX_PATH_TEXT
#define LLPS_YML_MAX_KEY_LEN              (64u)
#define LLPS_YML_MAX_VALUE_LEN            (256u)
#define LLPS_YML_MAX_DNS_NAME_LEN         (254u)
#define LLPS_YML_MAX_DNS_LABEL_LEN        (63u)

#define LLPS_YML_MAX_FILE_BYTES \
    ((uint32_t)(LLPS_YML_MAX_LINES * (LLPS_YML_MAX_LINE_LEN + 2u)))

_Static_assert(LLPS_YML_MAX_IP_TEXT >= 16u,
               "IPv4 text buffer must fit maximum dotted decimal address");
_Static_assert(LLPS_YML_MAX_IP_TEXT >= (LLPS_YML_MAX_DNS_NAME_LEN + 1u),
               "host text buffer must fit maximum DNS presentation name");
_Static_assert(LLPS_YML_MAX_LINE_LEN >= 80u,
               "line length budget unexpectedly small");
_Static_assert(LLPS_YML_MAX_LINES > 0u,
               "line count must be positive");
_Static_assert(LLPS_YML_READ_CHUNK > 0u,
               "read chunk must be positive");
_Static_assert(LLPS_YML_MAX_KEY_LEN > 0u,
               "key length must be positive");
_Static_assert(LLPS_YML_MAX_VALUE_LEN > 0u,
               "value length must be positive");

typedef enum {
    LLPS_YML_KEY_MAX_CLIENTS = 0,
    LLPS_YML_KEY_BUFFER_SIZE,
    LLPS_YML_KEY_LISTEN_HOST,
    LLPS_YML_KEY_LISTEN_PORT,
    LLPS_YML_KEY_TARGET_IP,
    LLPS_YML_KEY_TARGET_PORT,
    LLPS_YML_KEY_LISTEN_BACKLOG,
    LLPS_YML_KEY_ACCEPT_BATCH_MAX,
    LLPS_YML_KEY_SESSION_IDLE_TIMEOUT_MS,
    LLPS_YML_KEY_MAX_SESSIONS_PER_CLIENT_IP,
    LLPS_YML_KEY_MAX_NEW_SESSIONS_PER_CLIENT_IP_PER_WINDOW,
    LLPS_YML_KEY_CLIENT_IP_RATE_WINDOW_MS,
    LLPS_YML_KEY_CLIENT_PREFACE_TIMEOUT_MS,
    LLPS_YML_KEY_PROTOCOL_HANDSHAKE_GATE_ENABLED,
    LLPS_YML_KEY_PAYLOAD_ECC_ENABLED,
    LLPS_YML_KEY_IP_AUDIT_ENABLED,
    LLPS_YML_KEY_IP_AUDIT_PATH,
    LLPS_YML_KEY_AUDIT_MAC_ENABLED,
    LLPS_YML_KEY_AUDIT_MAC_KEY_PATH,
    LLPS_YML_KEY_REQUIRE_READINESS,
    LLPS_YML_KEY_PLATFORM_SAFETY_FLAGS,
    LLPS_YML_KEY_PLATFORM_SAFETY_EVIDENCE_ID,
    LLPS_YML_KEY_PLATFORM_ATTESTATION_FINGERPRINT,
    LLPS_YML_KEY_PLATFORM_OBSERVATION_DIGEST,
    LLPS_YML_KEY_PLATFORM_EVIDENCE_MODE,
    LLPS_YML_KEY_PHYS_MEM_DOMAIN0,
    LLPS_YML_KEY_PHYS_MEM_DOMAIN1,
    LLPS_YML_KEY_PHYS_MEM_DOMAIN2,
    LLPS_YML_KEY_HW_TMR_DOMAIN0,
    LLPS_YML_KEY_HW_TMR_DOMAIN1,
    LLPS_YML_KEY_HW_TMR_DOMAIN2,
    LLPS_YML_KEY_HW_TMR_VOTER_DOMAIN,
    LLPS_YML_KEY_SOFTWARE_ECC_ENABLED,
    LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_COUNT,
    LLPS_YML_KEY_SOFTWARE_ECC_DIMM_COUNT,
    LLPS_YML_KEY_SOFTWARE_ECC_SCRUB_RATE,
    LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_CORRECTED_ERROR_COUNT,
    LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_UNCORRECTED_ERROR_COUNT,
    LLPS_YML_KEY_SOFTWARE_ECC_DIMM_CORRECTED_ERROR_COUNT,
    LLPS_YML_KEY_SOFTWARE_ECC_DIMM_UNCORRECTED_ERROR_COUNT,
    LLPS_YML_KEY_SOFTWARE_NUMA_ENABLED,
    LLPS_YML_KEY_SOFTWARE_NUMA_MEMTOTAL_KIB,
    LLPS_YML_KEY_SOFTWARE_NUMA_LOCAL_DISTANCE,
    LLPS_YML_KEY_SOFTWARE_NUMA_REMOTE_DISTANCE,
    LLPS_YML_KEY_SOFTWARE_FAULT_INJECTION_MODE,
    LLPS_YML_KEY_EVIDENCE_MAC_ENABLED,
    LLPS_YML_KEY_EVIDENCE_MAC_KEY_PATH,
    LLPS_YML_KEY_COUNT
} llps_yml_key_t;

typedef struct {
    const char *name;
    llps_yml_key_t key;
} llps_yml_key_name_t;

typedef struct {
    uint32_t octet_count;
    uint32_t digit_count;
    uint32_t value;
    char first_digit;
} llps_yml_ipv4_scan_t;

enum {
    LLPS_YML_REQUIRED_KEY_COUNT = LLPS_YML_KEY_ACCEPT_BATCH_MAX + 1
};

_Static_assert(LLPS_YML_KEY_COUNT < 64,
               "present-key bitmask assumes fewer than 64 keys");

#define LLPS_YML_REQUIRED_MASK \
    ((uint64_t)((1ULL << LLPS_YML_REQUIRED_KEY_COUNT) - 1ULL))

/* -------------------------------------------------------------------------
 * Character helpers
 * ------------------------------------------------------------------------- */

static bool llps_yml_is_space(const char c) {
    return (c == ' ') || (c == '\t');
}

static bool llps_yml_is_digit(const char c) {
    return (c >= '0') && (c <= '9');
}

static bool llps_yml_is_lower_alpha(const char c) {
    return (c >= 'a') && (c <= 'z');
}

static bool llps_yml_is_upper_alpha(const char c) {
    return (c >= 'A') && (c <= 'Z');
}

static bool llps_yml_is_alpha(const char c) {
    return llps_yml_is_lower_alpha(c) || llps_yml_is_upper_alpha(c);
}

static bool llps_yml_is_alnum(const char c) {
    return llps_yml_is_alpha(c) || llps_yml_is_digit(c);
}

static bool llps_yml_is_key_char(const char c) {
    return llps_yml_is_lower_alpha(c) ||
           llps_yml_is_digit(c) ||
           (c == '_');
}

static bool llps_yml_is_dns_label_char(const char c) {
    return llps_yml_is_alnum(c) || (c == '-');
}

static bool llps_yml_is_allowed_text_byte(const unsigned char c) {
    return ((c >= 0x20u) && (c <= 0x7Eu)) || (c == 0x09u);
}

/* -------------------------------------------------------------------------
 * Bounded string helpers
 * ------------------------------------------------------------------------- */

static bool llps_yml_bounded_strlen(const char * const s,
                                    const size_t max_len,
                                    size_t * const out_len) {
    size_t i = 0u;

    if ((s == NULL) || (out_len == NULL) || (max_len == 0u)) {
        return false;
    }

    for (i = 0u; i < max_len; ++i) {
        if (s[i] == '\0') {
            *out_len = i;
            return true;
        }
    }

    return false;
}

static bool llps_yml_streq(const char * const a,
                           const char * const b,
                           const size_t max_len) {
    size_t i = 0u;

    if ((a == NULL) || (b == NULL) || (max_len == 0u)) {
        return false;
    }

    for (i = 0u; i < max_len; ++i) {
        if ((a[i] == '\0') && (b[i] == '\0')) {
            return true;
        }

        if (a[i] != b[i]) {
            return false;
        }
    }

    return false;
}

static llps_yml_status_t llps_yml_copy_cstr(char * const dst,
                                            const size_t dst_cap,
                                            const char * const src) {
    size_t len = 0u;
    size_t i = 0u;

    if ((dst == NULL) || (src == NULL) || (dst_cap == 0u)) {
        return LLPS_YML_E_NULL;
    }

    if (!llps_yml_bounded_strlen(src, dst_cap, &len)) {
        return LLPS_YML_E_STRING;
    }

    for (i = 0u; i <= len; ++i) {
        dst[i] = src[i];
    }

    return LLPS_YML_OK;
}

static void llps_yml_zero_hosts(llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_YML_MAX_IP_TEXT; ++i) {
        cfg->listen_host[i] = '\0';
        cfg->target_ip[i] = '\0';
    }
}

static void llps_yml_zero_paths(llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_YML_MAX_PATH_TEXT; ++i) {
        cfg->ip_audit_path[i] = '\0';
        cfg->audit_mac_key_path[i] = '\0';
        cfg->evidence_mac_key_path[i] = '\0';
    }
}

static void llps_yml_zero_platform_domains(llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        cfg->platform_physical_memory_domains[i] = 0u;
        cfg->platform_hardware_tmr_domains[i] = 0u;
    }
}

static void llps_yml_zero_software_ecc(llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return;
    }

    cfg->software_ecc_enabled = 0u;
    cfg->software_ecc_controller_count = 0u;
    cfg->software_ecc_dimm_count = 0u;
    cfg->software_ecc_scrub_rate = 0u;
    cfg->software_ecc_controller_corrected_error_count = 0u;
    cfg->software_ecc_controller_uncorrected_error_count = 0u;
    cfg->software_ecc_dimm_corrected_error_count = 0u;
    cfg->software_ecc_dimm_uncorrected_error_count = 0u;
}

static void llps_yml_zero_software_numa(llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return;
    }

    cfg->software_numa_enabled = 0u;
    cfg->software_numa_memtotal_kib = 0u;
    cfg->software_numa_local_distance = 0u;
    cfg->software_numa_remote_distance = 0u;
}

static void llps_yml_zero_config(llps_yml_config_t * const cfg) {
    if (cfg != NULL) {
        cfg->max_clients = 0u;
        cfg->buffer_size = 0u;

        llps_yml_zero_hosts(cfg);
        cfg->listen_port = 0u;
        cfg->target_port = 0u;
        cfg->listen_backlog = 0u;
        cfg->accept_batch_max = 0u;
        cfg->session_idle_timeout_ms =
            LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT;
        cfg->max_sessions_per_client_ip = 0u;
        cfg->max_new_sessions_per_client_ip_per_window = 0u;
        cfg->client_ip_rate_window_ms =
            LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT;
        cfg->client_preface_timeout_ms =
            LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT;
        cfg->protocol_handshake_gate_enabled =
            LLPS_PROTOCOL_HANDSHAKE_GATE_DEFAULT;
        cfg->payload_ecc_enabled = 0u;
        cfg->ip_audit_enabled = 0u;
        cfg->audit_mac_enabled = 0u;
        llps_yml_zero_paths(cfg);
        cfg->require_readiness = 0u;
        cfg->platform_safety_flags = 0u;
        cfg->platform_safety_evidence_id = 0u;
        cfg->platform_attestation_fingerprint = 0u;
        cfg->platform_observation_digest = 0u;
        cfg->platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_REAL;
        llps_yml_zero_platform_domains(cfg);
        cfg->platform_hardware_tmr_voter_domain = 0u;
        llps_yml_zero_software_ecc(cfg);
        llps_yml_zero_software_numa(cfg);
        cfg->software_fault_injection_mode =
            LLPS_SOFTWARE_FAULT_INJECTION_FULL;
        cfg->evidence_mac_enabled = 0u;
    }
}

/* -------------------------------------------------------------------------
 * Trim/comment/quote helpers
 * ------------------------------------------------------------------------- */

static char *llps_yml_trim_in_place(char * const s) {
    size_t len = 0u;
    size_t start = 0u;
    size_t end = 0u;

    if (s == NULL) {
        return NULL;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_LINE_LEN + 1u, &len)) {
        return NULL;
    }

    for (start = 0u;
         (start < len) && llps_yml_is_space(s[start]);
         ++start) {
    }

    for (end = len;
         (end > start) && llps_yml_is_space(s[end - 1u]);
         --end) {
    }

    s[end] = '\0';

    return &s[start];
}

static void llps_yml_strip_comment(char * const line) {
    size_t i = 0u;
    bool in_single_quote = false;
    bool in_double_quote = false;

    if (line == NULL) {
        return;
    }

    for (i = 0u; i < LLPS_YML_MAX_LINE_LEN; ++i) {
        const char c = line[i];

        if (c == '\0') {
            return;
        }

        if ((c == '\'') && !in_double_quote) {
            in_single_quote = !in_single_quote;
            continue;
        }

        if ((c == '"') && !in_single_quote) {
            in_double_quote = !in_double_quote;
            continue;
        }

        if ((c == '#') && !in_single_quote && !in_double_quote) {
            line[i] = '\0';
            return;
        }
    }
}

static llps_yml_status_t llps_yml_unquote_value(char ** const value_ref) {
    char *value = NULL;
    size_t len = 0u;
    size_t i = 0u;

    if (value_ref == NULL) {
        return LLPS_YML_E_NULL;
    }

    value = *value_ref;
    if (value == NULL) {
        return LLPS_YML_E_NULL;
    }

    if (!llps_yml_bounded_strlen(value, LLPS_YML_MAX_VALUE_LEN + 1u, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    if ((value[0] == '\'') || (value[0] == '"')) {
        const char quote = value[0];

        if ((len < 2u) || (value[len - 1u] != quote)) {
            return LLPS_YML_E_SYNTAX;
        }

        for (i = 1u; i < (len - 1u); ++i) {
            if ((value[i] == quote) || (value[i] == '\\')) {
                return LLPS_YML_E_SYNTAX;
            }
        }

        value[len - 1u] = '\0';
        *value_ref = &value[1];
        return LLPS_YML_OK;
    }

    for (i = 0u; i < len; ++i) {
        if ((value[i] == '\'') || (value[i] == '"') || (value[i] == '\\')) {
            return LLPS_YML_E_SYNTAX;
        }
    }

    return LLPS_YML_OK;
}

/* -------------------------------------------------------------------------
 * Scalar parsers
 * ------------------------------------------------------------------------- */

static llps_yml_status_t llps_yml_parse_u32(const char * const s,
                                            const uint32_t min_value,
                                            const uint32_t max_value,
                                            uint32_t * const out_value) {
    uint32_t value = 0u;
    size_t len = 0u;
    size_t i = 0u;

    if ((s == NULL) || (out_value == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (min_value > max_value) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_VALUE_LEN + 1u, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    for (i = 0u; i < len; ++i) {
        uint32_t digit = 0u;

        if (!llps_yml_is_digit(s[i])) {
            return LLPS_YML_E_SYNTAX;
        }

        digit = (uint32_t)(s[i] - '0');

        if (value > ((max_value - digit) / 10u)) {
            return LLPS_YML_E_RANGE;
        }

        value = (value * 10u) + digit;
    }

    if ((value < min_value) || (value > max_value)) {
        return LLPS_YML_E_RANGE;
    }

    *out_value = value;
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_u64(const char * const s,
                                            const uint64_t min_value,
                                            const uint64_t max_value,
                                            uint64_t * const out_value) {
    uint64_t value = 0u;
    size_t len = 0u;
    size_t i = 0u;

    if ((s == NULL) || (out_value == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (min_value > max_value) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_VALUE_LEN + 1u, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    for (i = 0u; i < len; ++i) {
        uint64_t digit = 0u;

        if (!llps_yml_is_digit(s[i])) {
            return LLPS_YML_E_SYNTAX;
        }

        digit = (uint64_t)((uint32_t)s[i] - (uint32_t)'0');
        if (value > ((UINT64_MAX - digit) / 10u)) {
            return LLPS_YML_E_RANGE;
        }
        value = (value * 10u) + digit;
    }

    if ((value < min_value) || (value > max_value)) {
        return LLPS_YML_E_RANGE;
    }

    *out_value = value;
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_platform_evidence_mode(
    const char * const s,
    uint32_t * const out_mode) {
    uint32_t value = 0u;

    if ((s == NULL) || (out_mode == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (llps_yml_streq(s, "real", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_PLATFORM_EVIDENCE_MODE_REAL;
        return LLPS_YML_OK;
    }

    if (llps_yml_streq(s, "synthetic", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC;
        return LLPS_YML_OK;
    }

    if (llps_yml_streq(s, "hybrid", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_PLATFORM_EVIDENCE_MODE_HYBRID;
        return LLPS_YML_OK;
    }

    if (llps_yml_parse_u32(s,
                           LLPS_PLATFORM_EVIDENCE_MODE_REAL,
                           LLPS_PLATFORM_EVIDENCE_MODE_HYBRID,
                           &value) != LLPS_YML_OK) {
        return LLPS_YML_E_SYNTAX;
    }

    *out_mode = value;
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_software_fault_injection_mode(
    const char * const s,
    uint32_t * const out_mode) {
    uint32_t value = 0u;

    if ((s == NULL) || (out_mode == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (llps_yml_streq(s, "off", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_SOFTWARE_FAULT_INJECTION_OFF;
        return LLPS_YML_OK;
    }

    if (llps_yml_streq(s, "single", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_SOFTWARE_FAULT_INJECTION_SINGLE;
        return LLPS_YML_OK;
    }

    if (llps_yml_streq(s, "double", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE;
        return LLPS_YML_OK;
    }

    if (llps_yml_streq(s, "full", LLPS_YML_MAX_VALUE_LEN)) {
        *out_mode = LLPS_SOFTWARE_FAULT_INJECTION_FULL;
        return LLPS_YML_OK;
    }

    if (llps_yml_parse_u32(s,
                           LLPS_SOFTWARE_FAULT_INJECTION_OFF,
                           LLPS_SOFTWARE_FAULT_INJECTION_MAX,
                           &value) != LLPS_YML_OK) {
        return LLPS_YML_E_SYNTAX;
    }

    *out_mode = value;
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_port(const char * const s,
                                             uint16_t * const out_port) {
    uint32_t value = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    if (out_port == NULL) {
        return LLPS_YML_E_NULL;
    }

    st = llps_yml_parse_u32(s, 1u, 65535u, &value);
    if (st != LLPS_YML_OK) {
        return st;
    }

    *out_port = (uint16_t)value;
    return LLPS_YML_OK;
}

static void llps_yml_ipv4_scan_init(llps_yml_ipv4_scan_t * const scan) {
    if (scan != NULL) {
        scan->octet_count = 0u;
        scan->digit_count = 0u;
        scan->value = 0u;
        scan->first_digit = '\0';
    }
}

static llps_yml_status_t llps_yml_ipv4_scan_digit(
    llps_yml_ipv4_scan_t * const scan,
    const char c) {
    if (scan == NULL) {
        return LLPS_YML_E_NULL;
    }

    if (scan->digit_count == 0u) {
        scan->first_digit = c;
        scan->value = 0u;
    } else if (scan->first_digit == '0') {
        return LLPS_YML_E_SYNTAX;
    }

    ++scan->digit_count;
    if (scan->digit_count > 3u) {
        return LLPS_YML_E_RANGE;
    }

    scan->value = (scan->value * 10u) + (uint32_t)(c - '0');
    if (scan->value > 255u) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_ipv4_scan_separator(
    llps_yml_ipv4_scan_t * const scan,
    const char c,
    bool * const out_done) {
    if ((scan == NULL) || (out_done == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (scan->digit_count == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    ++scan->octet_count;
    *out_done = (c == '\0');
    if (*out_done) {
        return LLPS_YML_OK;
    }

    if (scan->octet_count >= 4u) {
        return LLPS_YML_E_SYNTAX;
    }

    scan->digit_count = 0u;
    scan->value = 0u;
    scan->first_digit = '\0';
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_ipv4_text_only(const char * const s,
                                                       char * const dst,
                                                       const size_t dst_cap) {
    size_t len = 0u;
    size_t i = 0u;
    llps_yml_ipv4_scan_t scan;

    if ((s == NULL) || (dst == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (dst_cap < LLPS_YML_MAX_IP_TEXT) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_IP_TEXT, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    llps_yml_ipv4_scan_init(&scan);
    for (i = 0u; i <= len; ++i) {
        const char c = s[i];

        if (llps_yml_is_digit(c)) {
            const llps_yml_status_t digit_st =
                llps_yml_ipv4_scan_digit(&scan, c);
            if (digit_st != LLPS_YML_OK) {
                return digit_st;
            }

            continue;
        }

        if ((c == '.') || (c == '\0')) {
            bool done = false;
            const llps_yml_status_t sep_st =
                llps_yml_ipv4_scan_separator(&scan, c, &done);
            if (sep_st != LLPS_YML_OK) {
                return sep_st;
            }
            if (done) {
                break;
            }
            continue;
        }

        return LLPS_YML_E_SYNTAX;
    }

    if (scan.octet_count != 4u) {
        return LLPS_YML_E_SYNTAX;
    }

    return llps_yml_copy_cstr(dst, dst_cap, s);
}

static llps_yml_status_t llps_yml_validate_dns_host_text(
    const char * const s,
    const size_t len) {
    size_t label_len = 0u;
    size_t i = 0u;
    char previous = '\0';

    if (s == NULL) {
        return LLPS_YML_E_NULL;
    }

    if ((len == 0u) || (len > LLPS_YML_MAX_DNS_NAME_LEN)) {
        return LLPS_YML_E_RANGE;
    }

    for (i = 0u; i < len; ++i) {
        const char c = s[i];

        if (c == '.') {
            if ((label_len == 0u) || (previous == '-')) {
                return LLPS_YML_E_SYNTAX;
            }

            label_len = 0u;
            previous = c;
            continue;
        }

        if (!llps_yml_is_dns_label_char(c)) {
            return LLPS_YML_E_SYNTAX;
        }

        if ((label_len == 0u) && (c == '-')) {
            return LLPS_YML_E_SYNTAX;
        }

        ++label_len;
        if (label_len > LLPS_YML_MAX_DNS_LABEL_LEN) {
            return LLPS_YML_E_RANGE;
        }

        previous = c;
    }

    if ((label_len == 0u) && (s[len - 1u] != '.')) {
        return LLPS_YML_E_SYNTAX;
    }

    if (previous == '-') {
        return LLPS_YML_E_SYNTAX;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_parse_host_text(const char * const s,
                                                  char * const dst,
                                                  const size_t dst_cap) {
    size_t len = 0u;
    size_t i = 0u;
    bool numeric_or_dot_only = true;
    llps_yml_status_t st = LLPS_YML_OK;

    if ((s == NULL) || (dst == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (dst_cap < LLPS_YML_MAX_IP_TEXT) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_IP_TEXT, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    for (i = 0u; i < len; ++i) {
        if (!llps_yml_is_digit(s[i]) && (s[i] != '.')) {
            numeric_or_dot_only = false;
            break;
        }
    }

    if (numeric_or_dot_only) {
        return llps_yml_parse_ipv4_text_only(s, dst, dst_cap);
    }

    st = llps_yml_validate_dns_host_text(s, len);
    if (st != LLPS_YML_OK) {
        return st;
    }

    return llps_yml_copy_cstr(dst, dst_cap, s);
}

static bool llps_yml_path_has_parent_component(const char * const s,
                                               const size_t len) {
    size_t start = 0u;

    for (size_t i = 0u; i <= len; ++i) {
        if ((i == len) || (s[i] == '/')) {
            const size_t component_len = i - start;

            if ((component_len == 2u) &&
                (s[start] == '.') &&
                (s[start + 1u] == '.')) {
                return true;
            }

            start = i + 1u;
        }
    }

    return false;
}

static bool llps_yml_path_has_pxf_extension(const char * const s,
                                            const size_t len) {
    return (s != NULL) &&
           (len >= 5u) &&
           (s[len - 4u] == '.') &&
           (s[len - 3u] == 'p') &&
           (s[len - 2u] == 'x') &&
           (s[len - 1u] == 'f');
}

static llps_yml_status_t llps_yml_parse_path_text(const char * const s,
                                                  char * const dst,
                                                  const size_t dst_cap) {
    size_t len = 0u;

    if ((s == NULL) || (dst == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (dst_cap < LLPS_YML_MAX_PATH_TEXT) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_PATH_TEXT, &len)) {
        return LLPS_YML_E_STRING;
    }

    if ((len == 0u) || (s[0] != '/') || (s[len - 1u] == '/')) {
        return LLPS_YML_E_SYNTAX;
    }

    if (llps_yml_path_has_parent_component(s, len)) {
        return LLPS_YML_E_SYNTAX;
    }

    if (!llps_yml_path_has_pxf_extension(s, len)) {
        return LLPS_YML_E_SYNTAX;
    }

    for (size_t i = 0u; i < len; ++i) {
        const char c = s[i];

        if (!llps_yml_is_alnum(c) &&
            (c != '/') &&
            (c != '.') &&
            (c != '_') &&
            (c != '-')) {
            return LLPS_YML_E_SYNTAX;
        }

        if ((c == '/') && (i > 0u) && (s[i - 1u] == '/')) {
            return LLPS_YML_E_SYNTAX;
        }
    }

    return llps_yml_copy_cstr(dst, dst_cap, s);
}

static llps_yml_status_t llps_yml_parse_key_path_text(
    const char * const s,
    char * const dst,
    const size_t dst_cap) {
    size_t len = 0u;

    if ((s == NULL) || (dst == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (dst_cap < LLPS_YML_MAX_PATH_TEXT) {
        return LLPS_YML_E_RANGE;
    }

    if (!llps_yml_bounded_strlen(s, LLPS_YML_MAX_PATH_TEXT, &len)) {
        return LLPS_YML_E_STRING;
    }

    if ((len == 0u) || (s[0] != '/') || (s[len - 1u] == '/')) {
        return LLPS_YML_E_SYNTAX;
    }

    if (llps_yml_path_has_parent_component(s, len)) {
        return LLPS_YML_E_SYNTAX;
    }

    for (size_t i = 0u; i < len; ++i) {
        const char c = s[i];

        if (!llps_yml_is_alnum(c) &&
            (c != '/') &&
            (c != '.') &&
            (c != '_') &&
            (c != '-')) {
            return LLPS_YML_E_SYNTAX;
        }

        if ((c == '/') && (i > 0u) && (s[i - 1u] == '/')) {
            return LLPS_YML_E_SYNTAX;
        }
    }

    return llps_yml_copy_cstr(dst, dst_cap, s);
}

/* -------------------------------------------------------------------------
 * Key handling
 * ------------------------------------------------------------------------- */

static llps_yml_status_t llps_yml_validate_key_syntax(const char * const key) {
    size_t len = 0u;
    size_t i = 0u;

    if (key == NULL) {
        return LLPS_YML_E_NULL;
    }

    if (!llps_yml_bounded_strlen(key, LLPS_YML_MAX_KEY_LEN + 1u, &len)) {
        return LLPS_YML_E_STRING;
    }

    if (len == 0u) {
        return LLPS_YML_E_SYNTAX;
    }

    for (i = 0u; i < len; ++i) {
        if (!llps_yml_is_key_char(key[i])) {
            return LLPS_YML_E_SYNTAX;
        }
    }

    return LLPS_YML_OK;
}

static const llps_yml_key_name_t g_llps_yml_key_names[] = {
    {"max_clients", LLPS_YML_KEY_MAX_CLIENTS},
    {"buffer_size", LLPS_YML_KEY_BUFFER_SIZE},
    {"listen_host", LLPS_YML_KEY_LISTEN_HOST},
    {"listen_port", LLPS_YML_KEY_LISTEN_PORT},
    {"target_ip", LLPS_YML_KEY_TARGET_IP},
    {"target_host", LLPS_YML_KEY_TARGET_IP},
    {"target_port", LLPS_YML_KEY_TARGET_PORT},
    {"listen_backlog", LLPS_YML_KEY_LISTEN_BACKLOG},
    {"accept_batch_max", LLPS_YML_KEY_ACCEPT_BATCH_MAX},
    {"session_idle_timeout_ms", LLPS_YML_KEY_SESSION_IDLE_TIMEOUT_MS},
    {"max_sessions_per_client_ip", LLPS_YML_KEY_MAX_SESSIONS_PER_CLIENT_IP},
    {"max_new_sessions_per_client_ip_per_window",
     LLPS_YML_KEY_MAX_NEW_SESSIONS_PER_CLIENT_IP_PER_WINDOW},
    {"client_ip_rate_window_ms", LLPS_YML_KEY_CLIENT_IP_RATE_WINDOW_MS},
    {"client_preface_timeout_ms", LLPS_YML_KEY_CLIENT_PREFACE_TIMEOUT_MS},
    {"protocol_handshake_gate_enabled",
     LLPS_YML_KEY_PROTOCOL_HANDSHAKE_GATE_ENABLED},
    {"payload_ecc_enabled", LLPS_YML_KEY_PAYLOAD_ECC_ENABLED},
    {"ip_audit_enabled", LLPS_YML_KEY_IP_AUDIT_ENABLED},
    {"ip_audit_path", LLPS_YML_KEY_IP_AUDIT_PATH},
    {"audit_mac_enabled", LLPS_YML_KEY_AUDIT_MAC_ENABLED},
    {"audit_mac_key_path", LLPS_YML_KEY_AUDIT_MAC_KEY_PATH},
    {"require_readiness", LLPS_YML_KEY_REQUIRE_READINESS},
    {"platform_safety_flags", LLPS_YML_KEY_PLATFORM_SAFETY_FLAGS},
    {"platform_safety_evidence_id", LLPS_YML_KEY_PLATFORM_SAFETY_EVIDENCE_ID},
    {"platform_attestation_fingerprint",
     LLPS_YML_KEY_PLATFORM_ATTESTATION_FINGERPRINT},
    {"platform_observation_digest", LLPS_YML_KEY_PLATFORM_OBSERVATION_DIGEST},
    {"platform_evidence_mode", LLPS_YML_KEY_PLATFORM_EVIDENCE_MODE},
    {"phys_mem_domain0", LLPS_YML_KEY_PHYS_MEM_DOMAIN0},
    {"phys_mem_domain1", LLPS_YML_KEY_PHYS_MEM_DOMAIN1},
    {"phys_mem_domain2", LLPS_YML_KEY_PHYS_MEM_DOMAIN2},
    {"hw_tmr_domain0", LLPS_YML_KEY_HW_TMR_DOMAIN0},
    {"hw_tmr_domain1", LLPS_YML_KEY_HW_TMR_DOMAIN1},
    {"hw_tmr_domain2", LLPS_YML_KEY_HW_TMR_DOMAIN2},
    {"hw_tmr_voter_domain", LLPS_YML_KEY_HW_TMR_VOTER_DOMAIN},
    {"software_ecc_enabled", LLPS_YML_KEY_SOFTWARE_ECC_ENABLED},
    {"software_ecc_controller_count",
     LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_COUNT},
    {"software_ecc_dimm_count", LLPS_YML_KEY_SOFTWARE_ECC_DIMM_COUNT},
    {"software_ecc_scrub_rate", LLPS_YML_KEY_SOFTWARE_ECC_SCRUB_RATE},
    {"software_ecc_controller_corrected_error_count",
     LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_CORRECTED_ERROR_COUNT},
    {"software_ecc_controller_uncorrected_error_count",
     LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_UNCORRECTED_ERROR_COUNT},
    {"software_ecc_dimm_corrected_error_count",
     LLPS_YML_KEY_SOFTWARE_ECC_DIMM_CORRECTED_ERROR_COUNT},
    {"software_ecc_dimm_uncorrected_error_count",
     LLPS_YML_KEY_SOFTWARE_ECC_DIMM_UNCORRECTED_ERROR_COUNT},
    {"software_numa_enabled", LLPS_YML_KEY_SOFTWARE_NUMA_ENABLED},
    {"software_numa_memtotal_kib", LLPS_YML_KEY_SOFTWARE_NUMA_MEMTOTAL_KIB},
    {"software_numa_local_distance", LLPS_YML_KEY_SOFTWARE_NUMA_LOCAL_DISTANCE},
    {"software_numa_remote_distance",
     LLPS_YML_KEY_SOFTWARE_NUMA_REMOTE_DISTANCE},
    {"software_fault_injection_mode", LLPS_YML_KEY_SOFTWARE_FAULT_INJECTION_MODE},
    {"evidence_mac_enabled", LLPS_YML_KEY_EVIDENCE_MAC_ENABLED},
    {"evidence_mac_key_path", LLPS_YML_KEY_EVIDENCE_MAC_KEY_PATH}
};

static llps_yml_status_t llps_yml_key_from_string(const char * const key,
                                                  llps_yml_key_t * const out_key) {
    const size_t key_name_count =
        sizeof(g_llps_yml_key_names) / sizeof(g_llps_yml_key_names[0]);

    if ((key == NULL) || (out_key == NULL)) {
        return LLPS_YML_E_NULL;
    }

    for (size_t i = 0u; i < key_name_count; ++i) {
        if (llps_yml_streq(key,
                           g_llps_yml_key_names[i].name,
                           LLPS_YML_MAX_KEY_LEN)) {
            *out_key = g_llps_yml_key_names[i].key;
            return LLPS_YML_OK;
        }
    }

    return LLPS_YML_E_KEY;
}

/* -------------------------------------------------------------------------
 * Config validation
 * ------------------------------------------------------------------------- */

static bool llps_yml_domain_ids_are_distinct(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (ids == NULL) {
        return false;
    }

    return (ids[0] != 0u) &&
           (ids[1] != 0u) &&
           (ids[2] != 0u) &&
           (ids[0] != ids[1]) &&
           (ids[0] != ids[2]) &&
           (ids[1] != ids[2]);
}

static bool llps_yml_domain_ids_are_zero(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (ids == NULL) {
        return true;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (ids[i] != 0u) {
            return false;
        }
    }

    return true;
}

static bool llps_yml_domain_id_sets_are_disjoint(
    const uint32_t lhs[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t rhs[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        for (size_t j = 0u; j < LLPS_SESSION_TMR_BANK_COUNT; ++j) {
            if ((lhs[i] == 0u) || (rhs[j] == 0u) || (lhs[i] == rhs[j])) {
                return false;
            }
        }
    }

    return true;
}

static bool llps_yml_domain_id_is_disjoint_from_set(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t domain_id) {
    if ((ids == NULL) || (domain_id == 0u)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if ((ids[i] == 0u) || (ids[i] == domain_id)) {
            return false;
        }
    }

    return true;
}

static llps_yml_status_t llps_yml_validate_listener_limits(
    const llps_yml_config_t * const cfg) {
    if ((cfg->max_clients == 0u) || (cfg->max_clients > LLPS_MAX_CLIENTS)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->buffer_size == 0u) || (cfg->buffer_size > LLPS_BUFFER_SIZE)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->listen_port == 0u) || (cfg->target_port == 0u)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->listen_backlog == 0u) ||
        (cfg->listen_backlog > LLPS_LISTEN_BACKLOG)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->accept_batch_max == 0u) ||
        (cfg->accept_batch_max > LLPS_ACCEPT_BATCH_MAX) ||
        (cfg->accept_batch_max > cfg->max_clients) ||
        (cfg->listen_backlog < cfg->accept_batch_max)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_session_limits(
    const llps_yml_config_t * const cfg) {
    if ((cfg->session_idle_timeout_ms <
         LLPS_SESSION_IDLE_TIMEOUT_MS_MIN) ||
        (cfg->session_idle_timeout_ms >
         LLPS_SESSION_IDLE_TIMEOUT_MS_MAX)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->max_sessions_per_client_ip > cfg->max_clients) ||
        (cfg->max_new_sessions_per_client_ip_per_window >
         LLPS_CLIENT_IP_RATE_LIMIT_MAX)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->client_ip_rate_window_ms <
         LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN) ||
        (cfg->client_ip_rate_window_ms >
         LLPS_CLIENT_IP_RATE_WINDOW_MS_MAX)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->client_preface_timeout_ms != 0u) &&
        ((cfg->client_preface_timeout_ms <
          LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN) ||
         (cfg->client_preface_timeout_ms >
          LLPS_CLIENT_PREFACE_TIMEOUT_MS_MAX))) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_feature_modes(
    const llps_yml_config_t * const cfg) {
    if ((cfg->protocol_handshake_gate_enabled > 1u) ||
        ((cfg->protocol_handshake_gate_enabled != 0u) &&
         (cfg->client_preface_timeout_ms == 0u))) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->payload_ecc_enabled > 1u) ||
        (cfg->require_readiness > 1u) ||
        (cfg->ip_audit_enabled > 1u) ||
        (cfg->audit_mac_enabled > 1u)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->platform_evidence_mode >
         LLPS_PLATFORM_EVIDENCE_MODE_HYBRID) ||
        (cfg->evidence_mac_enabled > 1u) ||
        (cfg->software_ecc_enabled > 1u) ||
        (cfg->software_numa_enabled > 1u) ||
        (cfg->software_fault_injection_mode >
         LLPS_SOFTWARE_FAULT_INJECTION_MAX)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_software_mode_mix(
    const llps_yml_config_t * const cfg) {
    if ((cfg->platform_evidence_mode == LLPS_PLATFORM_EVIDENCE_MODE_REAL) &&
        ((cfg->software_ecc_enabled != 0u) ||
         (cfg->software_numa_enabled != 0u))) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->require_readiness != 0u) &&
        (cfg->software_ecc_enabled != 0u) &&
        (cfg->payload_ecc_enabled == 0u)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static bool llps_yml_software_ecc_fields_are_zero(
    const llps_yml_config_t * const cfg) {
    return (cfg->software_ecc_controller_count == 0u) &&
           (cfg->software_ecc_dimm_count == 0u) &&
           (cfg->software_ecc_scrub_rate == 0u) &&
           (cfg->software_ecc_controller_corrected_error_count == 0u) &&
           (cfg->software_ecc_controller_uncorrected_error_count == 0u) &&
           (cfg->software_ecc_dimm_corrected_error_count == 0u) &&
           (cfg->software_ecc_dimm_uncorrected_error_count == 0u);
}

static llps_yml_status_t llps_yml_validate_software_ecc(
    const llps_yml_config_t * const cfg) {
    if (cfg->software_ecc_enabled == 0u) {
        return llps_yml_software_ecc_fields_are_zero(cfg) ?
            LLPS_YML_OK : LLPS_YML_E_RANGE;
    }

    if ((cfg->software_ecc_controller_count == 0u) ||
        (cfg->software_ecc_controller_count >
         LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) ||
        (cfg->software_ecc_dimm_count == 0u) ||
        (cfg->software_ecc_dimm_count >
         LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX) ||
        (cfg->software_ecc_controller_count >
         cfg->software_ecc_dimm_count) ||
        (cfg->software_ecc_scrub_rate == 0u) ||
        (cfg->software_ecc_scrub_rate >
         LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static bool llps_yml_software_numa_fields_are_zero(
    const llps_yml_config_t * const cfg) {
    return (cfg->software_numa_memtotal_kib == 0u) &&
           (cfg->software_numa_local_distance == 0u) &&
           (cfg->software_numa_remote_distance == 0u);
}

static llps_yml_status_t llps_yml_validate_software_numa(
    const llps_yml_config_t * const cfg) {
    if (cfg->software_numa_enabled == 0u) {
        return llps_yml_software_numa_fields_are_zero(cfg) ?
            LLPS_YML_OK : LLPS_YML_E_RANGE;
    }

    if ((cfg->software_numa_memtotal_kib == 0u) ||
        (cfg->software_numa_memtotal_kib >
         LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX) ||
        ((cfg->software_numa_local_distance == 0u) !=
         (cfg->software_numa_remote_distance == 0u)) ||
        (cfg->software_numa_local_distance >
         LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ||
        (cfg->software_numa_remote_distance >
         LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ||
        ((cfg->software_numa_local_distance != 0u) &&
         (cfg->software_numa_remote_distance <=
          cfg->software_numa_local_distance)) ||
        ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_required_paths(
    const llps_yml_config_t * const cfg) {
    if ((cfg->ip_audit_enabled != 0u) && (cfg->ip_audit_path[0] == '\0')) {
        return LLPS_YML_E_REQUIRED;
    }

    if ((cfg->audit_mac_enabled != 0u) &&
        ((cfg->ip_audit_enabled == 0u) ||
         (cfg->audit_mac_key_path[0] == '\0'))) {
        return LLPS_YML_E_REQUIRED;
    }

    if ((cfg->evidence_mac_enabled != 0u) &&
        (cfg->evidence_mac_key_path[0] == '\0')) {
        return LLPS_YML_E_REQUIRED;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_platform_policy(
    const llps_yml_config_t * const cfg) {
    if ((cfg->platform_safety_flags & ~LLPS_PLATFORM_EVIDENCE_REQUIRED) != 0u) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->platform_evidence_mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) &&
        (((cfg->platform_safety_flags &
           LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u) ||
         ((cfg->platform_safety_flags &
           LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u)) &&
        (cfg->software_ecc_enabled == 0u)) {
        return LLPS_YML_E_RANGE;
    }

    if ((cfg->platform_evidence_mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) &&
        ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) &&
        (cfg->software_numa_enabled == 0u)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_platform_domains(
    const llps_yml_config_t * const cfg) {
    if (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) &&
        !llps_yml_domain_ids_are_zero(cfg->platform_physical_memory_domains)) {
        return LLPS_YML_E_RANGE;
    }

    if (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) == 0u) &&
        (!llps_yml_domain_ids_are_zero(cfg->platform_hardware_tmr_domains) ||
         (cfg->platform_hardware_tmr_voter_domain != 0u))) {
        return LLPS_YML_E_RANGE;
    }

    if (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) &&
        !llps_yml_domain_ids_are_distinct(
             cfg->platform_physical_memory_domains)) {
        return LLPS_YML_E_RANGE;
    }

    if (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) &&
        (!llps_yml_domain_ids_are_distinct(
             cfg->platform_hardware_tmr_domains) ||
         !llps_yml_domain_id_is_disjoint_from_set(
             cfg->platform_hardware_tmr_domains,
             cfg->platform_hardware_tmr_voter_domain))) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_external_domain_mix(
    const llps_yml_config_t * const cfg) {
    if (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) ==
         LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) &&
        (!llps_yml_domain_id_sets_are_disjoint(
              cfg->platform_physical_memory_domains,
              cfg->platform_hardware_tmr_domains) ||
         !llps_yml_domain_id_is_disjoint_from_set(
              cfg->platform_physical_memory_domains,
              cfg->platform_hardware_tmr_voter_domain))) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_readiness_contract(
    const llps_yml_config_t * const cfg,
    const bool enforce_attestation_fingerprint) {
    if ((cfg->require_readiness != 0u) &&
        ((cfg->platform_safety_evidence_id == 0u) ||
         (enforce_attestation_fingerprint &&
          (cfg->platform_attestation_fingerprint == 0u)) ||
         ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_REQUIRED) !=
          LLPS_PLATFORM_EVIDENCE_REQUIRED))) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_attestation_fingerprint(
    const llps_yml_config_t * const cfg,
    const bool enforce_attestation_fingerprint) {
    uint32_t expected_fingerprint = 0u;
    llps_status_t st = LLPS_OK;

    if ((cfg->platform_safety_flags == 0u) &&
        (cfg->platform_safety_evidence_id == 0u) &&
        (cfg->platform_attestation_fingerprint == 0u) &&
        (cfg->platform_observation_digest == 0u)) {
        return LLPS_YML_OK;
    }

    st = llps_compute_platform_attestation_fingerprint(
        cfg->platform_safety_flags,
        cfg->platform_safety_evidence_id,
        cfg->platform_physical_memory_domains,
        cfg->platform_hardware_tmr_domains,
        cfg->platform_hardware_tmr_voter_domain,
        &expected_fingerprint);
    if (st != LLPS_OK) {
        return LLPS_YML_E_RANGE;
    }

    if (enforce_attestation_fingerprint &&
        (cfg->platform_attestation_fingerprint != 0u) &&
        (cfg->platform_attestation_fingerprint != expected_fingerprint)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_no_self_loop(
    const llps_yml_config_t * const cfg) {
    if ((cfg->listen_port == cfg->target_port) &&
        llps_yml_streq(cfg->listen_host,
                       cfg->target_ip,
                       LLPS_YML_MAX_IP_TEXT)) {
        return LLPS_YML_E_RANGE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_validate_config(
    const llps_yml_config_t * const cfg,
    const bool enforce_attestation_fingerprint) {
    llps_yml_status_t st = LLPS_YML_OK;

    if (cfg == NULL) {
        return LLPS_YML_E_NULL;
    }

    st = llps_yml_validate_listener_limits(cfg);
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_session_limits(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_feature_modes(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_software_mode_mix(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_software_ecc(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_software_numa(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_required_paths(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_platform_policy(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_platform_domains(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_external_domain_mix(cfg);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_readiness_contract(
            cfg,
            enforce_attestation_fingerprint);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_attestation_fingerprint(
            cfg,
            enforce_attestation_fingerprint);
    }
    if (st == LLPS_YML_OK) {
        st = llps_yml_validate_no_self_loop(cfg);
    }

    return st;
}

/* -------------------------------------------------------------------------
 * Line parser
 * ------------------------------------------------------------------------- */

static llps_yml_status_t llps_yml_apply_u32_field(
    const char * const value,
    const uint32_t min_value,
    const uint32_t max_value,
    uint32_t * const dst) {
    uint32_t parsed_u32 = 0u;
    const llps_yml_status_t st =
        llps_yml_parse_u32(value, min_value, max_value, &parsed_u32);

    if (st == LLPS_YML_OK) {
        *dst = parsed_u32;
    }

    return st;
}

static llps_yml_status_t llps_yml_apply_u64_field(
    const char * const value,
    const uint64_t min_value,
    const uint64_t max_value,
    uint64_t * const dst) {
    uint64_t parsed_u64 = 0u;
    const llps_yml_status_t st =
        llps_yml_parse_u64(value, min_value, max_value, &parsed_u64);

    if (st == LLPS_YML_OK) {
        *dst = parsed_u64;
    }

    return st;
}

static llps_yml_status_t llps_yml_apply_capacity_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_MAX_CLIENTS:
        return llps_yml_apply_u32_field(value,
                                        1u,
                                        LLPS_MAX_CLIENTS,
                                        &cfg->max_clients);

    case LLPS_YML_KEY_BUFFER_SIZE:
        return llps_yml_apply_u32_field(value,
                                        1u,
                                        LLPS_BUFFER_SIZE,
                                        &cfg->buffer_size);

    case LLPS_YML_KEY_LISTEN_BACKLOG:
        return llps_yml_apply_u32_field(value,
                                        1u,
                                        LLPS_LISTEN_BACKLOG,
                                        &cfg->listen_backlog);

    case LLPS_YML_KEY_ACCEPT_BATCH_MAX:
        return llps_yml_apply_u32_field(value,
                                        1u,
                                        LLPS_ACCEPT_BATCH_MAX,
                                        &cfg->accept_batch_max);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_endpoint_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_LISTEN_HOST:
        return llps_yml_parse_host_text(value,
                                        cfg->listen_host,
                                        sizeof(cfg->listen_host));

    case LLPS_YML_KEY_LISTEN_PORT:
        return llps_yml_parse_port(value, &cfg->listen_port);

    case LLPS_YML_KEY_TARGET_IP:
        return llps_yml_parse_host_text(value,
                                        cfg->target_ip,
                                        sizeof(cfg->target_ip));

    case LLPS_YML_KEY_TARGET_PORT:
        return llps_yml_parse_port(value, &cfg->target_port);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_preface_timeout(
    const char * const value,
    llps_yml_config_t * const cfg) {
    uint32_t parsed_u32 = 0u;
    llps_yml_status_t st = llps_yml_parse_u32(
        value,
        0u,
        LLPS_CLIENT_PREFACE_TIMEOUT_MS_MAX,
        &parsed_u32);

    if ((st == LLPS_YML_OK) && (parsed_u32 != 0u) &&
        (parsed_u32 < LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN)) {
        st = LLPS_YML_E_RANGE;
    }

    if (st == LLPS_YML_OK) {
        cfg->client_preface_timeout_ms = parsed_u32;
    }

    return st;
}

static llps_yml_status_t llps_yml_apply_session_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {

    case LLPS_YML_KEY_SESSION_IDLE_TIMEOUT_MS:
        return llps_yml_apply_u32_field(value,
                                        LLPS_SESSION_IDLE_TIMEOUT_MS_MIN,
                                        LLPS_SESSION_IDLE_TIMEOUT_MS_MAX,
                                        &cfg->session_idle_timeout_ms);

    case LLPS_YML_KEY_MAX_SESSIONS_PER_CLIENT_IP:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        LLPS_MAX_CLIENTS,
                                        &cfg->max_sessions_per_client_ip);

    case LLPS_YML_KEY_MAX_NEW_SESSIONS_PER_CLIENT_IP_PER_WINDOW:
        return llps_yml_apply_u32_field(
            value,
            0u,
            LLPS_CLIENT_IP_RATE_LIMIT_MAX,
            &cfg->max_new_sessions_per_client_ip_per_window);

    case LLPS_YML_KEY_CLIENT_IP_RATE_WINDOW_MS:
        return llps_yml_apply_u32_field(value,
                                        LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN,
                                        LLPS_CLIENT_IP_RATE_WINDOW_MS_MAX,
                                        &cfg->client_ip_rate_window_ms);

    case LLPS_YML_KEY_CLIENT_PREFACE_TIMEOUT_MS:
        return llps_yml_apply_preface_timeout(value, cfg);

    case LLPS_YML_KEY_PROTOCOL_HANDSHAKE_GATE_ENABLED:
        return llps_yml_apply_u32_field(
            value,
            0u,
            1u,
            &cfg->protocol_handshake_gate_enabled);

    case LLPS_YML_KEY_PAYLOAD_ECC_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->payload_ecc_enabled);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_audit_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_IP_AUDIT_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->ip_audit_enabled);

    case LLPS_YML_KEY_IP_AUDIT_PATH:
        return llps_yml_parse_path_text(value,
                                        cfg->ip_audit_path,
                                        sizeof(cfg->ip_audit_path));

    case LLPS_YML_KEY_AUDIT_MAC_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->audit_mac_enabled);

    case LLPS_YML_KEY_AUDIT_MAC_KEY_PATH:
        return llps_yml_parse_key_path_text(value,
                                            cfg->audit_mac_key_path,
                                            sizeof(cfg->audit_mac_key_path));

    case LLPS_YML_KEY_REQUIRE_READINESS:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->require_readiness);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_platform_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    uint32_t parsed_u32 = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    *handled = true;

    switch (key) {

    case LLPS_YML_KEY_PLATFORM_SAFETY_FLAGS:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        LLPS_PLATFORM_EVIDENCE_REQUIRED,
                                        &cfg->platform_safety_flags);

    case LLPS_YML_KEY_PLATFORM_SAFETY_EVIDENCE_ID:
        return llps_yml_apply_u64_field(value,
                                        0u,
                                        UINT64_MAX,
                                        &cfg->platform_safety_evidence_id);

    case LLPS_YML_KEY_PLATFORM_ATTESTATION_FINGERPRINT:
        return llps_yml_apply_u32_field(
            value,
            0u,
            UINT32_MAX,
            &cfg->platform_attestation_fingerprint);

    case LLPS_YML_KEY_PLATFORM_OBSERVATION_DIGEST:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        UINT32_MAX,
                                        &cfg->platform_observation_digest);

    case LLPS_YML_KEY_PLATFORM_EVIDENCE_MODE:
        st = llps_yml_parse_platform_evidence_mode(value, &parsed_u32);
        if (st == LLPS_YML_OK) {
            cfg->platform_evidence_mode = parsed_u32;
        }
        return st;

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static bool llps_yml_domain_key_is_supported(const llps_yml_key_t key) {
    return (key == LLPS_YML_KEY_PHYS_MEM_DOMAIN0) ||
           (key == LLPS_YML_KEY_PHYS_MEM_DOMAIN1) ||
           (key == LLPS_YML_KEY_PHYS_MEM_DOMAIN2) ||
           (key == LLPS_YML_KEY_HW_TMR_DOMAIN0) ||
           (key == LLPS_YML_KEY_HW_TMR_DOMAIN1) ||
           (key == LLPS_YML_KEY_HW_TMR_DOMAIN2) ||
           (key == LLPS_YML_KEY_HW_TMR_VOTER_DOMAIN);
}

static bool llps_yml_apply_physical_domain_value(
    const llps_yml_key_t key,
    const uint32_t value,
    llps_yml_config_t * const cfg) {
    switch (key) {
    case LLPS_YML_KEY_PHYS_MEM_DOMAIN0:
        cfg->platform_physical_memory_domains[0] = value;
        return true;

    case LLPS_YML_KEY_PHYS_MEM_DOMAIN1:
        cfg->platform_physical_memory_domains[1] = value;
        return true;

    case LLPS_YML_KEY_PHYS_MEM_DOMAIN2:
        cfg->platform_physical_memory_domains[2] = value;
        return true;

    default:
        return false;
    }
}

static bool llps_yml_apply_tmr_domain_value(
    const llps_yml_key_t key,
    const uint32_t value,
    llps_yml_config_t * const cfg) {
    switch (key) {
    case LLPS_YML_KEY_HW_TMR_DOMAIN0:
        cfg->platform_hardware_tmr_domains[0] = value;
        return true;

    case LLPS_YML_KEY_HW_TMR_DOMAIN1:
        cfg->platform_hardware_tmr_domains[1] = value;
        return true;

    case LLPS_YML_KEY_HW_TMR_DOMAIN2:
        cfg->platform_hardware_tmr_domains[2] = value;
        return true;

    case LLPS_YML_KEY_HW_TMR_VOTER_DOMAIN:
        cfg->platform_hardware_tmr_voter_domain = value;
        return true;

    default:
        return false;
    }
}

static llps_yml_status_t llps_yml_apply_domain_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    uint32_t parsed_u32 = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    if (!llps_yml_domain_key_is_supported(key)) {
        *handled = false;
        return LLPS_YML_OK;
    }

    *handled = true;
    st = llps_yml_parse_u32(value, 0u, UINT32_MAX, &parsed_u32);
    if (st != LLPS_YML_OK) {
        return st;
    }

    if (!llps_yml_apply_physical_domain_value(key, parsed_u32, cfg)) {
        (void)llps_yml_apply_tmr_domain_value(key, parsed_u32, cfg);
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_apply_software_ecc_u32_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_SOFTWARE_ECC_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->software_ecc_enabled);

    case LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_COUNT:
        return llps_yml_apply_u32_field(
            value,
            0u,
            LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX,
            &cfg->software_ecc_controller_count);

    case LLPS_YML_KEY_SOFTWARE_ECC_DIMM_COUNT:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX,
                                        &cfg->software_ecc_dimm_count);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_software_ecc_u64_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_SOFTWARE_ECC_SCRUB_RATE:
        return llps_yml_apply_u64_field(value,
                                        0u,
                                        LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX,
                                        &cfg->software_ecc_scrub_rate);

    case LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_CORRECTED_ERROR_COUNT:
        return llps_yml_apply_u64_field(
            value,
            0u,
            UINT64_MAX,
            &cfg->software_ecc_controller_corrected_error_count);

    case LLPS_YML_KEY_SOFTWARE_ECC_CONTROLLER_UNCORRECTED_ERROR_COUNT:
        return llps_yml_apply_u64_field(
            value,
            0u,
            UINT64_MAX,
            &cfg->software_ecc_controller_uncorrected_error_count);

    case LLPS_YML_KEY_SOFTWARE_ECC_DIMM_CORRECTED_ERROR_COUNT:
        return llps_yml_apply_u64_field(
            value,
            0u,
            UINT64_MAX,
            &cfg->software_ecc_dimm_corrected_error_count);

    case LLPS_YML_KEY_SOFTWARE_ECC_DIMM_UNCORRECTED_ERROR_COUNT:
        return llps_yml_apply_u64_field(
            value,
            0u,
            UINT64_MAX,
            &cfg->software_ecc_dimm_uncorrected_error_count);

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_software_ecc_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    llps_yml_status_t st =
        llps_yml_apply_software_ecc_u32_key(key, value, cfg, handled);

    if ((st != LLPS_YML_OK) || *handled) {
        return st;
    }

    return llps_yml_apply_software_ecc_u64_key(key, value, cfg, handled);
}

static llps_yml_status_t llps_yml_apply_software_numa_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    uint32_t parsed_u32 = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_SOFTWARE_NUMA_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->software_numa_enabled);

    case LLPS_YML_KEY_SOFTWARE_NUMA_MEMTOTAL_KIB:
        return llps_yml_apply_u64_field(value,
                                        0u,
                                        LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX,
                                        &cfg->software_numa_memtotal_kib);

    case LLPS_YML_KEY_SOFTWARE_NUMA_LOCAL_DISTANCE:
        return llps_yml_apply_u64_field(value,
                                        0u,
                                        LLPS_SOFTWARE_NUMA_DISTANCE_MAX,
                                        &cfg->software_numa_local_distance);

    case LLPS_YML_KEY_SOFTWARE_NUMA_REMOTE_DISTANCE:
        return llps_yml_apply_u64_field(value,
                                        0u,
                                        LLPS_SOFTWARE_NUMA_DISTANCE_MAX,
                                        &cfg->software_numa_remote_distance);

    case LLPS_YML_KEY_SOFTWARE_FAULT_INJECTION_MODE:
        st = llps_yml_parse_software_fault_injection_mode(value,
                                                          &parsed_u32);
        if (st == LLPS_YML_OK) {
            cfg->software_fault_injection_mode = parsed_u32;
        }
        return st;

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_evidence_key(
    const llps_yml_key_t key,
    const char * const value,
    llps_yml_config_t * const cfg,
    bool * const handled) {
    *handled = true;

    switch (key) {
    case LLPS_YML_KEY_EVIDENCE_MAC_ENABLED:
        return llps_yml_apply_u32_field(value,
                                        0u,
                                        1u,
                                        &cfg->evidence_mac_enabled);

    case LLPS_YML_KEY_EVIDENCE_MAC_KEY_PATH:
        return llps_yml_parse_key_path_text(value,
                                            cfg->evidence_mac_key_path,
                                            sizeof(cfg->evidence_mac_key_path));

    default:
        *handled = false;
        return LLPS_YML_OK;
    }
}

static llps_yml_status_t llps_yml_apply_key_value(const llps_yml_key_t key,
                                                  const char * const value,
                                                  llps_yml_config_t * const cfg) {
    bool handled = false;
    llps_yml_status_t st = LLPS_YML_OK;

    if ((value == NULL) || (cfg == NULL)) {
        return LLPS_YML_E_NULL;
    }

    st = llps_yml_apply_capacity_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_endpoint_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_session_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_audit_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_platform_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_domain_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_software_ecc_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_software_numa_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }
    st = llps_yml_apply_evidence_key(key, value, cfg, &handled);
    if ((st != LLPS_YML_OK) || handled) {
        return st;
    }

    return LLPS_YML_E_KEY;
}

static llps_yml_status_t llps_yml_parse_line(char * const line,
                                             llps_yml_config_t * const cfg,
                                             uint64_t * const present_mask_ref) {
    char *work = NULL;
    const char *key = NULL;
    char *value = NULL;
    char *colon = NULL;
    size_t i = 0u;
    size_t line_len = 0u;
    llps_yml_key_t parsed_key = LLPS_YML_KEY_MAX_CLIENTS;
    uint64_t key_bit = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    if ((line == NULL) || (cfg == NULL) || (present_mask_ref == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (!llps_yml_bounded_strlen(line, LLPS_YML_MAX_LINE_LEN + 1u, &line_len)) {
        return LLPS_YML_E_LINE_TOO_LONG;
    }

    llps_yml_strip_comment(line);

    work = llps_yml_trim_in_place(line);
    if (work == NULL) {
        return LLPS_YML_E_SYNTAX;
    }

    if (work[0] == '\0') {
        return LLPS_YML_OK;
    }

    if ((work[0] == '-') || (work[0] == '[') || (work[0] == '{')) {
        return LLPS_YML_E_SYNTAX;
    }

    colon = NULL;
    for (i = 0u; i < LLPS_YML_MAX_LINE_LEN; ++i) {
        if (work[i] == '\0') {
            break;
        }

        if (work[i] == ':') {
            if (colon != NULL) {
                return LLPS_YML_E_SYNTAX;
            }

            colon = &work[i];
        }
    }

    if (colon == NULL) {
        return LLPS_YML_E_SYNTAX;
    }

    *colon = '\0';

    key = llps_yml_trim_in_place(work);
    value = llps_yml_trim_in_place(&colon[1]);

    if ((key == NULL) || (value == NULL)) {
        return LLPS_YML_E_SYNTAX;
    }

    if ((key[0] == '\0') || (value[0] == '\0')) {
        return LLPS_YML_E_SYNTAX;
    }

    st = llps_yml_validate_key_syntax(key);
    if (st != LLPS_YML_OK) {
        return st;
    }

    st = llps_yml_unquote_value(&value);
    if (st != LLPS_YML_OK) {
        return st;
    }

    st = llps_yml_key_from_string(key, &parsed_key);
    if (st != LLPS_YML_OK) {
        return st;
    }

    key_bit = (uint64_t)(1ULL << (uint32_t)parsed_key);

    if (((*present_mask_ref) & key_bit) != 0u) {
        return LLPS_YML_E_DUPLICATE;
    }

    st = llps_yml_apply_key_value(parsed_key, value, cfg);
    if (st != LLPS_YML_OK) {
        return st;
    }

    *present_mask_ref |= key_bit;

    return LLPS_YML_OK;
}

/* -------------------------------------------------------------------------
 * File reader
 * ------------------------------------------------------------------------- */

static llps_yml_status_t llps_yml_close_fd(int * const fd_ref) {
    int fd = -1;

    if (fd_ref == NULL) {
        return LLPS_YML_E_NULL;
    }

    fd = *fd_ref;
    *fd_ref = -1;

    if (fd < 0) {
        return LLPS_YML_OK;
    }

    if (close(fd) != 0) {
        return LLPS_YML_E_CLOSE;
    }

    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_open_readonly(const char * const path,
                                                int * const out_fd) {
    size_t path_len = 0u;
    int fd = -1;

    if ((path == NULL) || (out_fd == NULL)) {
        return LLPS_YML_E_NULL;
    }

    *out_fd = -1;

    if (!llps_yml_bounded_strlen(path, LLPS_YML_MAX_PATH_LEN, &path_len)) {
        return LLPS_YML_E_RANGE;
    }

    if (path_len == 0u) {
        return LLPS_YML_E_RANGE;
    }

#ifdef O_CLOEXEC
    fd = open(path, O_RDONLY | O_CLOEXEC);
#else
    fd = open(path, O_RDONLY);
#endif

    if (fd < 0) {
        return LLPS_YML_E_OPEN;
    }

#ifndef O_CLOEXEC
    {
        int flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0) {
            (void)llps_yml_close_fd(&fd);
            return LLPS_YML_E_OPEN;
        }

        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
            (void)llps_yml_close_fd(&fd);
            return LLPS_YML_E_OPEN;
        }
    }
#endif

    *out_fd = fd;
    return LLPS_YML_OK;
}

static llps_yml_status_t llps_yml_commit_line(char * const line,
                                              const size_t line_len,
                                              const uint32_t line_no,
                                              llps_yml_config_t * const cfg,
                                              uint64_t * const present_mask_ref,
                                              uint32_t * const error_line_ref) {
    llps_yml_status_t st = LLPS_YML_OK;

    if ((line == NULL) || (cfg == NULL) || (present_mask_ref == NULL)) {
        return LLPS_YML_E_NULL;
    }

    if (line_no > LLPS_YML_MAX_LINES) {
        if (error_line_ref != NULL) {
            *error_line_ref = line_no;
        }
        return LLPS_YML_E_TOO_MANY_LINES;
    }

    if (line_len > LLPS_YML_MAX_LINE_LEN) {
        if (error_line_ref != NULL) {
            *error_line_ref = line_no;
        }
        return LLPS_YML_E_LINE_TOO_LONG;
    }

    line[line_len] = '\0';

    st = llps_yml_parse_line(line, cfg, present_mask_ref);
    if ((st != LLPS_YML_OK) && (error_line_ref != NULL)) {
        *error_line_ref = line_no;
    }

    return st;
}

static llps_yml_status_t llps_yml_load_config_internal(
    const char * const path,
    llps_yml_config_t * const out_cfg,
    uint32_t * const error_line_ref,
    const bool enforce_attestation_fingerprint) {
    int fd = -1;
    uint8_t read_buf[LLPS_YML_READ_CHUNK];
    char line[LLPS_YML_MAX_LINE_LEN + 1u];

    size_t line_len = 0u;
    uint32_t line_no = 1u;
    uint32_t total_bytes = 0u;
    uint64_t present_mask = 0u;

    bool pending_cr = false;
    bool saw_any_byte = false;

    llps_yml_config_t cfg;
    llps_yml_status_t st = LLPS_YML_OK;

    if (error_line_ref != NULL) {
        *error_line_ref = 0u;
    }

    if ((path == NULL) || (out_cfg == NULL)) {
        return LLPS_YML_E_NULL;
    }

    llps_yml_zero_config(&cfg);

    st = llps_yml_open_readonly(path, &fd);
    if (st != LLPS_YML_OK) {
        return st;
    }

    for (uint64_t read_cycle = 0u; read_cycle < UINT64_MAX; ++read_cycle) {
        ssize_t nread = 0;
        size_t i = 0u;

        nread = read(fd, read_buf, sizeof(read_buf));

        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }

            (void)llps_yml_close_fd(&fd);
            return LLPS_YML_E_READ;
        }

        if (nread == 0) {
            break;
        }

        for (i = 0u; i < (size_t)nread; ++i) {
            const unsigned char c = read_buf[i];

            saw_any_byte = true;

            if (total_bytes >= LLPS_YML_MAX_FILE_BYTES) {
                (void)llps_yml_close_fd(&fd);
                return LLPS_YML_E_TOO_LARGE;
            }
            ++total_bytes;

            if (pending_cr) {
                if (c != '\n') {
                    (void)llps_yml_close_fd(&fd);
                    if (error_line_ref != NULL) {
                        *error_line_ref = line_no;
                    }
                    return LLPS_YML_E_SYNTAX;
                }

                st = llps_yml_commit_line(line,
                                          line_len,
                                          line_no,
                                          &cfg,
                                          &present_mask,
                                          error_line_ref);
                if (st != LLPS_YML_OK) {
                    (void)llps_yml_close_fd(&fd);
                    return st;
                }

                ++line_no;
                line_len = 0u;
                pending_cr = false;
                continue;
            }

            if (c == '\r') {
                pending_cr = true;
                continue;
            }

            if (c == '\n') {
                st = llps_yml_commit_line(line,
                                          line_len,
                                          line_no,
                                          &cfg,
                                          &present_mask,
                                          error_line_ref);
                if (st != LLPS_YML_OK) {
                    (void)llps_yml_close_fd(&fd);
                    return st;
                }

                ++line_no;
                line_len = 0u;
                continue;
            }

            if ((c == '\0') || !llps_yml_is_allowed_text_byte(c)) {
                (void)llps_yml_close_fd(&fd);
                if (error_line_ref != NULL) {
                    *error_line_ref = line_no;
                }
                return LLPS_YML_E_SYNTAX;
            }

            if (line_len >= LLPS_YML_MAX_LINE_LEN) {
                (void)llps_yml_close_fd(&fd);
                if (error_line_ref != NULL) {
                    *error_line_ref = line_no;
                }
                return LLPS_YML_E_LINE_TOO_LONG;
            }

            line[line_len] = (char)c;
            ++line_len;
        }
    }

    if (pending_cr) {
        st = llps_yml_commit_line(line,
                                  line_len,
                                  line_no,
                                  &cfg,
                                  &present_mask,
                                  error_line_ref);
        if (st != LLPS_YML_OK) {
            (void)llps_yml_close_fd(&fd);
            return st;
        }

        ++line_no;
        line_len = 0u;
    }

    if (line_len > 0u) {
        st = llps_yml_commit_line(line,
                                  line_len,
                                  line_no,
                                  &cfg,
                                  &present_mask,
                                  error_line_ref);
        if (st != LLPS_YML_OK) {
            (void)llps_yml_close_fd(&fd);
            return st;
        }
    }

    st = llps_yml_close_fd(&fd);
    if (st != LLPS_YML_OK) {
        return st;
    }

    if (!saw_any_byte) {
        return LLPS_YML_E_REQUIRED;
    }

    if ((present_mask & LLPS_YML_REQUIRED_MASK) != LLPS_YML_REQUIRED_MASK) {
        return LLPS_YML_E_REQUIRED;
    }

    st = llps_yml_validate_config(&cfg, enforce_attestation_fingerprint);
    if (st != LLPS_YML_OK) {
        return st;
    }

    *out_cfg = cfg;
    return LLPS_YML_OK;
}

llps_yml_status_t llps_yml_load_config_ex(const char * const path,
                                          llps_yml_config_t * const out_cfg,
                                          uint32_t * const error_line_ref) {
    return llps_yml_load_config_internal(path,
                                         out_cfg,
                                         error_line_ref,
                                         true);
}

llps_yml_status_t llps_yml_load_config_for_attestation_ex(
    const char * const path,
    llps_yml_config_t * const out_cfg,
    uint32_t * const error_line_ref) {
    return llps_yml_load_config_internal(path,
                                         out_cfg,
                                         error_line_ref,
                                         false);
}

const char *llps_yml_status_string(const llps_yml_status_t st) {
    const char *msg = "unknown";

    switch (st) {
    case LLPS_YML_OK:
        msg = "ok";
        break;
    case LLPS_YML_E_NULL:
        msg = "null argument";
        break;
    case LLPS_YML_E_OPEN:
        msg = "open failed";
        break;
    case LLPS_YML_E_READ:
        msg = "read failed";
        break;
    case LLPS_YML_E_CLOSE:
        msg = "close failed";
        break;
    case LLPS_YML_E_TOO_LARGE:
        msg = "file too large";
        break;
    case LLPS_YML_E_TOO_MANY_LINES:
        msg = "too many lines";
        break;
    case LLPS_YML_E_LINE_TOO_LONG:
        msg = "line too long";
        break;
    case LLPS_YML_E_SYNTAX:
        msg = "syntax error";
        break;
    case LLPS_YML_E_KEY:
        msg = "unknown key";
        break;
    case LLPS_YML_E_DUPLICATE:
        msg = "duplicate key";
        break;
    case LLPS_YML_E_REQUIRED:
        msg = "required key missing";
        break;
    case LLPS_YML_E_RANGE:
        msg = "value out of range";
        break;
    case LLPS_YML_E_STRING:
        msg = "string too long or unterminated";
        break;
    default:
        msg = "unknown";
        break;
    }

    return msg;
}
