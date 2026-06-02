/**
 * @file src/config/llps_config_validate.c
 * @brief Configuration parsing and validation for LLPS runtime options.
 *
 * @details
 * Configuration code owns text input normalization before values cross into
 * the runtime state.
 */

#include "llps_config_validate.h"

#include "llps_config.h"
#include "llps_domain.h"
#include "llps_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool llps_config_bounded_strlen(const char * const text,
                                       const size_t cap,
                                       size_t * const out_len) {
    if ((text == NULL) || (cap == 0u) || (out_len == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < cap; ++i) {
        if (text[i] == '\0') {
            *out_len = i;
            return true;
        }
    }

    return false;
}

static bool llps_config_text_has_nul(const char * const text,
                                     const size_t cap) {
    size_t len = 0u;

    return llps_config_bounded_strlen(text, cap, &len);
}

static bool llps_config_path_has_pxf_extension(const char * const text,
                                               const size_t cap) {
    static const char suffix[] = ".pxf";
    const size_t suffix_len = sizeof(suffix) - 1u;
    size_t len = 0u;

    if (!llps_config_bounded_strlen(text, cap, &len)) {
        return false;
    }

    if (len <= suffix_len) {
        return false;
    }

    return memcmp(&text[len - suffix_len], suffix, suffix_len) == 0;
}

static bool llps_config_path_has_parent_component(const char * const text,
                                                  const size_t len) {
    size_t start = 0u;

    if (text == NULL) {
        return true;
    }

    for (size_t i = 0u; i <= len; ++i) {
        if ((i == len) || (text[i] == '/')) {
            const size_t component_len = i - start;

            if ((component_len == 2u) &&
                (text[start] == '.') &&
                (text[start + 1u] == '.')) {
                return true;
            }

            start = i + 1u;
        }
    }

    return false;
}

static bool llps_config_path_is_safe(const char * const text,
                                     const size_t cap,
                                     const bool allow_empty) {
    size_t len = 0u;

    if (!llps_config_bounded_strlen(text, cap, &len)) {
        return false;
    }

    if (len == 0u) {
        return allow_empty;
    }

    if ((text[0] != '/') || (text[len - 1u] == '/') ||
        llps_config_path_has_parent_component(text, len)) {
        return false;
    }

    for (size_t i = 0u; i < len; ++i) {
        const char c = text[i];
        const bool alnum =
            ((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'Z')) ||
            ((c >= 'a') && (c <= 'z'));

        if (!alnum &&
            (c != '/') &&
            (c != '.') &&
            (c != '_') &&
            (c != '-')) {
            return false;
        }

        if ((c == '/') && (i > 0u) && (text[i - 1u] == '/')) {
            return false;
        }
    }

    return true;
}

static bool llps_platform_attestation_config_is_valid(
    const llps_yml_config_t * const cfg) {
    llps_status_t status = LLPS_OK;
    uint32_t expected_fingerprint = 0u;

    if (cfg == NULL) {
        return false;
    }

    if ((cfg->platform_safety_flags == 0u) &&
        (cfg->platform_safety_evidence_id == 0u) &&
        (cfg->platform_attestation_fingerprint == 0u)) {
        return true;
    }

    status = llps_compute_platform_attestation_fingerprint(
        cfg->platform_safety_flags,
        cfg->platform_safety_evidence_id,
        cfg->platform_physical_memory_domains,
        cfg->platform_hardware_tmr_domains,
        cfg->platform_hardware_tmr_voter_domain,
        &expected_fingerprint);
    if (status != LLPS_OK) {
        return false;
    }

    if (cfg->platform_attestation_fingerprint == 0u) {
        return cfg->require_readiness == 0u;
    }

    return cfg->platform_attestation_fingerprint == expected_fingerprint;
}

static bool llps_runtime_cfg_core_limits_are_valid(
    const llps_yml_config_t * const cfg) {
    return (cfg->max_clients != 0u) &&
           (cfg->max_clients <= LLPS_MAX_CLIENTS) &&
           (cfg->buffer_size != 0u) &&
           (cfg->buffer_size <= LLPS_BUFFER_SIZE) &&
           (cfg->accept_batch_max != 0u) &&
           (cfg->accept_batch_max <= LLPS_ACCEPT_BATCH_MAX) &&
           (cfg->accept_batch_max <= cfg->max_clients) &&
           (cfg->listen_backlog != 0u) &&
           (cfg->listen_backlog <= LLPS_LISTEN_BACKLOG) &&
           (cfg->listen_backlog >= cfg->accept_batch_max) &&
           ((cfg->session_idle_timeout_ms == 0u) ||
            ((cfg->session_idle_timeout_ms >=
              LLPS_SESSION_IDLE_TIMEOUT_MS_MIN) &&
             (cfg->session_idle_timeout_ms <=
              LLPS_SESSION_IDLE_TIMEOUT_MS_MAX))) &&
           (cfg->max_sessions_per_client_ip <= cfg->max_clients) &&
           (cfg->max_new_sessions_per_client_ip_per_window <=
            LLPS_CLIENT_IP_RATE_LIMIT_MAX) &&
           (cfg->client_ip_rate_window_ms >=
            LLPS_CLIENT_IP_RATE_WINDOW_MS_MIN) &&
           (cfg->client_ip_rate_window_ms <=
            LLPS_CLIENT_IP_RATE_WINDOW_MS_MAX) &&
           ((cfg->client_preface_timeout_ms == 0u) ||
            ((cfg->client_preface_timeout_ms >=
              LLPS_CLIENT_PREFACE_TIMEOUT_MS_MIN) &&
             (cfg->client_preface_timeout_ms <=
              LLPS_CLIENT_PREFACE_TIMEOUT_MS_MAX))) &&
           (cfg->protocol_handshake_gate_enabled <= 1u) &&
           ((cfg->protocol_handshake_gate_enabled == 0u) ||
            (cfg->client_preface_timeout_ms != 0u)) &&
           (cfg->listen_port != 0u) &&
           (cfg->target_port != 0u);
}

static bool llps_runtime_cfg_paths_are_valid(
    const llps_yml_config_t * const cfg) {
    return (cfg->payload_ecc_enabled <= 1u) &&
           (cfg->ip_audit_enabled <= 1u) &&
           ((cfg->ip_audit_enabled == 0u) ||
            llps_config_path_has_pxf_extension(cfg->ip_audit_path,
                                               sizeof(cfg->ip_audit_path))) &&
           (cfg->audit_mac_enabled <= 1u) &&
           ((cfg->audit_mac_enabled == 0u) ||
            ((cfg->ip_audit_enabled != 0u) &&
             llps_config_path_is_safe(cfg->audit_mac_key_path,
                                      sizeof(cfg->audit_mac_key_path),
                                      false))) &&
           ((cfg->audit_mac_enabled != 0u) ||
            llps_config_path_is_safe(cfg->audit_mac_key_path,
                                     sizeof(cfg->audit_mac_key_path),
                                     true)) &&
           (cfg->evidence_mac_enabled <= 1u) &&
           ((cfg->evidence_mac_enabled == 0u) ||
            llps_config_path_is_safe(cfg->evidence_mac_key_path,
                                     sizeof(cfg->evidence_mac_key_path),
                                     false)) &&
           ((cfg->evidence_mac_enabled != 0u) ||
            llps_config_path_is_safe(cfg->evidence_mac_key_path,
                                     sizeof(cfg->evidence_mac_key_path),
                                     true));
}

static bool llps_runtime_cfg_platform_basics_are_valid(
    const llps_yml_config_t * const cfg) {
    return (cfg->require_readiness <= 1u) &&
           (cfg->platform_evidence_mode <=
            LLPS_PLATFORM_EVIDENCE_MODE_HYBRID) &&
           (cfg->software_ecc_enabled <= 1u) &&
           (cfg->software_numa_enabled <= 1u) &&
           (cfg->software_fault_injection_mode <=
            LLPS_SOFTWARE_FAULT_INJECTION_MAX) &&
           ((cfg->platform_safety_flags & ~LLPS_PLATFORM_EVIDENCE_REQUIRED) ==
            0u) &&
           llps_config_text_has_nul(cfg->listen_host, sizeof(cfg->listen_host)) &&
           llps_config_text_has_nul(cfg->target_ip, sizeof(cfg->target_ip));
}

static bool llps_runtime_cfg_software_ecc_is_valid(
    const llps_yml_config_t * const cfg) {
    if (cfg->software_ecc_enabled == 0u) {
        return (cfg->software_ecc_controller_count == 0u) &&
               (cfg->software_ecc_dimm_count == 0u) &&
               (cfg->software_ecc_scrub_rate == 0u) &&
               (cfg->software_ecc_controller_corrected_error_count == 0u) &&
               (cfg->software_ecc_controller_uncorrected_error_count == 0u) &&
               (cfg->software_ecc_dimm_corrected_error_count == 0u) &&
               (cfg->software_ecc_dimm_uncorrected_error_count == 0u);
    }
    return (cfg->software_ecc_controller_count != 0u) &&
           (cfg->software_ecc_controller_count <=
            LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) &&
           (cfg->software_ecc_dimm_count != 0u) &&
           (cfg->software_ecc_dimm_count <= LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX) &&
           (cfg->software_ecc_controller_count <=
            cfg->software_ecc_dimm_count) &&
           (cfg->software_ecc_scrub_rate != 0u) &&
           (cfg->software_ecc_scrub_rate <= LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX);
}

static bool llps_runtime_cfg_software_numa_is_valid(
    const llps_yml_config_t * const cfg) {
    if (cfg->software_numa_enabled == 0u) {
        return (cfg->software_numa_memtotal_kib == 0u) &&
               (cfg->software_numa_local_distance == 0u) &&
               (cfg->software_numa_remote_distance == 0u);
    }
    return (cfg->software_numa_memtotal_kib != 0u) &&
           (cfg->software_numa_memtotal_kib <=
            LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX) &&
           ((cfg->software_numa_local_distance == 0u) ==
            (cfg->software_numa_remote_distance == 0u)) &&
           (cfg->software_numa_local_distance <=
            LLPS_SOFTWARE_NUMA_DISTANCE_MAX) &&
           (cfg->software_numa_remote_distance <=
            LLPS_SOFTWARE_NUMA_DISTANCE_MAX) &&
           ((cfg->software_numa_local_distance == 0u) ||
            (cfg->software_numa_remote_distance >
             cfg->software_numa_local_distance)) &&
           ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u);
}

static bool llps_runtime_cfg_platform_policy_is_valid(
    const llps_yml_config_t * const cfg) {
    const bool synthetic =
        cfg->platform_evidence_mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC;
    const bool synthetic_ecc_required =
        ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u) ||
        ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u);

    return ((cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL) ||
            ((cfg->software_ecc_enabled == 0u) &&
             (cfg->software_numa_enabled == 0u))) &&
           ((cfg->require_readiness == 0u) ||
            (cfg->software_ecc_enabled == 0u) ||
            (cfg->payload_ecc_enabled != 0u)) &&
           (!synthetic || !synthetic_ecc_required ||
            (cfg->software_ecc_enabled != 0u)) &&
           (!synthetic ||
            ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) ||
            (cfg->software_numa_enabled != 0u)) &&
           ((cfg->require_readiness == 0u) ||
            ((cfg->platform_safety_evidence_id != 0u) &&
             (cfg->platform_attestation_fingerprint != 0u) &&
             ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_REQUIRED) ==
              LLPS_PLATFORM_EVIDENCE_REQUIRED)));
}

static bool llps_runtime_cfg_domain_bindings_are_valid(
    const llps_yml_config_t * const cfg) {
    return (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) !=
             0u) ||
            llps_domain_ids_are_zero(cfg->platform_physical_memory_domains)) &&
           (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) !=
             0u) ||
            llps_domain_ids_are_zero(cfg->platform_hardware_tmr_domains)) &&
           (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) ==
             0u) ||
            llps_domain_ids_are_distinct(cfg->platform_physical_memory_domains)) &&
           (((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) ==
             0u) ||
            llps_domain_ids_are_distinct(cfg->platform_hardware_tmr_domains)) &&
           (((cfg->platform_safety_flags &
              LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) !=
             LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) ||
            llps_domain_id_sets_are_disjoint(cfg->platform_physical_memory_domains,
                                             cfg->platform_hardware_tmr_domains));
}

bool llps_runtime_cfg_values_are_valid(const llps_yml_config_t * const cfg) {
    if ((cfg == NULL) ||
        !llps_runtime_cfg_core_limits_are_valid(cfg) ||
        !llps_runtime_cfg_paths_are_valid(cfg) ||
        !llps_runtime_cfg_platform_basics_are_valid(cfg) ||
        !llps_runtime_cfg_software_ecc_is_valid(cfg) ||
        !llps_runtime_cfg_software_numa_is_valid(cfg) ||
        !llps_runtime_cfg_platform_policy_is_valid(cfg) ||
        !llps_runtime_cfg_domain_bindings_are_valid(cfg) ||
        !llps_platform_attestation_config_is_valid(cfg)) {
        return false;
    }

    return (cfg->listen_port != cfg->target_port) ||
           (strcmp(cfg->listen_host, cfg->target_ip) != 0);
}
