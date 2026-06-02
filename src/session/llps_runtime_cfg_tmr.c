/**
 * @file src/session/llps_runtime_cfg_tmr.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_runtime_cfg_tmr.h"

#include "llps_config_validate.h"
#include "llps_crc.h"
#include "llps_internal.h"
#include "llps_safety_counters.h"
#include "llps_tmr_vote.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK0)
LLPS_USED
llps_runtime_cfg_bank_t g_runtime_cfg_bank0;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK1)
LLPS_USED
llps_runtime_cfg_bank_t g_runtime_cfg_bank1;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK2)
LLPS_USED
llps_runtime_cfg_bank_t g_runtime_cfg_bank2;

static llps_runtime_cfg_bank_t *llps_runtime_cfg_bank_ref(
    const uint32_t bank_id) {
    static llps_runtime_cfg_bank_t * const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_runtime_cfg_bank0,
        &g_runtime_cfg_bank1,
        &g_runtime_cfg_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static const llps_runtime_cfg_bank_t *llps_runtime_cfg_bank_cref(
    const uint32_t bank_id) {
    static const llps_runtime_cfg_bank_t *
        const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_runtime_cfg_bank0,
        &g_runtime_cfg_bank1,
        &g_runtime_cfg_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static uint32_t llps_runtime_cfg_bank_magic_for_bank(const uint32_t bank_id) {
    return LLPS_RUNTIME_CFG_BANK_MAGIC ^ (0x11001100u * (bank_id + 1u));
}

static uint32_t llps_runtime_cfg_crc_text(uint32_t crc,
                                          const char * const text,
                                          const size_t len) {
    for (size_t i = 0u; i < len; ++i) {
        crc = llps_crc32_update_byte(crc, (uint8_t)text[i]);
    }
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_header(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->magic_start);
    crc = llps_crc32_update_u32(crc, bank->bank_id);
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_network(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->cfg.max_clients);
    crc = llps_crc32_update_u32(crc, bank->cfg.buffer_size);
    crc = llps_crc32_update_u32(crc, bank->cfg.payload_ecc_enabled);
    crc = llps_runtime_cfg_crc_text(crc,
                                    bank->cfg.listen_host,
                                    sizeof(bank->cfg.listen_host));
    crc = llps_crc32_update_u32(crc, bank->cfg.listen_port);
    crc = llps_runtime_cfg_crc_text(crc,
                                    bank->cfg.target_ip,
                                    sizeof(bank->cfg.target_ip));
    crc = llps_crc32_update_u32(crc, bank->cfg.target_port);
    crc = llps_crc32_update_u32(crc, bank->cfg.listen_backlog);
    crc = llps_crc32_update_u32(crc, bank->cfg.accept_batch_max);
    crc = llps_crc32_update_u32(crc, bank->cfg.session_idle_timeout_ms);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.max_sessions_per_client_ip);
    crc = llps_crc32_update_u32(
        crc,
        bank->cfg.max_new_sessions_per_client_ip_per_window);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.client_ip_rate_window_ms);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.client_preface_timeout_ms);
    crc = llps_crc32_update_u32(
        crc,
        bank->cfg.protocol_handshake_gate_enabled);
    crc = llps_crc32_update_u32(crc, bank->cfg.ip_audit_enabled);
    crc = llps_runtime_cfg_crc_text(crc,
                                    bank->cfg.ip_audit_path,
                                    sizeof(bank->cfg.ip_audit_path));
    crc = llps_crc32_update_u32(crc, bank->cfg.audit_mac_enabled);
    return llps_runtime_cfg_crc_text(crc,
                                     bank->cfg.audit_mac_key_path,
                                     sizeof(bank->cfg.audit_mac_key_path));
}

static uint32_t llps_runtime_cfg_bank_crc_platform(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->cfg.require_readiness);
    crc = llps_crc32_update_u32(crc, bank->cfg.platform_safety_flags);
    crc = llps_crc32_update_u64(crc, bank->cfg.platform_safety_evidence_id);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.platform_attestation_fingerprint);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.platform_observation_digest);
    crc = llps_crc32_update_u32(crc, bank->cfg.platform_evidence_mode);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(
            crc,
            bank->cfg.platform_physical_memory_domains[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(
            crc,
            bank->cfg.platform_hardware_tmr_domains[i]);
    }
    crc = llps_crc32_update_u32(
        crc,
        bank->cfg.platform_hardware_tmr_voter_domain);
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_software(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->cfg.software_ecc_enabled);
    crc = llps_crc32_update_u32(crc,
                                bank->cfg.software_ecc_controller_count);
    crc = llps_crc32_update_u32(crc, bank->cfg.software_ecc_dimm_count);
    crc = llps_crc32_update_u64(crc, bank->cfg.software_ecc_scrub_rate);
    crc = llps_crc32_update_u64(
        crc,
        bank->cfg.software_ecc_controller_corrected_error_count);
    crc = llps_crc32_update_u64(
        crc,
        bank->cfg.software_ecc_controller_uncorrected_error_count);
    crc = llps_crc32_update_u64(
        crc,
        bank->cfg.software_ecc_dimm_corrected_error_count);
    crc = llps_crc32_update_u64(
        crc,
        bank->cfg.software_ecc_dimm_uncorrected_error_count);
    crc = llps_crc32_update_u32(crc, bank->cfg.software_numa_enabled);
    crc = llps_crc32_update_u64(crc, bank->cfg.software_numa_memtotal_kib);
    crc = llps_crc32_update_u64(crc, bank->cfg.software_numa_local_distance);
    crc = llps_crc32_update_u64(crc, bank->cfg.software_numa_remote_distance);
    crc = llps_crc32_update_u32(crc, bank->cfg.software_fault_injection_mode);
    crc = llps_crc32_update_u32(crc, bank->cfg.evidence_mac_enabled);
    return llps_runtime_cfg_crc_text(crc,
                                     bank->cfg.evidence_mac_key_path,
                                     sizeof(bank->cfg.evidence_mac_key_path));
}

static uint32_t llps_runtime_cfg_bank_crc_runtime_inverse(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->max_clients_inverse);
    crc = llps_crc32_update_u32(crc, bank->buffer_size_inverse);
    crc = llps_crc32_update_u32(crc, bank->payload_ecc_enabled_inverse);
    crc = llps_crc32_update_u32(crc, bank->listen_port_inverse);
    crc = llps_crc32_update_u32(crc, bank->target_port_inverse);
    crc = llps_crc32_update_u32(crc, bank->listen_backlog_inverse);
    crc = llps_crc32_update_u32(crc, bank->accept_batch_max_inverse);
    crc = llps_crc32_update_u32(crc,
                                bank->session_idle_timeout_ms_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->max_sessions_per_client_ip_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->max_new_sessions_per_client_ip_per_window_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->client_ip_rate_window_ms_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->client_preface_timeout_ms_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->protocol_handshake_gate_enabled_inverse);
    crc = llps_crc32_update_u32(crc, bank->ip_audit_enabled_inverse);
    crc = llps_crc32_update_u32(crc, bank->audit_mac_enabled_inverse);
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_platform_inverse(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->require_readiness_inverse);
    crc = llps_crc32_update_u32(crc, bank->platform_safety_flags_inverse);
    crc = llps_crc32_update_u64(crc,
                                bank->platform_safety_evidence_id_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->platform_attestation_fingerprint_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->platform_observation_digest_inverse);
    crc = llps_crc32_update_u32(crc,
                                bank->platform_evidence_mode_inverse);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(
            crc,
            bank->platform_physical_memory_domains_inverse[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(
            crc,
            bank->platform_hardware_tmr_domains_inverse[i]);
    }
    crc = llps_crc32_update_u32(
        crc,
        bank->platform_hardware_tmr_voter_domain_inverse);
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_software_inverse(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_crc32_update_u32(crc, bank->software_ecc_enabled_inverse);
    crc = llps_crc32_update_u32(
        crc,
        bank->software_ecc_controller_count_inverse);
    crc = llps_crc32_update_u32(crc, bank->software_ecc_dimm_count_inverse);
    crc = llps_crc32_update_u64(crc, bank->software_ecc_scrub_rate_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_ecc_controller_corrected_error_count_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_ecc_controller_uncorrected_error_count_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_ecc_dimm_corrected_error_count_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_ecc_dimm_uncorrected_error_count_inverse);
    crc = llps_crc32_update_u32(crc, bank->software_numa_enabled_inverse);
    crc = llps_crc32_update_u64(crc, bank->software_numa_memtotal_kib_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_numa_local_distance_inverse);
    crc = llps_crc32_update_u64(
        crc,
        bank->software_numa_remote_distance_inverse);
    crc = llps_crc32_update_u32(crc,
                                bank->software_fault_injection_mode_inverse);
    crc = llps_crc32_update_u32(crc, bank->evidence_mac_enabled_inverse);
    return crc;
}

static uint32_t llps_runtime_cfg_bank_crc_text_inverse(
    uint32_t crc,
    const llps_runtime_cfg_bank_t * const bank) {
    crc = llps_runtime_cfg_crc_text(
        crc,
        (const char *)bank->listen_host_inverse,
        sizeof(bank->listen_host_inverse));
    crc = llps_runtime_cfg_crc_text(
        crc,
        (const char *)bank->target_ip_inverse,
        sizeof(bank->target_ip_inverse));
    crc = llps_runtime_cfg_crc_text(
        crc,
        (const char *)bank->ip_audit_path_inverse,
        sizeof(bank->ip_audit_path_inverse));
    crc = llps_runtime_cfg_crc_text(
        crc,
        (const char *)bank->audit_mac_key_path_inverse,
        sizeof(bank->audit_mac_key_path_inverse));
    return llps_runtime_cfg_crc_text(
        crc,
        (const char *)bank->evidence_mac_key_path_inverse,
        sizeof(bank->evidence_mac_key_path_inverse));
}

uint32_t llps_runtime_cfg_bank_compute_crc(
    const llps_runtime_cfg_bank_t * const bank) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (bank == NULL) {
        return 0u;
    }

    crc = llps_runtime_cfg_bank_crc_header(crc, bank);
    crc = llps_runtime_cfg_bank_crc_network(crc, bank);
    crc = llps_runtime_cfg_bank_crc_platform(crc, bank);
    crc = llps_runtime_cfg_bank_crc_software(crc, bank);
    crc = llps_runtime_cfg_bank_crc_runtime_inverse(crc, bank);
    crc = llps_runtime_cfg_bank_crc_platform_inverse(crc, bank);
    crc = llps_runtime_cfg_bank_crc_software_inverse(crc, bank);
    crc = llps_runtime_cfg_bank_crc_text_inverse(crc, bank);
    crc = llps_crc32_update_u32(crc, bank->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static bool llps_runtime_cfg_runtime_equal(
    const llps_yml_config_t * const lhs,
    const llps_yml_config_t * const rhs) {
    return (lhs->max_clients == rhs->max_clients) &&
           (lhs->buffer_size == rhs->buffer_size) &&
           (lhs->payload_ecc_enabled == rhs->payload_ecc_enabled) &&
           (lhs->listen_port == rhs->listen_port) &&
           (lhs->target_port == rhs->target_port) &&
           (lhs->listen_backlog == rhs->listen_backlog) &&
           (lhs->accept_batch_max == rhs->accept_batch_max) &&
           (lhs->session_idle_timeout_ms ==
            rhs->session_idle_timeout_ms) &&
           (lhs->max_sessions_per_client_ip ==
            rhs->max_sessions_per_client_ip) &&
           (lhs->max_new_sessions_per_client_ip_per_window ==
            rhs->max_new_sessions_per_client_ip_per_window) &&
           (lhs->client_ip_rate_window_ms ==
            rhs->client_ip_rate_window_ms) &&
           (lhs->client_preface_timeout_ms ==
            rhs->client_preface_timeout_ms) &&
           (lhs->protocol_handshake_gate_enabled ==
            rhs->protocol_handshake_gate_enabled) &&
           (lhs->ip_audit_enabled == rhs->ip_audit_enabled) &&
           (lhs->audit_mac_enabled == rhs->audit_mac_enabled);
}

static bool llps_runtime_cfg_platform_equal(
    const llps_yml_config_t * const lhs,
    const llps_yml_config_t * const rhs) {
    return
           (lhs->require_readiness == rhs->require_readiness) &&
           (lhs->platform_safety_flags == rhs->platform_safety_flags) &&
           (lhs->platform_safety_evidence_id ==
            rhs->platform_safety_evidence_id) &&
           (lhs->platform_attestation_fingerprint ==
            rhs->platform_attestation_fingerprint) &&
           (lhs->platform_observation_digest ==
            rhs->platform_observation_digest) &&
           (lhs->platform_evidence_mode ==
            rhs->platform_evidence_mode) &&
           (lhs->platform_hardware_tmr_voter_domain ==
            rhs->platform_hardware_tmr_voter_domain);
}

static bool llps_runtime_cfg_software_equal(
    const llps_yml_config_t * const lhs,
    const llps_yml_config_t * const rhs) {
    return
           (lhs->software_ecc_enabled == rhs->software_ecc_enabled) &&
           (lhs->software_ecc_controller_count ==
            rhs->software_ecc_controller_count) &&
           (lhs->software_ecc_dimm_count ==
            rhs->software_ecc_dimm_count) &&
           (lhs->software_ecc_scrub_rate ==
            rhs->software_ecc_scrub_rate) &&
           (lhs->software_ecc_controller_corrected_error_count ==
            rhs->software_ecc_controller_corrected_error_count) &&
           (lhs->software_ecc_controller_uncorrected_error_count ==
            rhs->software_ecc_controller_uncorrected_error_count) &&
           (lhs->software_ecc_dimm_corrected_error_count ==
            rhs->software_ecc_dimm_corrected_error_count) &&
           (lhs->software_ecc_dimm_uncorrected_error_count ==
            rhs->software_ecc_dimm_uncorrected_error_count) &&
           (lhs->software_numa_enabled == rhs->software_numa_enabled) &&
           (lhs->software_numa_memtotal_kib ==
            rhs->software_numa_memtotal_kib) &&
           (lhs->software_numa_local_distance ==
            rhs->software_numa_local_distance) &&
           (lhs->software_numa_remote_distance ==
            rhs->software_numa_remote_distance) &&
           (lhs->software_fault_injection_mode ==
            rhs->software_fault_injection_mode) &&
           (lhs->evidence_mac_enabled == rhs->evidence_mac_enabled);
}

static bool llps_runtime_cfg_arrays_equal(
    const llps_yml_config_t * const lhs,
    const llps_yml_config_t * const rhs) {
    return
           (memcmp(lhs->platform_physical_memory_domains,
                   rhs->platform_physical_memory_domains,
                   sizeof(lhs->platform_physical_memory_domains)) == 0) &&
           (memcmp(lhs->platform_hardware_tmr_domains,
                   rhs->platform_hardware_tmr_domains,
                   sizeof(lhs->platform_hardware_tmr_domains)) == 0) &&
           (memcmp(lhs->listen_host,
                   rhs->listen_host,
                   sizeof(lhs->listen_host)) == 0) &&
           (memcmp(lhs->target_ip,
                   rhs->target_ip,
                   sizeof(lhs->target_ip)) == 0) &&
           (memcmp(lhs->ip_audit_path,
                   rhs->ip_audit_path,
                   sizeof(lhs->ip_audit_path)) == 0) &&
           (memcmp(lhs->audit_mac_key_path,
                   rhs->audit_mac_key_path,
                   sizeof(lhs->audit_mac_key_path)) == 0) &&
           (memcmp(lhs->evidence_mac_key_path,
                   rhs->evidence_mac_key_path,
                   sizeof(lhs->evidence_mac_key_path)) == 0);
}

bool llps_runtime_cfg_equal(const llps_yml_config_t * const lhs,
                            const llps_yml_config_t * const rhs) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    return llps_runtime_cfg_runtime_equal(lhs, rhs) &&
           llps_runtime_cfg_platform_equal(lhs, rhs) &&
           llps_runtime_cfg_software_equal(lhs, rhs) &&
           llps_runtime_cfg_arrays_equal(lhs, rhs);
}

static bool llps_runtime_cfg_bank_runtime_inverse_is_invalid(
    const llps_runtime_cfg_bank_t * const bank) {
    return (bank->max_clients_inverse != ~bank->cfg.max_clients) ||
           (bank->buffer_size_inverse != ~bank->cfg.buffer_size) ||
           (bank->payload_ecc_enabled_inverse !=
            ~bank->cfg.payload_ecc_enabled) ||
           (bank->listen_port_inverse != ~((uint32_t)bank->cfg.listen_port)) ||
           (bank->target_port_inverse != ~((uint32_t)bank->cfg.target_port)) ||
           (bank->listen_backlog_inverse != ~bank->cfg.listen_backlog) ||
           (bank->accept_batch_max_inverse != ~bank->cfg.accept_batch_max) ||
           (bank->session_idle_timeout_ms_inverse !=
            ~bank->cfg.session_idle_timeout_ms) ||
           (bank->max_sessions_per_client_ip_inverse !=
            ~bank->cfg.max_sessions_per_client_ip) ||
           (bank->max_new_sessions_per_client_ip_per_window_inverse !=
            ~bank->cfg.max_new_sessions_per_client_ip_per_window) ||
           (bank->client_ip_rate_window_ms_inverse !=
            ~bank->cfg.client_ip_rate_window_ms) ||
           (bank->client_preface_timeout_ms_inverse !=
            ~bank->cfg.client_preface_timeout_ms) ||
           (bank->protocol_handshake_gate_enabled_inverse !=
            ~bank->cfg.protocol_handshake_gate_enabled) ||
           (bank->ip_audit_enabled_inverse != ~bank->cfg.ip_audit_enabled) ||
           (bank->audit_mac_enabled_inverse != ~bank->cfg.audit_mac_enabled);
}

static bool llps_runtime_cfg_bank_platform_inverse_is_invalid(
    const llps_runtime_cfg_bank_t * const bank) {
    return (bank->require_readiness_inverse !=
            ~bank->cfg.require_readiness) ||
           (bank->platform_safety_flags_inverse !=
            ~bank->cfg.platform_safety_flags) ||
           (bank->platform_safety_evidence_id_inverse !=
            ~bank->cfg.platform_safety_evidence_id) ||
           (bank->platform_attestation_fingerprint_inverse !=
            ~bank->cfg.platform_attestation_fingerprint) ||
           (bank->platform_observation_digest_inverse !=
            ~bank->cfg.platform_observation_digest) ||
           (bank->platform_evidence_mode_inverse !=
            ~bank->cfg.platform_evidence_mode) ||
           (bank->platform_hardware_tmr_voter_domain_inverse !=
            ~bank->cfg.platform_hardware_tmr_voter_domain);
}

static bool llps_runtime_cfg_bank_software_inverse_is_invalid(
    const llps_runtime_cfg_bank_t * const bank) {
    return (bank->software_ecc_enabled_inverse !=
            ~bank->cfg.software_ecc_enabled) ||
           (bank->software_ecc_controller_count_inverse !=
            ~bank->cfg.software_ecc_controller_count) ||
           (bank->software_ecc_dimm_count_inverse !=
            ~bank->cfg.software_ecc_dimm_count) ||
           (bank->software_ecc_scrub_rate_inverse !=
            ~bank->cfg.software_ecc_scrub_rate) ||
           (bank->software_ecc_controller_corrected_error_count_inverse !=
            ~bank->cfg.software_ecc_controller_corrected_error_count) ||
           (bank->software_ecc_controller_uncorrected_error_count_inverse !=
            ~bank->cfg.software_ecc_controller_uncorrected_error_count) ||
           (bank->software_ecc_dimm_corrected_error_count_inverse !=
            ~bank->cfg.software_ecc_dimm_corrected_error_count) ||
           (bank->software_ecc_dimm_uncorrected_error_count_inverse !=
            ~bank->cfg.software_ecc_dimm_uncorrected_error_count) ||
           (bank->software_numa_enabled_inverse !=
            ~bank->cfg.software_numa_enabled) ||
           (bank->software_numa_memtotal_kib_inverse !=
            ~bank->cfg.software_numa_memtotal_kib) ||
           (bank->software_numa_local_distance_inverse !=
            ~bank->cfg.software_numa_local_distance) ||
           (bank->software_numa_remote_distance_inverse !=
            ~bank->cfg.software_numa_remote_distance) ||
           (bank->software_fault_injection_mode_inverse !=
            ~bank->cfg.software_fault_injection_mode) ||
           (bank->evidence_mac_enabled_inverse !=
            ~bank->cfg.evidence_mac_enabled);
}

static bool llps_runtime_cfg_text_inverse_is_valid(
    const uint8_t * const inverse,
    const char * const text,
    const size_t len) {
    for (size_t i = 0u; i < len; ++i) {
        if (inverse[i] != (uint8_t)(~((uint8_t)text[i]))) {
            return false;
        }
    }
    return true;
}

static bool llps_runtime_cfg_bank_text_inverses_are_valid(
    const llps_runtime_cfg_bank_t * const bank) {
    return llps_runtime_cfg_text_inverse_is_valid(
               bank->listen_host_inverse,
               bank->cfg.listen_host,
               sizeof(bank->cfg.listen_host)) &&
           llps_runtime_cfg_text_inverse_is_valid(
               bank->target_ip_inverse,
               bank->cfg.target_ip,
               sizeof(bank->cfg.target_ip)) &&
           llps_runtime_cfg_text_inverse_is_valid(
               bank->ip_audit_path_inverse,
               bank->cfg.ip_audit_path,
               sizeof(bank->cfg.ip_audit_path)) &&
           llps_runtime_cfg_text_inverse_is_valid(
               bank->audit_mac_key_path_inverse,
               bank->cfg.audit_mac_key_path,
               sizeof(bank->cfg.audit_mac_key_path)) &&
           llps_runtime_cfg_text_inverse_is_valid(
               bank->evidence_mac_key_path_inverse,
               bank->cfg.evidence_mac_key_path,
               sizeof(bank->cfg.evidence_mac_key_path));
}

static bool llps_runtime_cfg_bank_domain_inverses_are_valid(
    const llps_runtime_cfg_bank_t * const bank) {
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (bank->platform_physical_memory_domains_inverse[i] !=
            ~bank->cfg.platform_physical_memory_domains[i]) {
            return false;
        }
        if (bank->platform_hardware_tmr_domains_inverse[i] !=
            ~bank->cfg.platform_hardware_tmr_domains[i]) {
            return false;
        }
    }
    return true;
}

bool llps_runtime_cfg_bank_is_valid(
    const llps_runtime_cfg_bank_t * const bank,
    const uint32_t expected_bank_id) {
    const uint32_t magic = llps_runtime_cfg_bank_magic_for_bank(expected_bank_id);

    if (bank == NULL) {
        return false;
    }
    if ((bank->magic_start != magic) ||
        (bank->magic_end != magic) ||
        (bank->bank_id != expected_bank_id) ||
        llps_runtime_cfg_bank_runtime_inverse_is_invalid(bank) ||
        llps_runtime_cfg_bank_platform_inverse_is_invalid(bank) ||
        llps_runtime_cfg_bank_software_inverse_is_invalid(bank) ||
        !llps_runtime_cfg_values_are_valid(&bank->cfg) ||
        !llps_runtime_cfg_bank_text_inverses_are_valid(bank) ||
        !llps_runtime_cfg_bank_domain_inverses_are_valid(bank)) {
        return false;
    }
    return (bank->crc_inverse == ~bank->crc) &&
           (bank->crc == llps_runtime_cfg_bank_compute_crc(bank));
}

static void llps_runtime_cfg_bank_set_runtime_inverse(
    llps_runtime_cfg_bank_t * const bank,
    const llps_yml_config_t * const cfg) {
    bank->max_clients_inverse = ~cfg->max_clients;
    bank->buffer_size_inverse = ~cfg->buffer_size;
    bank->payload_ecc_enabled_inverse = ~cfg->payload_ecc_enabled;
    bank->listen_port_inverse = ~((uint32_t)cfg->listen_port);
    bank->target_port_inverse = ~((uint32_t)cfg->target_port);
    bank->listen_backlog_inverse = ~cfg->listen_backlog;
    bank->accept_batch_max_inverse = ~cfg->accept_batch_max;
    bank->session_idle_timeout_ms_inverse = ~cfg->session_idle_timeout_ms;
    bank->max_sessions_per_client_ip_inverse =
        ~cfg->max_sessions_per_client_ip;
    bank->max_new_sessions_per_client_ip_per_window_inverse =
        ~cfg->max_new_sessions_per_client_ip_per_window;
    bank->client_ip_rate_window_ms_inverse =
        ~cfg->client_ip_rate_window_ms;
    bank->client_preface_timeout_ms_inverse =
        ~cfg->client_preface_timeout_ms;
    bank->protocol_handshake_gate_enabled_inverse =
        ~cfg->protocol_handshake_gate_enabled;
    bank->ip_audit_enabled_inverse = ~cfg->ip_audit_enabled;
    bank->audit_mac_enabled_inverse = ~cfg->audit_mac_enabled;
}

static void llps_runtime_cfg_bank_set_platform_inverse(
    llps_runtime_cfg_bank_t * const bank,
    const llps_yml_config_t * const cfg) {
    bank->require_readiness_inverse = ~cfg->require_readiness;
    bank->platform_safety_flags_inverse = ~cfg->platform_safety_flags;
    bank->platform_safety_evidence_id_inverse =
        ~cfg->platform_safety_evidence_id;
    bank->platform_attestation_fingerprint_inverse =
        ~cfg->platform_attestation_fingerprint;
    bank->platform_observation_digest_inverse =
        ~cfg->platform_observation_digest;
    bank->platform_evidence_mode_inverse = ~cfg->platform_evidence_mode;
    bank->platform_hardware_tmr_voter_domain_inverse =
        ~cfg->platform_hardware_tmr_voter_domain;
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        bank->platform_physical_memory_domains_inverse[i] =
            ~cfg->platform_physical_memory_domains[i];
        bank->platform_hardware_tmr_domains_inverse[i] =
            ~cfg->platform_hardware_tmr_domains[i];
    }
}

static void llps_runtime_cfg_bank_set_software_inverse(
    llps_runtime_cfg_bank_t * const bank,
    const llps_yml_config_t * const cfg) {
    bank->software_ecc_enabled_inverse = ~cfg->software_ecc_enabled;
    bank->software_ecc_controller_count_inverse =
        ~cfg->software_ecc_controller_count;
    bank->software_ecc_dimm_count_inverse = ~cfg->software_ecc_dimm_count;
    bank->software_ecc_scrub_rate_inverse = ~cfg->software_ecc_scrub_rate;
    bank->software_ecc_controller_corrected_error_count_inverse =
        ~cfg->software_ecc_controller_corrected_error_count;
    bank->software_ecc_controller_uncorrected_error_count_inverse =
        ~cfg->software_ecc_controller_uncorrected_error_count;
    bank->software_ecc_dimm_corrected_error_count_inverse =
        ~cfg->software_ecc_dimm_corrected_error_count;
    bank->software_ecc_dimm_uncorrected_error_count_inverse =
        ~cfg->software_ecc_dimm_uncorrected_error_count;
    bank->software_numa_enabled_inverse = ~cfg->software_numa_enabled;
    bank->software_numa_memtotal_kib_inverse =
        ~cfg->software_numa_memtotal_kib;
    bank->software_numa_local_distance_inverse =
        ~cfg->software_numa_local_distance;
    bank->software_numa_remote_distance_inverse =
        ~cfg->software_numa_remote_distance;
    bank->software_fault_injection_mode_inverse =
        ~cfg->software_fault_injection_mode;
    bank->evidence_mac_enabled_inverse = ~cfg->evidence_mac_enabled;
}

static void llps_runtime_cfg_bank_set_text_inverse(
    uint8_t * const inverse,
    const char * const text,
    const size_t len) {
    for (size_t i = 0u; i < len; ++i) {
        inverse[i] = (uint8_t)(~((uint8_t)text[i]));
    }
}

static void llps_runtime_cfg_bank_set_text_inverses(
    llps_runtime_cfg_bank_t * const bank,
    const llps_yml_config_t * const cfg) {
    llps_runtime_cfg_bank_set_text_inverse(
        bank->listen_host_inverse,
        cfg->listen_host,
        sizeof(bank->cfg.listen_host));
    llps_runtime_cfg_bank_set_text_inverse(
        bank->target_ip_inverse,
        cfg->target_ip,
        sizeof(bank->cfg.target_ip));
    llps_runtime_cfg_bank_set_text_inverse(
        bank->ip_audit_path_inverse,
        cfg->ip_audit_path,
        sizeof(bank->cfg.ip_audit_path));
    llps_runtime_cfg_bank_set_text_inverse(
        bank->audit_mac_key_path_inverse,
        cfg->audit_mac_key_path,
        sizeof(bank->cfg.audit_mac_key_path));
    llps_runtime_cfg_bank_set_text_inverse(
        bank->evidence_mac_key_path_inverse,
        cfg->evidence_mac_key_path,
        sizeof(bank->cfg.evidence_mac_key_path));
}

void llps_runtime_cfg_bank_from_config(
    llps_runtime_cfg_bank_t * const bank,
    const uint32_t bank_id,
    const llps_yml_config_t * const cfg) {
    const uint32_t magic = llps_runtime_cfg_bank_magic_for_bank(bank_id);

    if ((bank != NULL) && (cfg != NULL)) {
        bank->magic_start = magic;
        bank->bank_id = bank_id;
        bank->cfg = *cfg;
        llps_runtime_cfg_bank_set_runtime_inverse(bank, cfg);
        llps_runtime_cfg_bank_set_platform_inverse(bank, cfg);
        llps_runtime_cfg_bank_set_software_inverse(bank, cfg);
        llps_runtime_cfg_bank_set_text_inverses(bank, cfg);
        bank->magic_end = magic;
        bank->crc = llps_runtime_cfg_bank_compute_crc(bank);
        bank->crc_inverse = ~bank->crc;
    }
}

void llps_runtime_cfg_write_all(const llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_runtime_cfg_bank_t * const bank =
            llps_runtime_cfg_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        llps_runtime_cfg_bank_from_config(bank, bank_id, cfg);
    }
}

static void llps_runtime_cfg_repair_divergent_banks(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_yml_config_t snapshots[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_yml_config_t * const majority) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        if (!valid[bank_id] ||
            !llps_runtime_cfg_equal(&snapshots[bank_id], majority)) {
            llps_runtime_cfg_bank_t * const bank =
                llps_runtime_cfg_bank_ref(bank_id);
            if (bank != NULL) {
                llps_runtime_cfg_bank_from_config(bank, bank_id, majority);
                LLPS_MEMORY_SAFETY_COUNTER_INC(runtime_cfg_single_bank_repairs);
            }
        }
    }
}

bool llps_runtime_cfg_reconcile(llps_yml_config_t * const canonical_cfg) {
    bool valid[LLPS_SESSION_TMR_BANK_COUNT] = { false, false, false };
    llps_yml_config_t snapshots[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t valid_count = 0u;
    uint32_t majority_index = UINT32_MAX;
    llps_yml_config_t majority;

    if (canonical_cfg == NULL) {
        return false;
    }

    (void)memset(snapshots, 0, sizeof(snapshots));
    (void)memset(&majority, 0, sizeof(majority));

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_runtime_cfg_bank_t * const bank =
            llps_runtime_cfg_bank_cref(bank_id);

        valid[bank_id] = llps_runtime_cfg_bank_is_valid(bank, bank_id);
        if (valid[bank_id] && (bank != NULL)) {
            snapshots[bank_id] = bank->cfg;
            ++valid_count;
        }
    }

    if (valid_count < 2u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(runtime_cfg_majority_failures);
        return false;
    }

    if (!llps_tmr_vote_find_matching_pair(
            valid,
            llps_runtime_cfg_equal(&snapshots[0u], &snapshots[1u]),
            llps_runtime_cfg_equal(&snapshots[0u], &snapshots[2u]),
            llps_runtime_cfg_equal(&snapshots[1u], &snapshots[2u]),
            &majority_index)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(runtime_cfg_majority_failures);
        return false;
    }
    majority = snapshots[majority_index];

    llps_runtime_cfg_repair_divergent_banks(valid, snapshots, &majority);
    *canonical_cfg = majority;
    return true;
}

static bool llps_select_runtime_cfg_no_majority_ports(
    const llps_yml_config_t * const cfg,
    uint16_t out_ports[LLPS_SESSION_TMR_BANK_COUNT]) {
    uint32_t count = 1u;

    if ((cfg == NULL) || (out_ports == NULL)) {
        return false;
    }

    out_ports[0] = cfg->target_port;
    out_ports[1] = 0u;
    out_ports[2] = 0u;

    for (uint32_t candidate = 1u;
         (candidate <= UINT16_MAX) && (count < LLPS_SESSION_TMR_BANK_COUNT);
         ++candidate) {
        const uint16_t port = (uint16_t)candidate;
        bool duplicate = false;

        if (port == cfg->listen_port) {
            continue;
        }

        for (uint32_t i = 0u; i < count; ++i) {
            if (port == out_ports[i]) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            out_ports[count] = port;
            ++count;
        }
    }

    return count == LLPS_SESSION_TMR_BANK_COUNT;
}

static bool llps_runtime_cfg_save_banks(
    llps_runtime_cfg_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (saved == NULL) {
        return false;
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_runtime_cfg_bank_t * const bank =
            llps_runtime_cfg_bank_cref(bank_id);
        if (bank == NULL) {
            return false;
        }
        saved[bank_id] = *bank;
    }

    return true;
}

static void llps_runtime_cfg_restore_banks(
    const llps_runtime_cfg_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (saved == NULL) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_runtime_cfg_bank_t * const bank =
            llps_runtime_cfg_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        *bank = saved[bank_id];
    }
}

static bool llps_runtime_cfg_self_test_bank_refs(
    llps_runtime_cfg_bank_t ** const bank0,
    llps_runtime_cfg_bank_t ** const bank1,
    llps_runtime_cfg_bank_t ** const bank2) {
    if ((bank0 == NULL) || (bank1 == NULL) || (bank2 == NULL)) {
        return false;
    }

    *bank0 = llps_runtime_cfg_bank_ref(0u);
    *bank1 = llps_runtime_cfg_bank_ref(1u);
    *bank2 = llps_runtime_cfg_bank_ref(2u);
    if ((*bank0 == NULL) || (*bank1 == NULL) || (*bank2 == NULL)) {
        LLPS_EXPECT(false, return false);
    }
    return true;
}

static bool llps_runtime_cfg_self_test_single_repair(
    llps_yml_config_t * const canonical_cfg,
    const llps_yml_config_t * const saved_cfg,
    llps_runtime_cfg_bank_t * const bank0,
    uint32_t * const coverage) {
    if ((canonical_cfg == NULL) || (saved_cfg == NULL) ||
        (bank0 == NULL) || (coverage == NULL)) {
        return false;
    }

    bank0->magic_start ^= UINT32_MAX;
    const bool passed = llps_runtime_cfg_reconcile(canonical_cfg) &&
                        llps_runtime_cfg_equal(canonical_cfg, saved_cfg) &&
                        llps_runtime_cfg_bank_is_valid(bank0, 0u);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_RUNTIME_CFG_SINGLE_REPAIR;
    }
    return passed;
}

static bool llps_runtime_cfg_self_test_no_majority(
    llps_yml_config_t * const canonical_cfg,
    const llps_yml_config_t * const saved_cfg,
    llps_runtime_cfg_bank_t * const bank0,
    llps_runtime_cfg_bank_t * const bank1,
    llps_runtime_cfg_bank_t * const bank2,
    uint32_t * const coverage) {
    uint16_t ports[LLPS_SESSION_TMR_BANK_COUNT] = { 0u, 0u, 0u };
    llps_yml_config_t cfg0;
    llps_yml_config_t cfg1;
    llps_yml_config_t cfg2;

    if ((canonical_cfg == NULL) || (saved_cfg == NULL) ||
        (bank0 == NULL) || (bank1 == NULL) || (bank2 == NULL) ||
        (coverage == NULL) ||
        !llps_select_runtime_cfg_no_majority_ports(saved_cfg, ports)) {
        return false;
    }

    cfg0 = *saved_cfg;
    cfg1 = *saved_cfg;
    cfg2 = *saved_cfg;
    cfg0.target_port = ports[0u];
    cfg1.target_port = ports[1u];
    cfg2.target_port = ports[2u];
    llps_runtime_cfg_bank_from_config(bank0, 0u, &cfg0);
    llps_runtime_cfg_bank_from_config(bank1, 1u, &cfg1);
    llps_runtime_cfg_bank_from_config(bank2, 2u, &cfg2);
    const bool passed = !llps_runtime_cfg_reconcile(canonical_cfg);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_RUNTIME_CFG_NO_MAJORITY_FAIL_CLOSED;
    }
    return passed;
}

static bool llps_runtime_cfg_self_test_dual_fail(
    llps_yml_config_t * const canonical_cfg,
    const llps_yml_config_t * const saved_cfg,
    llps_runtime_cfg_bank_t * const bank0,
    llps_runtime_cfg_bank_t * const bank1,
    uint32_t * const coverage) {
    if ((canonical_cfg == NULL) || (saved_cfg == NULL) ||
        (bank0 == NULL) || (bank1 == NULL) || (coverage == NULL)) {
        return false;
    }

    *canonical_cfg = *saved_cfg;
    llps_runtime_cfg_write_all(saved_cfg);
    bank0->magic_start = 0u;
    bank1->magic_start = 0u;
    const bool passed = !llps_runtime_cfg_reconcile(canonical_cfg);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_RUNTIME_CFG_DUAL_FAIL_CLOSED;
    }
    return passed;
}

bool llps_runtime_cfg_tmr_startup_self_test(
    llps_yml_config_t * const canonical_cfg,
    uint32_t * const coverage) {
    const llps_yml_config_t saved_cfg =
        (canonical_cfg != NULL) ? *canonical_cfg : (llps_yml_config_t){ 0 };
    llps_runtime_cfg_bank_t saved_banks[LLPS_SESSION_TMR_BANK_COUNT];
    bool passed = false;
    bool saved_banks_valid = false;
    llps_runtime_cfg_bank_t *bank0 = NULL;
    llps_runtime_cfg_bank_t *bank1 = NULL;
    llps_runtime_cfg_bank_t *bank2 = NULL;

    if ((canonical_cfg == NULL) ||
        (coverage == NULL)) {
        return false;
    }

    saved_banks_valid = llps_runtime_cfg_save_banks(saved_banks);
    passed = saved_banks_valid &&
             llps_runtime_cfg_reconcile(canonical_cfg) &&
             llps_runtime_cfg_equal(canonical_cfg, &saved_cfg);

    if (passed) {
        passed = llps_runtime_cfg_self_test_bank_refs(&bank0, &bank1, &bank2);
    }

    if (passed) {
        passed = llps_runtime_cfg_self_test_single_repair(canonical_cfg,
                                                          &saved_cfg,
                                                          bank0,
                                                          coverage);
    }
    if (passed) {
        passed = llps_runtime_cfg_self_test_no_majority(canonical_cfg,
                                                        &saved_cfg,
                                                        bank0,
                                                        bank1,
                                                        bank2,
                                                        coverage);
    }

    if (passed) {
        passed = llps_runtime_cfg_self_test_dual_fail(canonical_cfg,
                                                      &saved_cfg,
                                                      bank0,
                                                      bank1,
                                                      coverage);
    }

    if (canonical_cfg != NULL) {
        *canonical_cfg = saved_cfg;
    }
    if (saved_banks_valid) {
        llps_runtime_cfg_restore_banks(saved_banks);
    }
    return passed;
}
