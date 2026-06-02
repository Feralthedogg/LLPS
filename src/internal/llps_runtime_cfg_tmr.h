/**
 * @file src/internal/llps_runtime_cfg_tmr.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_RUNTIME_CFG_TMR_H
#define LLPS_RUNTIME_CFG_TMR_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t magic_start;
    uint32_t bank_id;
    llps_yml_config_t cfg;
    uint32_t max_clients_inverse;
    uint32_t buffer_size_inverse;
    uint32_t payload_ecc_enabled_inverse;
    uint32_t listen_port_inverse;
    uint32_t target_port_inverse;
    uint32_t listen_backlog_inverse;
    uint32_t accept_batch_max_inverse;
    uint32_t session_idle_timeout_ms_inverse;
    uint32_t max_sessions_per_client_ip_inverse;
    uint32_t max_new_sessions_per_client_ip_per_window_inverse;
    uint32_t client_ip_rate_window_ms_inverse;
    uint32_t client_preface_timeout_ms_inverse;
    uint32_t protocol_handshake_gate_enabled_inverse;
    uint32_t ip_audit_enabled_inverse;
    uint32_t audit_mac_enabled_inverse;
    uint32_t require_readiness_inverse;
    uint32_t platform_safety_flags_inverse;
    uint64_t platform_safety_evidence_id_inverse;
    uint32_t platform_attestation_fingerprint_inverse;
    uint32_t platform_observation_digest_inverse;
    uint32_t platform_evidence_mode_inverse;
    uint32_t platform_physical_memory_domains_inverse[
        LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t platform_hardware_tmr_domains_inverse[
        LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t platform_hardware_tmr_voter_domain_inverse;
    uint32_t software_ecc_enabled_inverse;
    uint32_t software_ecc_controller_count_inverse;
    uint32_t software_ecc_dimm_count_inverse;
    uint64_t software_ecc_scrub_rate_inverse;
    uint64_t software_ecc_controller_corrected_error_count_inverse;
    uint64_t software_ecc_controller_uncorrected_error_count_inverse;
    uint64_t software_ecc_dimm_corrected_error_count_inverse;
    uint64_t software_ecc_dimm_uncorrected_error_count_inverse;
    uint32_t software_numa_enabled_inverse;
    uint64_t software_numa_memtotal_kib_inverse;
    uint64_t software_numa_local_distance_inverse;
    uint64_t software_numa_remote_distance_inverse;
    uint32_t software_fault_injection_mode_inverse;
    uint32_t evidence_mac_enabled_inverse;
    uint8_t listen_host_inverse[LLPS_YML_MAX_IP_TEXT];
    uint8_t target_ip_inverse[LLPS_YML_MAX_IP_TEXT];
    uint8_t ip_audit_path_inverse[LLPS_YML_MAX_PATH_TEXT];
    uint8_t audit_mac_key_path_inverse[LLPS_YML_MAX_PATH_TEXT];
    uint8_t evidence_mac_key_path_inverse[LLPS_YML_MAX_PATH_TEXT];
    uint32_t crc;
    uint32_t crc_inverse;
    uint32_t magic_end;
} llps_runtime_cfg_bank_t;

extern llps_runtime_cfg_bank_t g_runtime_cfg_bank0;
extern llps_runtime_cfg_bank_t g_runtime_cfg_bank1;
extern llps_runtime_cfg_bank_t g_runtime_cfg_bank2;

/** @brief Compute the CRC for one replicated runtime-config bank. */
uint32_t llps_runtime_cfg_bank_compute_crc(
    const llps_runtime_cfg_bank_t *bank);
/** @brief Compare two normalized runtime configuration snapshots. */
bool llps_runtime_cfg_equal(const llps_yml_config_t *lhs,
                            const llps_yml_config_t *rhs);
/** @brief Validate canaries, inverse fields, config bounds, and CRC. */
bool llps_runtime_cfg_bank_is_valid(const llps_runtime_cfg_bank_t *bank,
                                    uint32_t expected_bank_id);
/** @brief Populate one runtime-config bank from a canonical config. */
void llps_runtime_cfg_bank_from_config(llps_runtime_cfg_bank_t *bank,
                                       uint32_t bank_id,
                                       const llps_yml_config_t *cfg);
/** @brief Write a canonical config into all runtime-config TMR banks. */
void llps_runtime_cfg_write_all(const llps_yml_config_t *cfg);
/** @brief Vote runtime-config banks and repair a single divergent bank. */
bool llps_runtime_cfg_reconcile(llps_yml_config_t *canonical_cfg);
/** @brief Exercise runtime-config repair and fail-closed startup paths. */
bool llps_runtime_cfg_tmr_startup_self_test(llps_yml_config_t *canonical_cfg,
                                            uint32_t *coverage);

#endif /* LLPS_RUNTIME_CFG_TMR_H */
