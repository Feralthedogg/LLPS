/**
 * @file src/internal/llps_platform_evidence_runtime.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_PLATFORM_EVIDENCE_RUNTIME_H
#define LLPS_PLATFORM_EVIDENCE_RUNTIME_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    const char *edac_sysfs_root;
    const char *boot_id_path;
    const char *platform_id_path;
    const char *executable_image_path;
    const char *numa_sysfs_root;
    uint32_t configured_platform_safety_flags;
    uint64_t configured_platform_safety_evidence_id;
    uint32_t configured_platform_attestation_fingerprint;
    uint32_t configured_platform_observation_digest;
    uint32_t configured_physical_memory_domain_ids[
        LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t configured_hardware_tmr_domain_ids[
        LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t configured_hardware_tmr_voter_domain_id;
    uint32_t platform_evidence_mode;
    bool payload_ecc_enabled;
    bool software_ecc_enabled;
    uint32_t software_ecc_controller_count;
    uint32_t software_ecc_dimm_count;
    uint64_t software_ecc_scrub_rate;
    uint64_t software_ecc_controller_corrected_error_count;
    uint64_t software_ecc_controller_uncorrected_error_count;
    uint64_t software_ecc_dimm_corrected_error_count;
    uint64_t software_ecc_dimm_uncorrected_error_count;
    bool software_numa_enabled;
    uint64_t software_numa_memtotal_kib;
    uint64_t software_numa_local_distance;
    uint64_t software_numa_remote_distance;
    uint32_t software_fault_injection_mode;
    bool evidence_mac_enabled;
    const char *evidence_mac_key_path;
} llps_platform_evidence_context_t;

bool llps_platform_safety_evidence_is_valid_in_context(
    const llps_platform_evidence_context_t *context,
    const llps_platform_safety_evidence_t *evidence);
bool llps_platform_safety_evidence_request_is_bound_in_context(
    const llps_platform_evidence_context_t *context,
    const llps_platform_safety_evidence_t *evidence);
bool llps_platform_safety_evidence_observation_digest_is_bound_in_context(
    const llps_platform_evidence_context_t *context,
    const llps_platform_safety_evidence_t *evidence);
bool llps_platform_safety_evidence_mac_is_valid_in_context(
    const llps_platform_evidence_context_t *context,
    const llps_platform_safety_evidence_t *evidence);
llps_status_t llps_make_platform_safety_evidence_in_context(
    const llps_platform_evidence_context_t *context,
    uint32_t flags,
    uint64_t evidence_id,
    llps_platform_safety_evidence_t *out_evidence);
llps_status_t llps_make_platform_safety_evidence_ex_in_context(
    const llps_platform_evidence_context_t *context,
    uint32_t flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t *out_evidence);
llps_status_t llps_make_platform_safety_evidence_raw_in_context(
    const llps_platform_evidence_context_t *context,
    uint32_t flags,
    uint32_t observed_flags,
    uint32_t attested_flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t *out_evidence);
llps_status_t llps_collect_platform_safety_evidence_in_context(
    const llps_platform_evidence_context_t *context,
    uint32_t requested_flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t *out_evidence);

#endif /* LLPS_PLATFORM_EVIDENCE_RUNTIME_H */
