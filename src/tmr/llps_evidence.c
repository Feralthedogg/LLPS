/**
 * @file src/tmr/llps_evidence.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_evidence.h"

#include "llps_crc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint32_t llps_platform_safety_evidence_known_flags(void) {
    return LLPS_PLATFORM_EVIDENCE_REQUIRED;
}

bool llps_platform_domain_inverses_are_valid(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t ids_inverse[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((ids == NULL) || (ids_inverse == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (ids_inverse[i] != ~ids[i]) {
            return false;
        }
    }

    return true;
}

static uint32_t llps_evidence_crc_header_edac(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->magic);
    crc = llps_crc32_update_u32(crc, e->version);
    crc = llps_crc32_update_u32(crc, e->flags);
    crc = llps_crc32_update_u32(crc, e->flags_inverse);
    crc = llps_crc32_update_u32(crc, e->observed_flags);
    crc = llps_crc32_update_u32(crc, e->observed_flags_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->edac_observation_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_controller_count);
    crc = llps_crc32_update_u32(crc, e->edac_controller_count_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_count);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_count_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_count);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_count_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_controller_counter_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_controller_counter_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_mode_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_mode_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_counter_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_counter_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_coverage_inverse);
    crc = llps_crc32_update_u64(crc, e->edac_corrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_corrected_error_count_inverse);
    crc = llps_crc32_update_u64(crc, e->edac_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_uncorrected_error_count_inverse);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_corrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_corrected_error_count_inverse);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_uncorrected_error_count_inverse);
    crc = llps_crc32_update_u64(crc, e->edac_scrub_rate_sum);
    return llps_crc32_update_u64(crc, e->edac_scrub_rate_sum_inverse);
}

static uint32_t llps_evidence_crc_runtime(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->platform_boot_fingerprint);
    crc = llps_crc32_update_u32(crc, e->platform_boot_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->platform_identity_fingerprint);
    crc = llps_crc32_update_u32(crc, e->platform_identity_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->executable_image_fingerprint);
    crc = llps_crc32_update_u32(crc, e->executable_image_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->process_memory_locked);
    crc = llps_crc32_update_u32(crc, e->process_memory_locked_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_locked);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_locked_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_prefaulted);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_prefaulted_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_prefault_pages);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_prefault_pages_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_hardened);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_hardened_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_passed);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_passed_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_coverage);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_required_coverage);
    return llps_crc32_update_u32(crc, e->tmr_startup_self_test_required_coverage_inverse);
}

static uint32_t llps_evidence_crc_software(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->platform_evidence_mode);
    crc = llps_crc32_update_u32(crc, e->platform_evidence_mode_inverse);
    crc = llps_crc32_update_u32(crc, e->software_evidence_schema_version);
    crc = llps_crc32_update_u32(crc, e->software_evidence_schema_version_inverse);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_passed);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_passed_inverse);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_coverage);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_required_coverage);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_required_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->software_ecc_controller_count);
    crc = llps_crc32_update_u32(crc, e->software_ecc_controller_count_inverse);
    crc = llps_crc32_update_u32(crc, e->software_dimm_bank_count);
    crc = llps_crc32_update_u32(crc, e->software_dimm_bank_count_inverse);
    crc = llps_crc32_update_u64(crc, e->software_ecc_scrub_rate);
    crc = llps_crc32_update_u64(crc, e->software_ecc_scrub_rate_inverse);
    crc = llps_crc32_update_u32(crc, e->software_dimm_generation);
    crc = llps_crc32_update_u32(crc, e->software_dimm_generation_inverse);
    crc = llps_crc32_update_u32(crc, e->software_dimm_scrub_generation);
    crc = llps_crc32_update_u32(crc, e->software_dimm_scrub_generation_inverse);
    crc = llps_crc32_update_u32(crc, e->software_dimm_fault_injection_coverage);
    crc = llps_crc32_update_u32(crc, e->software_dimm_fault_injection_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->software_fault_injection_mode);
    crc = llps_crc32_update_u32(crc, e->software_fault_injection_mode_inverse);
    crc = llps_crc32_update_u32(crc, e->software_dimm_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->software_dimm_observation_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->software_numa_profile_fingerprint);
    return llps_crc32_update_u32(crc, e->software_numa_profile_fingerprint_inverse);
}

static uint32_t llps_evidence_crc_physical_domains(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->physical_domain_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->physical_domain_observation_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->physical_domain_topology_coverage);
    crc = llps_crc32_update_u32(crc, e->physical_domain_topology_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->physical_domain_observed_count);
    crc = llps_crc32_update_u32(crc, e->physical_domain_observed_count_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_memtotal_kib);
    crc = llps_crc32_update_u64(crc, e->physical_domain_memtotal_kib_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_entries);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_entries_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_sum);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_sum_inverse);
    crc = llps_crc32_update_u32(crc, e->physical_domain_distance_pair_coverage);
    crc = llps_crc32_update_u32(crc, e->physical_domain_distance_pair_coverage_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_01);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_01_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_02);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_02_inverse);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_12);
    return llps_crc32_update_u64(crc, e->physical_domain_distance_12_inverse);
}

static uint32_t llps_evidence_crc_tmr_memory(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->tmr_memory_domain_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_domain_observation_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_resident);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_resident_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_resident_pages);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_resident_pages_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_residency_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_residency_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_distinct);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_distinct_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_spaced);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_spaced_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_pages);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_pages_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_probe_failures);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_probe_failures_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_min_distance);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_min_distance_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_required_distance);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_required_distance_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_01);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_01_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_02);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_02_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_12);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_12_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_pair_coverage);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_pair_coverage_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_fingerprint_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_pages_checked);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_pages_checked_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_mismatch_count);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_mismatch_count_inverse);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_probe_failures);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_probe_failures_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_domain_region_coverage);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_domain_region_coverage_inverse);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->tmr_memory_observed_domain_ids[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->tmr_memory_observed_domain_ids_inverse[i]);
    }
    return crc;
}

static uint32_t llps_evidence_crc_attestation(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->attested_flags);
    crc = llps_crc32_update_u32(crc, e->attested_flags_inverse);
    crc = llps_crc32_update_u32(crc, e->attestation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->attestation_fingerprint_inverse);
    crc = llps_crc32_update_u64(crc, e->evidence_id);
    crc = llps_crc32_update_u64(crc, e->evidence_id_inverse);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->physical_memory_domain_ids[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->physical_memory_domain_ids_inverse[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->hardware_tmr_domain_ids[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->hardware_tmr_domain_ids_inverse[i]);
    }
    crc = llps_crc32_update_u32(crc, e->hardware_tmr_voter_domain_id);
    crc = llps_crc32_update_u32(crc, e->hardware_tmr_voter_domain_id_inverse);
    crc = llps_crc32_update_u32(crc, e->tmr_layout_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_layout_fingerprint_inverse);
    crc = llps_crc32_update_u32(crc, e->observation_digest);
    crc = llps_crc32_update_u32(crc, e->observation_digest_inverse);
    crc = llps_crc32_update_u32(crc, e->evidence_mac_enabled);
    crc = llps_crc32_update_u32(crc, e->evidence_mac_enabled_inverse);
    crc = llps_crc32_update_u32(crc, e->evidence_mac_key_fingerprint);
    return llps_crc32_update_u32(crc, e->evidence_mac_key_fingerprint_inverse);
}

uint32_t llps_platform_safety_evidence_compute_crc(
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (evidence == NULL) {
        return 0u;
    }

    crc = llps_evidence_crc_header_edac(crc, evidence);
    crc = llps_evidence_crc_runtime(crc, evidence);
    crc = llps_evidence_crc_software(crc, evidence);
    crc = llps_evidence_crc_physical_domains(crc, evidence);
    crc = llps_evidence_crc_tmr_memory(crc, evidence);
    crc = llps_evidence_crc_attestation(crc, evidence);
    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static uint32_t llps_evidence_digest_header_edac_runtime(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->magic);
    crc = llps_crc32_update_u32(crc, e->version);
    crc = llps_crc32_update_u32(crc, e->flags);
    crc = llps_crc32_update_u32(crc, e->observed_flags);
    crc = llps_crc32_update_u32(crc, e->attested_flags);
    crc = llps_crc32_update_u64(crc, e->evidence_id);
    crc = llps_crc32_update_u32(crc, e->edac_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->edac_controller_count);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_count);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_count);
    crc = llps_crc32_update_u32(crc, e->edac_controller_counter_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_mode_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_dimm_counter_coverage);
    crc = llps_crc32_update_u32(crc, e->edac_scrub_rate_coverage);
    crc = llps_crc32_update_u64(crc, e->edac_corrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_corrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_dimm_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc, e->edac_scrub_rate_sum);
    crc = llps_crc32_update_u32(crc, e->platform_boot_fingerprint);
    crc = llps_crc32_update_u32(crc, e->platform_identity_fingerprint);
    crc = llps_crc32_update_u32(crc, e->executable_image_fingerprint);
    crc = llps_crc32_update_u32(crc, e->process_memory_locked);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_locked);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_prefaulted);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_prefault_pages);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_hardened);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_passed);
    crc = llps_crc32_update_u32(crc, e->tmr_startup_self_test_coverage);
    return llps_crc32_update_u32(crc, e->tmr_startup_self_test_required_coverage);
}

static uint32_t llps_evidence_digest_software(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->platform_evidence_mode);
    crc = llps_crc32_update_u32(crc, e->software_evidence_schema_version);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_passed);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_coverage);
    crc = llps_crc32_update_u32(crc, e->software_evidence_self_test_required_coverage);
    crc = llps_crc32_update_u32(crc, e->software_ecc_controller_count);
    crc = llps_crc32_update_u32(crc, e->software_dimm_bank_count);
    crc = llps_crc32_update_u64(crc, e->software_ecc_scrub_rate);
    crc = llps_crc32_update_u32(crc, e->software_dimm_generation);
    crc = llps_crc32_update_u32(crc, e->software_dimm_scrub_generation);
    crc = llps_crc32_update_u32(crc, e->software_dimm_fault_injection_coverage);
    crc = llps_crc32_update_u32(crc, e->software_fault_injection_mode);
    crc = llps_crc32_update_u32(crc, e->software_dimm_observation_fingerprint);
    return llps_crc32_update_u32(crc, e->software_numa_profile_fingerprint);
}

static uint32_t llps_evidence_digest_domains_tmr(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    crc = llps_crc32_update_u32(crc, e->physical_domain_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->physical_domain_topology_coverage);
    crc = llps_crc32_update_u32(crc, e->physical_domain_observed_count);
    crc = llps_crc32_update_u64(crc, e->physical_domain_memtotal_kib);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_entries);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_sum);
    crc = llps_crc32_update_u32(crc, e->physical_domain_distance_pair_coverage);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_01);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_02);
    crc = llps_crc32_update_u64(crc, e->physical_domain_distance_12);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_domain_observation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_resident);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_resident_pages);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_residency_fingerprint);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_distinct);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frames_spaced);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_pages);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_probe_failures);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_min_distance);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_required_distance);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_01);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_02);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_physical_frame_distance_12);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_pair_coverage);
    crc = llps_crc32_update_u32(crc, e->tmr_memory_physical_frame_fingerprint);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_pages_checked);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_mismatch_count);
    crc = llps_crc32_update_u64(crc, e->tmr_memory_domain_probe_failures);
    return llps_crc32_update_u32(crc, e->tmr_memory_domain_region_coverage);
}

static uint32_t llps_evidence_digest_attestation(
    uint32_t crc,
    const llps_platform_safety_evidence_t * const e) {
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->physical_memory_domain_ids[i]);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->hardware_tmr_domain_ids[i]);
    }
    crc = llps_crc32_update_u32(crc, e->hardware_tmr_voter_domain_id);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, e->tmr_memory_observed_domain_ids[i]);
    }
    crc = llps_crc32_update_u32(crc, e->tmr_layout_fingerprint);
    crc = llps_crc32_update_u32(crc, e->attestation_fingerprint);
    crc = llps_crc32_update_u32(crc, e->evidence_mac_enabled);
    return llps_crc32_update_u32(crc, e->evidence_mac_key_fingerprint);
}

uint32_t llps_platform_safety_evidence_compute_observation_digest(
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (evidence == NULL) {
        return 0u;
    }

    crc = llps_evidence_digest_header_edac_runtime(crc, evidence);
    crc = llps_evidence_digest_software(crc, evidence);
    crc = llps_evidence_digest_domains_tmr(crc, evidence);
    crc = llps_evidence_digest_attestation(crc, evidence);
    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}
