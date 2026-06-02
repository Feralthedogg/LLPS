/**
 * @file src/platform/llps_platform_evidence_runtime.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_platform_evidence_runtime.h"

#include "llps_control_flag.h"
#include "llps_domain.h"
#include "llps_edac.h"
#include "llps_evidence.h"
#include "llps_guard.h"
#include "llps_hmac.h"
#include "llps_numa.h"
#include "llps_platform.h"
#include "llps_runtime_latches.h"
#include "llps_software_evidence.h"
#include "llps_tmr_layout.h"
#include "llps_tmr_observer.h"
#include "llps_tmr_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static bool llps_platform_evidence_header_is_valid(
    const llps_platform_safety_evidence_t * const evidence,
    const uint32_t effective_flags,
    const uint32_t known_flags) {
    if ((evidence->magic != LLPS_PLATFORM_EVIDENCE_MAGIC) ||
        (evidence->version != LLPS_PLATFORM_EVIDENCE_VERSION) ||
        (evidence->evidence_id == 0u) ||
        (evidence->flags_inverse != ~evidence->flags) ||
        (evidence->observed_flags_inverse != ~evidence->observed_flags) ||
        (evidence->flags != effective_flags) ||
        (evidence->evidence_id_inverse != ~evidence->evidence_id) ||
        (evidence->tmr_layout_fingerprint_inverse !=
         ~evidence->tmr_layout_fingerprint) ||
        (evidence->observation_digest_inverse !=
         ~evidence->observation_digest) ||
        (evidence->observation_digest !=
         llps_platform_safety_evidence_compute_observation_digest(evidence)) ||
        (evidence->crc_inverse != ~evidence->crc) ||
        (evidence->tmr_layout_fingerprint != llps_tmr_layout_fingerprint()) ||
        ((evidence->flags & ~known_flags) != 0u) ||
        ((evidence->observed_flags &
          ~LLPS_PLATFORM_EVIDENCE_OBSERVED_MASK) != 0u) ||
        ((evidence->attested_flags &
          ~LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) != 0u) ||
        (((evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u) &&
         ((evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u))) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_edac_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->edac_observation_fingerprint_inverse !=
         ~evidence->edac_observation_fingerprint) ||
        (evidence->edac_controller_count_inverse !=
         ~evidence->edac_controller_count) ||
        (evidence->edac_dimm_count_inverse != ~evidence->edac_dimm_count) ||
        (evidence->edac_scrub_rate_count_inverse !=
         ~evidence->edac_scrub_rate_count) ||
        (evidence->edac_controller_counter_coverage_inverse !=
         ~evidence->edac_controller_counter_coverage) ||
        (evidence->edac_dimm_mode_coverage_inverse !=
         ~evidence->edac_dimm_mode_coverage) ||
        (evidence->edac_dimm_counter_coverage_inverse !=
         ~evidence->edac_dimm_counter_coverage) ||
        (evidence->edac_scrub_rate_coverage_inverse !=
         ~evidence->edac_scrub_rate_coverage) ||
        (evidence->edac_corrected_error_count_inverse !=
         ~evidence->edac_corrected_error_count) ||
        (evidence->edac_uncorrected_error_count_inverse !=
         ~evidence->edac_uncorrected_error_count) ||
        (evidence->edac_dimm_corrected_error_count_inverse !=
         ~evidence->edac_dimm_corrected_error_count) ||
        (evidence->edac_dimm_uncorrected_error_count_inverse !=
         ~evidence->edac_dimm_uncorrected_error_count) ||
        (evidence->edac_scrub_rate_sum_inverse !=
         ~evidence->edac_scrub_rate_sum) ||
        !llps_control_flag_value_is_valid(
             evidence->edac_controller_counter_coverage) ||
        !llps_control_flag_value_is_valid(
             evidence->edac_dimm_mode_coverage) ||
        !llps_control_flag_value_is_valid(
             evidence->edac_dimm_counter_coverage) ||
        !llps_control_flag_value_is_valid(
             evidence->edac_scrub_rate_coverage)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_runtime_latches_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->platform_boot_fingerprint_inverse !=
         ~evidence->platform_boot_fingerprint) ||
        (evidence->platform_identity_fingerprint_inverse !=
         ~evidence->platform_identity_fingerprint) ||
        (evidence->executable_image_fingerprint_inverse !=
         ~evidence->executable_image_fingerprint) ||
        (evidence->process_memory_locked_inverse !=
         ~evidence->process_memory_locked) ||
        (evidence->tmr_memory_locked_inverse !=
         ~evidence->tmr_memory_locked) ||
        (evidence->tmr_memory_prefaulted_inverse !=
         ~evidence->tmr_memory_prefaulted) ||
        (evidence->tmr_memory_prefault_pages_inverse !=
         ~evidence->tmr_memory_prefault_pages) ||
        (evidence->tmr_memory_hardened_inverse !=
         ~evidence->tmr_memory_hardened) ||
        (evidence->tmr_startup_self_test_passed_inverse !=
         ~evidence->tmr_startup_self_test_passed) ||
        (evidence->tmr_startup_self_test_coverage_inverse !=
         ~evidence->tmr_startup_self_test_coverage) ||
        (evidence->tmr_startup_self_test_required_coverage_inverse !=
         ~evidence->tmr_startup_self_test_required_coverage) ||
        !llps_control_flag_value_is_valid(evidence->process_memory_locked) ||
        !llps_control_flag_value_is_valid(evidence->tmr_memory_locked) ||
        !llps_control_flag_value_is_valid(evidence->tmr_memory_prefaulted) ||
        !llps_control_flag_value_is_valid(evidence->tmr_memory_hardened) ||
        !llps_control_flag_value_is_valid(
             evidence->tmr_startup_self_test_passed)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_software_inverse_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->platform_evidence_mode_inverse !=
         ~evidence->platform_evidence_mode) ||
        (evidence->software_evidence_schema_version_inverse !=
         ~evidence->software_evidence_schema_version) ||
        (evidence->software_evidence_self_test_passed_inverse !=
         ~evidence->software_evidence_self_test_passed) ||
        (evidence->software_evidence_self_test_coverage_inverse !=
         ~evidence->software_evidence_self_test_coverage) ||
        (evidence->software_evidence_self_test_required_coverage_inverse !=
         ~evidence->software_evidence_self_test_required_coverage) ||
        (evidence->software_ecc_controller_count_inverse !=
         ~evidence->software_ecc_controller_count) ||
        (evidence->software_dimm_bank_count_inverse !=
         ~evidence->software_dimm_bank_count) ||
        (evidence->software_ecc_scrub_rate_inverse !=
         ~evidence->software_ecc_scrub_rate) ||
        (evidence->software_dimm_generation_inverse !=
         ~evidence->software_dimm_generation) ||
        (evidence->software_dimm_scrub_generation_inverse !=
         ~evidence->software_dimm_scrub_generation) ||
        (evidence->software_dimm_fault_injection_coverage_inverse !=
         ~evidence->software_dimm_fault_injection_coverage) ||
        (evidence->software_fault_injection_mode_inverse !=
         ~evidence->software_fault_injection_mode) ||
        (evidence->software_dimm_observation_fingerprint_inverse !=
         ~evidence->software_dimm_observation_fingerprint) ||
        (evidence->software_numa_profile_fingerprint_inverse !=
         ~evidence->software_numa_profile_fingerprint) ||
        !llps_platform_evidence_mode_is_valid(
             evidence->platform_evidence_mode) ||
        (evidence->software_fault_injection_mode >
         LLPS_SOFTWARE_FAULT_INJECTION_MAX) ||
        !llps_control_flag_value_is_valid(
             evidence->software_evidence_self_test_passed)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_software_policy_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if (llps_platform_evidence_mode_uses_software(
            evidence->platform_evidence_mode) &&
        (evidence->software_evidence_self_test_required_coverage != 0u)) {
        if ((evidence->software_evidence_self_test_passed != 1u) ||
            (evidence->software_evidence_schema_version !=
             LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION) ||
            (evidence->software_ecc_controller_count >
             LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) ||
            (evidence->software_dimm_bank_count >
             LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX) ||
            (((evidence->software_evidence_self_test_required_coverage &
               (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
                LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
                LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING)) !=
              0u) &&
             ((evidence->software_ecc_controller_count == 0u) ||
              (evidence->software_dimm_bank_count == 0u) ||
              (evidence->software_ecc_controller_count >
               evidence->software_dimm_bank_count) ||
              (evidence->software_ecc_scrub_rate == 0u) ||
              (evidence->software_ecc_scrub_rate >
               LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX))) ||
            ((evidence->software_evidence_self_test_coverage &
              evidence->software_evidence_self_test_required_coverage) !=
             evidence->software_evidence_self_test_required_coverage) ||
            (evidence->software_dimm_observation_fingerprint == 0u) ||
            (((evidence->software_evidence_self_test_required_coverage &
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING) !=
              0u) &&
             (evidence->software_numa_profile_fingerprint == 0u))) {
            return false;
        }
    }

    return true;
}

static bool llps_platform_evidence_software_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    return llps_platform_evidence_software_inverse_shape_is_valid(evidence) &&
           llps_platform_evidence_software_policy_shape_is_valid(evidence);
}

static bool llps_platform_evidence_mac_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->evidence_mac_enabled_inverse !=
         ~evidence->evidence_mac_enabled) ||
        (evidence->evidence_mac_key_fingerprint_inverse !=
         ~evidence->evidence_mac_key_fingerprint) ||
        !llps_control_flag_value_is_valid(evidence->evidence_mac_enabled)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        if (evidence->evidence_mac_inverse[i] !=
            (uint8_t)(~evidence->evidence_mac[i])) {
            return false;
        }
    }

    if ((evidence->evidence_mac_enabled == 0u) &&
        (evidence->evidence_mac_key_fingerprint != 0u)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_tmr_memory_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->tmr_memory_resident_inverse !=
         ~evidence->tmr_memory_resident) ||
        (evidence->tmr_memory_resident_pages_inverse !=
         ~evidence->tmr_memory_resident_pages) ||
        (evidence->tmr_memory_residency_fingerprint_inverse !=
         ~evidence->tmr_memory_residency_fingerprint) ||
        (evidence->tmr_memory_physical_frames_distinct_inverse !=
         ~evidence->tmr_memory_physical_frames_distinct) ||
        (evidence->tmr_memory_physical_frames_spaced_inverse !=
         ~evidence->tmr_memory_physical_frames_spaced) ||
        (evidence->tmr_memory_physical_frame_pages_inverse !=
         ~evidence->tmr_memory_physical_frame_pages) ||
        (evidence->tmr_memory_physical_frame_probe_failures_inverse !=
         ~evidence->tmr_memory_physical_frame_probe_failures) ||
        (evidence->tmr_memory_physical_frame_min_distance_inverse !=
         ~evidence->tmr_memory_physical_frame_min_distance) ||
        (evidence->tmr_memory_physical_frame_required_distance_inverse !=
         ~evidence->tmr_memory_physical_frame_required_distance) ||
        (evidence->tmr_memory_physical_frame_distance_01_inverse !=
         ~evidence->tmr_memory_physical_frame_distance_01) ||
        (evidence->tmr_memory_physical_frame_distance_02_inverse !=
         ~evidence->tmr_memory_physical_frame_distance_02) ||
        (evidence->tmr_memory_physical_frame_distance_12_inverse !=
         ~evidence->tmr_memory_physical_frame_distance_12) ||
        (evidence->tmr_memory_physical_frame_pair_coverage_inverse !=
         ~evidence->tmr_memory_physical_frame_pair_coverage) ||
        (evidence->tmr_memory_physical_frame_fingerprint_inverse !=
         ~evidence->tmr_memory_physical_frame_fingerprint) ||
        !llps_control_flag_value_is_valid(evidence->tmr_memory_resident) ||
        !llps_control_flag_value_is_valid(
             evidence->tmr_memory_physical_frames_distinct) ||
        !llps_control_flag_value_is_valid(
             evidence->tmr_memory_physical_frames_spaced)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_physical_domain_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->physical_domain_observation_fingerprint_inverse !=
         ~evidence->physical_domain_observation_fingerprint) ||
        (evidence->physical_domain_topology_coverage_inverse !=
         ~evidence->physical_domain_topology_coverage) ||
        (evidence->physical_domain_observed_count_inverse !=
         ~evidence->physical_domain_observed_count) ||
        (evidence->physical_domain_memtotal_kib_inverse !=
         ~evidence->physical_domain_memtotal_kib) ||
        (evidence->physical_domain_distance_entries_inverse !=
         ~evidence->physical_domain_distance_entries) ||
        (evidence->physical_domain_distance_sum_inverse !=
         ~evidence->physical_domain_distance_sum) ||
        (evidence->physical_domain_distance_pair_coverage_inverse !=
         ~evidence->physical_domain_distance_pair_coverage) ||
        (evidence->physical_domain_distance_01_inverse !=
         ~evidence->physical_domain_distance_01) ||
        (evidence->physical_domain_distance_02_inverse !=
         ~evidence->physical_domain_distance_02) ||
        (evidence->physical_domain_distance_12_inverse !=
         ~evidence->physical_domain_distance_12) ||
        (evidence->tmr_memory_domain_observation_fingerprint_inverse !=
         ~evidence->tmr_memory_domain_observation_fingerprint) ||
        (evidence->tmr_memory_domain_pages_checked_inverse !=
         ~evidence->tmr_memory_domain_pages_checked) ||
        (evidence->tmr_memory_domain_mismatch_count_inverse !=
         ~evidence->tmr_memory_domain_mismatch_count) ||
        (evidence->tmr_memory_domain_probe_failures_inverse !=
         ~evidence->tmr_memory_domain_probe_failures) ||
        (evidence->tmr_memory_domain_region_coverage_inverse !=
         ~evidence->tmr_memory_domain_region_coverage) ||
        !llps_platform_domain_inverses_are_valid(
             evidence->tmr_memory_observed_domain_ids,
             evidence->tmr_memory_observed_domain_ids_inverse) ||
        !llps_platform_domain_inverses_are_valid(
             evidence->physical_memory_domain_ids,
             evidence->physical_memory_domain_ids_inverse)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_physical_domain_absence_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) {
        return true;
    }

    if (!llps_domain_ids_are_zero(evidence->physical_memory_domain_ids) ||
        (evidence->physical_domain_observation_fingerprint != 0u) ||
        (evidence->physical_domain_topology_coverage != 0u) ||
        (evidence->physical_domain_observed_count != 0u) ||
        (evidence->physical_domain_memtotal_kib != 0u) ||
        (evidence->physical_domain_distance_entries != 0u) ||
        (evidence->physical_domain_distance_sum != 0u) ||
        (evidence->physical_domain_distance_pair_coverage != 0u) ||
        (evidence->physical_domain_distance_01 != 0u) ||
        (evidence->physical_domain_distance_02 != 0u) ||
        (evidence->physical_domain_distance_12 != 0u) ||
        (evidence->tmr_memory_domain_observation_fingerprint != 0u) ||
        (evidence->tmr_memory_domain_pages_checked != 0u) ||
        (evidence->tmr_memory_domain_mismatch_count != 0u) ||
        (evidence->tmr_memory_domain_probe_failures != 0u) ||
        (evidence->tmr_memory_domain_region_coverage != 0u) ||
        !llps_domain_ids_are_zero(evidence->tmr_memory_observed_domain_ids)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_hardware_tmr_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->attested_flags_inverse != ~evidence->attested_flags) ||
        (evidence->attestation_fingerprint_inverse !=
         ~evidence->attestation_fingerprint) ||
        !llps_platform_domain_inverses_are_valid(
             evidence->hardware_tmr_domain_ids,
             evidence->hardware_tmr_domain_ids_inverse) ||
        (evidence->hardware_tmr_voter_domain_id_inverse !=
         ~evidence->hardware_tmr_voter_domain_id)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_hardware_tmr_absence_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) {
        return true;
    }

    if (!llps_domain_ids_are_zero(evidence->hardware_tmr_domain_ids) ||
        (evidence->hardware_tmr_voter_domain_id != 0u)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence,
    const uint32_t effective_flags,
    const uint32_t known_flags) {
    if (!llps_platform_evidence_header_is_valid(evidence,
                                                effective_flags,
                                                known_flags)) {
        return false;
    }

    if (!llps_platform_evidence_edac_shape_is_valid(evidence) ||
        !llps_platform_evidence_runtime_latches_shape_is_valid(evidence) ||
        !llps_platform_evidence_software_shape_is_valid(evidence) ||
        !llps_platform_evidence_tmr_memory_shape_is_valid(evidence) ||
        !llps_platform_evidence_physical_domain_shape_is_valid(evidence) ||
        !llps_platform_evidence_physical_domain_absence_is_valid(evidence) ||
        !llps_platform_evidence_hardware_tmr_shape_is_valid(evidence) ||
        !llps_platform_evidence_hardware_tmr_absence_is_valid(evidence) ||
        !llps_platform_evidence_mac_shape_is_valid(evidence)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_matches_tmr_physical_frames(
    const llps_platform_safety_evidence_t * const evidence) {
    bool current_frames_distinct = false;
    bool current_frames_spaced = false;
    uint64_t current_frame_pages = 0u;
    uint64_t current_frame_probe_failures = 0u;
    uint64_t current_frame_min_distance = 0u;
    uint64_t current_frame_required_distance = 0u;
    uint64_t current_frame_distance_01 = 0u;
    uint64_t current_frame_distance_02 = 0u;
    uint64_t current_frame_distance_12 = 0u;
    uint32_t current_frame_pair_coverage = 0u;
    uint32_t current_frame_fingerprint = 0u;

    llps_observe_tmr_physical_frames(&current_frames_distinct,
                                     &current_frames_spaced,
                                     &current_frame_pages,
                                     &current_frame_probe_failures,
                                     &current_frame_min_distance,
                                     &current_frame_required_distance,
                                     &current_frame_distance_01,
                                     &current_frame_distance_02,
                                     &current_frame_distance_12,
                                     &current_frame_pair_coverage,
                                     &current_frame_fingerprint);
    return (evidence->tmr_memory_physical_frames_distinct ==
            llps_bool_to_u32(current_frames_distinct)) &&
           (evidence->tmr_memory_physical_frames_spaced ==
            llps_bool_to_u32(current_frames_spaced)) &&
           (evidence->tmr_memory_physical_frame_pages == current_frame_pages) &&
           (evidence->tmr_memory_physical_frame_probe_failures ==
            current_frame_probe_failures) &&
           (evidence->tmr_memory_physical_frame_min_distance ==
            current_frame_min_distance) &&
           (evidence->tmr_memory_physical_frame_required_distance ==
            current_frame_required_distance) &&
           (evidence->tmr_memory_physical_frame_distance_01 ==
            current_frame_distance_01) &&
           (evidence->tmr_memory_physical_frame_distance_02 ==
            current_frame_distance_02) &&
           (evidence->tmr_memory_physical_frame_distance_12 ==
            current_frame_distance_12) &&
           (evidence->tmr_memory_physical_frame_pair_coverage ==
            current_frame_pair_coverage) &&
           (evidence->tmr_memory_physical_frame_fingerprint ==
            current_frame_fingerprint);
}

static bool llps_platform_evidence_matches_tmr_memory(
    const llps_platform_safety_evidence_t * const evidence) {
    bool current_resident = false;
    uint64_t current_resident_pages = 0u;
    uint32_t current_residency_fingerprint = 0u;

    llps_observe_tmr_memory_residency(&current_resident,
                                      &current_resident_pages,
                                      &current_residency_fingerprint);
    if ((evidence->tmr_memory_resident !=
         llps_bool_to_u32(current_resident)) ||
        (evidence->tmr_memory_resident_pages != current_resident_pages) ||
        (evidence->tmr_memory_residency_fingerprint !=
         current_residency_fingerprint)) {
        return false;
    }

    return llps_platform_evidence_matches_tmr_physical_frames(evidence);
}

static bool llps_platform_evidence_matches_platform_identity(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    const uint32_t current_boot_fingerprint =
        llps_platform_boot_fingerprint(context->boot_id_path);
    uint32_t current_identity_fingerprint =
        llps_platform_identity_fingerprint(context->platform_id_path);
    const uint32_t current_executable_fingerprint =
        llps_platform_executable_image_fingerprint(
            context->executable_image_path);

    if ((current_identity_fingerprint == 0u) &&
        (context->platform_evidence_mode ==
         LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC)) {
        current_identity_fingerprint =
            llps_platform_synthetic_identity_fingerprint(
                evidence->evidence_id,
                context->software_ecc_enabled,
                context->software_ecc_controller_count,
                context->software_ecc_dimm_count,
                context->software_ecc_scrub_rate,
                context->software_ecc_controller_corrected_error_count,
                context->software_ecc_controller_uncorrected_error_count,
                context->software_ecc_dimm_corrected_error_count,
                context->software_ecc_dimm_uncorrected_error_count,
                context->software_numa_enabled,
                context->software_numa_memtotal_kib,
                context->software_numa_local_distance,
                context->software_numa_remote_distance,
                context->software_fault_injection_mode,
                evidence->physical_memory_domain_ids,
                evidence->hardware_tmr_domain_ids,
                evidence->hardware_tmr_voter_domain_id);
    }

    if ((evidence->platform_boot_fingerprint != current_boot_fingerprint) ||
        (evidence->platform_identity_fingerprint !=
         current_identity_fingerprint) ||
        (evidence->executable_image_fingerprint !=
         current_executable_fingerprint)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_matches_runtime_latches(
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t current_coverage = 0u;
    const uint32_t current_process_memory_locked =
        llps_bool_to_u32(llps_guarded_bool_read(g_process_memory_locked,
                                                g_process_memory_locked_inverse));
    const uint32_t current_tmr_memory_locked =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_locked,
                                                g_tmr_memory_locked_inverse));
    const uint32_t current_tmr_memory_prefaulted =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_prefaulted,
                                                g_tmr_memory_prefaulted_inverse));
    const uint64_t current_tmr_memory_prefault_pages =
        llps_tmr_memory_prefault_pages_read();
    const uint32_t current_tmr_memory_hardened =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_hardened,
                                                g_tmr_memory_hardened_inverse));
    const uint32_t current_self_test_passed =
        llps_bool_to_u32(llps_guarded_bool_read(
            g_tmr_startup_self_test_passed,
            g_tmr_startup_self_test_passed_inverse));

    if (llps_tmr_startup_self_test_coverage_is_valid()) {
        current_coverage = g_tmr_startup_self_test_coverage;
    }

    if ((evidence->process_memory_locked != current_process_memory_locked) ||
        (evidence->tmr_memory_locked != current_tmr_memory_locked) ||
        (evidence->tmr_memory_prefaulted != current_tmr_memory_prefaulted) ||
        (evidence->tmr_memory_prefault_pages !=
         current_tmr_memory_prefault_pages) ||
        (evidence->tmr_memory_hardened != current_tmr_memory_hardened) ||
        (evidence->tmr_startup_self_test_passed != current_self_test_passed) ||
        (evidence->tmr_startup_self_test_coverage != current_coverage) ||
        (evidence->tmr_startup_self_test_required_coverage !=
         LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE)) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_software_absent_matches(
    const llps_platform_safety_evidence_t * const evidence,
    const llps_software_evidence_observation_t * const observation) {
    return (evidence != NULL) &&
           (observation != NULL) &&
           !observation->required &&
           (evidence->software_evidence_self_test_passed == 0u) &&
           (evidence->software_evidence_schema_version == 0u) &&
           (evidence->software_evidence_self_test_coverage == 0u) &&
           (evidence->software_evidence_self_test_required_coverage == 0u) &&
           (evidence->software_ecc_controller_count == 0u) &&
           (evidence->software_dimm_bank_count == 0u) &&
           (evidence->software_ecc_scrub_rate == 0u) &&
           (evidence->software_dimm_generation == 0u) &&
           (evidence->software_dimm_scrub_generation == 0u) &&
           (evidence->software_dimm_fault_injection_coverage == 0u) &&
           (evidence->software_fault_injection_mode ==
            LLPS_SOFTWARE_FAULT_INJECTION_OFF) &&
           (evidence->software_dimm_observation_fingerprint == 0u) &&
           (evidence->software_numa_profile_fingerprint == 0u);
}

static bool llps_platform_evidence_software_ready_matches(
    const llps_platform_safety_evidence_t * const evidence,
    const llps_software_evidence_observation_t * const observation) {
    return (evidence != NULL) &&
           (observation != NULL) &&
           (evidence->software_evidence_self_test_passed ==
            (observation->passed ? 1u : 0u)) &&
           (evidence->software_evidence_schema_version ==
            observation->schema_version) &&
           (evidence->software_evidence_self_test_coverage ==
            observation->coverage) &&
           (evidence->software_evidence_self_test_required_coverage ==
            observation->required_coverage) &&
           (evidence->software_ecc_controller_count ==
            observation->controller_count) &&
           (evidence->software_dimm_bank_count == observation->bank_count) &&
           (evidence->software_ecc_scrub_rate == observation->scrub_rate) &&
           (evidence->software_dimm_generation == observation->generation) &&
           (evidence->software_dimm_scrub_generation ==
            observation->scrub_generation) &&
           (evidence->software_dimm_fault_injection_coverage ==
            observation->fault_injection_coverage) &&
           (evidence->software_fault_injection_mode ==
            observation->fault_injection_mode) &&
           (evidence->software_dimm_observation_fingerprint ==
            observation->fingerprint) &&
           (evidence->software_numa_profile_fingerprint ==
            observation->numa_profile_fingerprint);
}

static bool llps_platform_evidence_matches_software_evidence(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    llps_software_evidence_observation_t observation;

    if ((context == NULL) || (evidence == NULL)) {
        return false;
    }

    if (evidence->platform_evidence_mode != context->platform_evidence_mode) {
        return false;
    }

    llps_software_evidence_observe(context->platform_evidence_mode,
                                   context->software_ecc_enabled,
                                   context->software_ecc_controller_count,
                                   context->software_ecc_dimm_count,
                                   context->software_ecc_scrub_rate,
                                   context->software_numa_enabled,
                                   context->software_numa_memtotal_kib,
                                   context->software_numa_local_distance,
                                   context->software_numa_remote_distance,
                                   context->software_fault_injection_mode,
                                   evidence->physical_memory_domain_ids,
                                   &observation);

    if (!llps_software_evidence_observation_is_ready(&observation)) {
        return llps_platform_evidence_software_absent_matches(evidence,
                                                              &observation);
    }

    return llps_platform_evidence_software_ready_matches(evidence,
                                                         &observation);
}

static bool llps_platform_evidence_context_uses_software_ecc(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    return (context != NULL) &&
           (evidence != NULL) &&
           context->software_ecc_enabled &&
           llps_platform_evidence_mode_uses_software(
               context->platform_evidence_mode) &&
           (evidence->software_evidence_schema_version ==
            LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION) &&
           (evidence->software_evidence_self_test_passed == 1u);
}

static bool llps_platform_evidence_context_uses_software_numa(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    return (context != NULL) &&
           (evidence != NULL) &&
           context->software_numa_enabled &&
           llps_platform_evidence_mode_uses_software(
               context->platform_evidence_mode) &&
           (evidence->software_evidence_schema_version ==
            LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION) &&
           (evidence->software_evidence_self_test_passed == 1u);
}

static bool llps_platform_evidence_edac_observation_matches(
    const llps_platform_safety_evidence_t * const evidence,
    const uint32_t current_observed_flags,
    const uint32_t current_fingerprint,
    const llps_edac_observation_t * const current_observation) {
    return (evidence != NULL) &&
           (current_observation != NULL) &&
           (evidence->observed_flags == current_observed_flags) &&
           (evidence->edac_observation_fingerprint == current_fingerprint) &&
           (evidence->edac_controller_count ==
            current_observation->controller_count) &&
           (evidence->edac_dimm_count == current_observation->dimm_count) &&
           (evidence->edac_scrub_rate_count ==
            current_observation->scrub_rate_count) &&
           (evidence->edac_controller_counter_coverage ==
            current_observation->controller_counter_coverage) &&
           (evidence->edac_dimm_mode_coverage ==
            current_observation->dimm_mode_coverage) &&
           (evidence->edac_dimm_counter_coverage ==
            current_observation->dimm_counter_coverage) &&
           (evidence->edac_scrub_rate_coverage ==
            current_observation->scrub_rate_coverage) &&
           (evidence->edac_corrected_error_count ==
            current_observation->corrected_error_count) &&
           (evidence->edac_uncorrected_error_count ==
            current_observation->uncorrected_error_count) &&
           (evidence->edac_dimm_corrected_error_count ==
            current_observation->dimm_corrected_error_count) &&
           (evidence->edac_dimm_uncorrected_error_count ==
            current_observation->dimm_uncorrected_error_count) &&
           (evidence->edac_scrub_rate_sum ==
            current_observation->scrub_rate_sum);
}

static bool llps_platform_evidence_matches_edac(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    bool current_ecc_present = false;
    bool current_ecc_clean = false;
    uint32_t current_fingerprint = 0u;
    uint32_t current_observed_flags = 0u;
    llps_edac_observation_t current_observation = { 0 };

    if (evidence->observed_flags == 0u) {
        return true;
    }

    if (llps_platform_evidence_context_uses_software_ecc(context, evidence)) {
        llps_edac_synthesize_ecc(context->software_ecc_controller_count,
                                 context->software_ecc_dimm_count,
                                 context->software_ecc_scrub_rate,
                                 context->software_ecc_controller_corrected_error_count,
                                 context->software_ecc_controller_uncorrected_error_count,
                                 context->software_ecc_dimm_corrected_error_count,
                                 context->software_ecc_dimm_uncorrected_error_count,
                                 &current_ecc_present,
                                 &current_ecc_clean,
                                 &current_fingerprint,
                                 &current_observation);
    } else if (context->platform_evidence_mode !=
               LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
        llps_edac_probe_ecc(context->edac_sysfs_root,
                            &current_ecc_present,
                            &current_ecc_clean,
                            &current_fingerprint,
                            &current_observation);
    }
    current_observed_flags =
        llps_edac_observed_flags(current_ecc_present, current_ecc_clean);

    return llps_platform_evidence_edac_observation_matches(
        evidence,
        current_observed_flags,
        current_fingerprint,
        &current_observation);
}

typedef struct {
    bool observed;
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
} llps_platform_physical_domain_observation_t;

typedef struct {
    bool bound;
    uint32_t fingerprint;
    uint64_t pages_checked;
    uint64_t mismatch_count;
    uint64_t probe_failures;
    uint32_t region_coverage;
    uint32_t observed_domains[LLPS_SESSION_TMR_BANK_COUNT];
} llps_platform_tmr_domain_observation_t;

static void llps_platform_evidence_observe_physical_domains(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence,
    llps_platform_physical_domain_observation_t * const current) {
    if ((context == NULL) || (evidence == NULL) || (current == NULL)) {
        return;
    }

    if (llps_platform_evidence_context_uses_software_numa(context, evidence)) {
        llps_numa_synthesize_physical_memory_domains(
            evidence->physical_memory_domain_ids,
            context->software_numa_memtotal_kib,
            context->software_numa_local_distance,
            context->software_numa_remote_distance,
            &current->observed,
            &current->fingerprint,
            &current->topology_coverage,
            &current->observed_count,
            &current->memtotal_kib,
            &current->distance_entries,
            &current->distance_sum,
            &current->distance_pair_coverage,
            &current->distance_01,
            &current->distance_02,
            &current->distance_12);
    } else if (context->platform_evidence_mode !=
               LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
        llps_numa_probe_physical_memory_domains(
            context->numa_sysfs_root,
            evidence->physical_memory_domain_ids,
            &current->observed,
            &current->fingerprint,
            &current->topology_coverage,
            &current->observed_count,
            &current->memtotal_kib,
            &current->distance_entries,
            &current->distance_sum,
            &current->distance_pair_coverage,
            &current->distance_01,
            &current->distance_02,
            &current->distance_12);
    }
}

static bool llps_platform_evidence_physical_domain_matches(
    const llps_platform_safety_evidence_t * const evidence,
    const llps_platform_physical_domain_observation_t * const current) {
    return (evidence != NULL) &&
           (current != NULL) &&
           current->observed &&
           (evidence->physical_domain_observation_fingerprint ==
            current->fingerprint) &&
           (evidence->physical_domain_topology_coverage ==
            current->topology_coverage) &&
           (evidence->physical_domain_observed_count ==
            current->observed_count) &&
           (evidence->physical_domain_memtotal_kib == current->memtotal_kib) &&
           (evidence->physical_domain_distance_entries ==
            current->distance_entries) &&
           (evidence->physical_domain_distance_sum == current->distance_sum) &&
           (evidence->physical_domain_distance_pair_coverage ==
            current->distance_pair_coverage) &&
           (evidence->physical_domain_distance_01 == current->distance_01) &&
           (evidence->physical_domain_distance_02 == current->distance_02) &&
           (evidence->physical_domain_distance_12 == current->distance_12);
}

static void llps_platform_evidence_observe_tmr_domains(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence,
    llps_platform_tmr_domain_observation_t * const current) {
    if ((context == NULL) || (evidence == NULL) || (current == NULL)) {
        return;
    }

    if (llps_platform_evidence_context_uses_software_numa(context, evidence)) {
        llps_synthesize_tmr_memory_domains(
            evidence->physical_memory_domain_ids,
            &current->bound,
            &current->fingerprint,
            current->observed_domains,
            &current->pages_checked,
            &current->mismatch_count,
            &current->probe_failures,
            &current->region_coverage);
    } else {
        llps_probe_tmr_memory_domains(evidence->physical_memory_domain_ids,
                                      &current->bound,
                                      &current->fingerprint,
                                      current->observed_domains,
                                      &current->pages_checked,
                                      &current->mismatch_count,
                                      &current->probe_failures,
                                      &current->region_coverage);
    }
}

static bool llps_platform_evidence_tmr_domain_matches(
    const llps_platform_safety_evidence_t * const evidence,
    const llps_platform_tmr_domain_observation_t * const current) {
    return (evidence != NULL) &&
           (current != NULL) &&
           current->bound &&
           (evidence->tmr_memory_domain_observation_fingerprint ==
            current->fingerprint) &&
           (evidence->tmr_memory_domain_pages_checked ==
            current->pages_checked) &&
           (evidence->tmr_memory_domain_mismatch_count ==
            current->mismatch_count) &&
           (evidence->tmr_memory_domain_probe_failures ==
            current->probe_failures) &&
           (evidence->tmr_memory_domain_region_coverage ==
            current->region_coverage) &&
           llps_domain_ids_match(evidence->tmr_memory_observed_domain_ids,
                                 current->observed_domains);
}

static bool llps_platform_evidence_matches_physical_domains(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    llps_platform_physical_domain_observation_t physical = { 0 };
    llps_platform_tmr_domain_observation_t tmr = { 0 };

    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) {
        return true;
    }

    if (!llps_domain_ids_are_distinct(evidence->physical_memory_domain_ids)) {
        return false;
    }

    llps_platform_evidence_observe_physical_domains(context, evidence, &physical);
    if (!llps_platform_evidence_physical_domain_matches(evidence, &physical)) {
        return false;
    }

    llps_platform_evidence_observe_tmr_domains(context, evidence, &tmr);
    return llps_platform_evidence_tmr_domain_matches(evidence, &tmr);
}

static bool llps_platform_evidence_domain_attestations_are_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    if (((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) &&
        (!llps_domain_ids_are_distinct(evidence->hardware_tmr_domain_ids) ||
         !llps_domain_id_is_disjoint_from_set(
             evidence->hardware_tmr_domain_ids,
             evidence->hardware_tmr_voter_domain_id))) {
        return false;
    }

    if ((evidence->attested_flags == LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) &&
        (!llps_domain_id_sets_are_disjoint(evidence->physical_memory_domain_ids,
                                           evidence->hardware_tmr_domain_ids) ||
         !llps_domain_id_is_disjoint_from_set(
             evidence->physical_memory_domain_ids,
             evidence->hardware_tmr_voter_domain_id))) {
        return false;
    }

    return true;
}

static bool llps_platform_evidence_attestation_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t expected_attestation_fingerprint = 0u;

    if (llps_compute_platform_attestation_fingerprint(
            evidence->attested_flags,
            evidence->evidence_id,
            evidence->physical_memory_domain_ids,
            evidence->hardware_tmr_domain_ids,
            evidence->hardware_tmr_voter_domain_id,
            &expected_attestation_fingerprint) != LLPS_OK) {
        return false;
    }

    if (evidence->attestation_fingerprint !=
        expected_attestation_fingerprint) {
        return false;
    }

    return evidence->crc ==
           llps_platform_safety_evidence_compute_crc(evidence);
}

bool llps_platform_safety_evidence_mac_is_valid_in_context(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    uint8_t expected_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint32_t key_fingerprint = 0u;

    if ((context == NULL) || (evidence == NULL)) {
        return false;
    }

    if ((context->evidence_mac_enabled ? 1u : 0u) !=
        evidence->evidence_mac_enabled) {
        return false;
    }

    if (evidence->evidence_mac_enabled == 0u) {
        for (size_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
            if (evidence->evidence_mac[i] != 0u) {
                return false;
            }
        }
        return true;
    }

    if (!llps_evidence_hmac_sha256_file(context->evidence_mac_key_path,
                                        evidence,
                                        expected_mac,
                                        &key_fingerprint) ||
        (key_fingerprint != evidence->evidence_mac_key_fingerprint)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        if (evidence->evidence_mac[i] != expected_mac[i]) {
            return false;
        }
    }

    return true;
}

bool llps_platform_safety_evidence_request_is_bound_in_context(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    if ((context == NULL) || (evidence == NULL)) {
        return false;
    }

    if ((context->configured_platform_safety_flags == 0u) ||
        (context->configured_platform_safety_evidence_id == 0u) ||
        (context->configured_platform_attestation_fingerprint == 0u)) {
        return false;
    }

    return (evidence->flags == context->configured_platform_safety_flags) &&
           (evidence->evidence_id ==
            context->configured_platform_safety_evidence_id) &&
           (evidence->attestation_fingerprint ==
            context->configured_platform_attestation_fingerprint) &&
           llps_domain_ids_match(evidence->physical_memory_domain_ids,
                                 context->configured_physical_memory_domain_ids) &&
           llps_domain_ids_match(evidence->hardware_tmr_domain_ids,
                                 context->configured_hardware_tmr_domain_ids) &&
           (evidence->hardware_tmr_voter_domain_id ==
            context->configured_hardware_tmr_voter_domain_id);
}

bool llps_platform_safety_evidence_observation_digest_is_bound_in_context(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    if ((context == NULL) || (evidence == NULL)) {
        return false;
    }

    return (context->configured_platform_observation_digest != 0u) &&
           (context->configured_platform_observation_digest ==
            evidence->observation_digest);
}

bool llps_platform_safety_evidence_is_valid_in_context(
    const llps_platform_evidence_context_t * const context,
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t known_flags = 0u;
    uint32_t effective_flags = 0u;

    if ((context == NULL) || (evidence == NULL)) {
        return false;
    }

    known_flags = llps_platform_safety_evidence_known_flags();
    effective_flags = evidence->observed_flags | evidence->attested_flags;

    if (!llps_platform_evidence_shape_is_valid(evidence,
                                               effective_flags,
                                               known_flags)) {
        return false;
    }

    if (!llps_platform_evidence_matches_tmr_memory(evidence) ||
        !llps_platform_evidence_matches_platform_identity(context, evidence) ||
        !llps_platform_evidence_matches_runtime_latches(evidence) ||
        !llps_platform_evidence_matches_software_evidence(context, evidence) ||
        !llps_platform_evidence_matches_edac(context, evidence) ||
        !llps_platform_evidence_matches_physical_domains(context, evidence) ||
        !llps_platform_evidence_domain_attestations_are_valid(evidence) ||
        !llps_platform_evidence_attestation_is_valid(evidence) ||
        !llps_platform_safety_evidence_mac_is_valid_in_context(context,
                                                               evidence)) {
        return false;
    }

    return true;
}
