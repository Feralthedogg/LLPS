/**
 * @file src/readiness/llps_readiness.c
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#include "llps_readiness.h"

#include "llps_domain.h"
#include "llps_evidence.h"
#include "llps_internal.h"
#include "llps_numa.h"
#include "llps_tmr_layout.h"
#include "llps_tmr_platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool llps_memory_report_core_guards_ready(
    const llps_memory_safety_report_t * const report) {
    return (report != NULL) &&
           report->runtime_cfg_tmr_valid &&
           report->control_flag_tmr_valid &&
           report->free_list_tmr_valid &&
           report->tmr_layout_valid &&
           report->process_memory_locked &&
           report->tmr_memory_locked &&
           report->tmr_memory_prefaulted &&
           report->tmr_memory_resident &&
           report->tmr_memory_physical_frames_distinct &&
           report->tmr_memory_physical_frames_spaced &&
           report->tmr_memory_hardened &&
           report->tmr_memory_observed_domains_valid &&
           report->tmr_startup_self_test_passed &&
           report->tmr_startup_self_test_coverage_valid &&
           report->readiness_runtime_monitor_enabled &&
           report->runtime_safety_latches_valid &&
           report->memory_safety_counters_valid &&
           report->tmr_bank_guard_valid[0] &&
           report->tmr_bank_guard_valid[1] &&
           report->tmr_bank_guard_valid[2];
}

static bool llps_memory_report_startup_coverage_ready(
    const llps_memory_safety_report_t * const report) {
    return (report != NULL) &&
           ((report->tmr_startup_self_test_coverage &
             report->tmr_startup_self_test_required_coverage) ==
            report->tmr_startup_self_test_required_coverage);
}

static bool llps_memory_report_tmr_spacing_ready(
    const llps_memory_safety_report_t * const report) {
    return (report != NULL) &&
           (report->tmr_bank_distance_01 >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES) &&
           (report->tmr_bank_distance_02 >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES) &&
           (report->tmr_bank_distance_12 >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES) &&
           (report->tmr_metadata_min_bank_distance >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
}

static bool llps_memory_report_runtime_domains_ready(
    const llps_memory_safety_report_t * const report) {
    if ((report == NULL) || !report->readiness_runtime_monitor_enabled) {
        return report != NULL;
    }
    if (!report->tmr_memory_domains_bound) {
        return false;
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (report->tmr_memory_observed_domain_ids[i] ==
            LLPS_TMR_MEMORY_DOMAIN_UNKNOWN) {
            return false;
        }
    }

    return (report->tmr_memory_domain_pages_checked != 0u) &&
           (report->tmr_memory_domain_mismatch_count == 0u) &&
           (report->tmr_memory_domain_probe_failures == 0u) &&
           ((report->tmr_memory_domain_region_coverage &
             LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) ==
            LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
}

static bool llps_memory_report_physical_frames_ready(
    const llps_memory_safety_report_t * const report) {
    return report->tmr_memory_prefault_pages_valid &&
           (report->tmr_memory_prefault_pages != 0u) &&
           (report->tmr_memory_prefault_failures == 0u) &&
           (report->tmr_memory_resident_pages != 0u) &&
           (report->tmr_memory_residency_failures == 0u) &&
           (report->tmr_memory_residency_fingerprint != 0u) &&
           (report->tmr_memory_physical_frame_faults == 0u) &&
           (report->tmr_memory_physical_frame_pages != 0u) &&
           (report->tmr_memory_physical_frame_probe_failures == 0u) &&
           (report->tmr_memory_physical_frame_required_distance != 0u) &&
           (report->tmr_memory_physical_frame_min_distance >=
            report->tmr_memory_physical_frame_required_distance) &&
           ((report->tmr_memory_physical_frame_pair_coverage &
             LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) ==
            LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) &&
           (report->tmr_memory_physical_frame_distance_01 >=
            report->tmr_memory_physical_frame_required_distance) &&
           (report->tmr_memory_physical_frame_distance_02 >=
            report->tmr_memory_physical_frame_required_distance) &&
           (report->tmr_memory_physical_frame_distance_12 >=
            report->tmr_memory_physical_frame_required_distance) &&
           (report->tmr_memory_physical_frame_fingerprint != 0u);
}

static bool llps_memory_report_tmr_domain_counters_ready(
    const llps_memory_safety_report_t * const report) {
    return (!report->readiness_runtime_monitor_enabled) ||
           ((report->tmr_memory_domain_bind_failures == 0u) &&
            (report->tmr_memory_domain_observation_fingerprint != 0u) &&
            (report->tmr_memory_domain_pages_checked != 0u) &&
            (report->tmr_memory_domain_mismatch_count == 0u) &&
            (report->tmr_memory_domain_probe_failures == 0u) &&
            ((report->tmr_memory_domain_region_coverage &
              LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) ==
             LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL));
}

static bool llps_memory_report_safety_counters_ready(
    const llps_memory_safety_report_t * const report) {
    return (report->tmr_majority_failures == 0u) &&
           (report->tmr_layout_failures == 0u) &&
           (report->process_memory_lock_failures == 0u) &&
           (report->tmr_memory_lock_failures == 0u) &&
           (report->memory_safety_counters_fingerprint != 0u) &&
           (report->tmr_scrub_passes != 0u) &&
           (report->tmr_scrub_sessions_checked != 0u) &&
           (report->tmr_scrub_fail_closed_sessions == 0u) &&
           llps_memory_report_tmr_domain_counters_ready(report) &&
           (report->tmr_memory_harden_failures == 0u) &&
           (report->contract_violations == 0u) &&
           (report->free_list_majority_failures == 0u) &&
           (report->runtime_cfg_majority_failures == 0u) &&
           (report->control_flag_majority_failures == 0u);
}

static bool llps_memory_report_runtime_failures_clear(
    const llps_memory_safety_report_t * const report) {
    return (report->readiness_runtime_monitor_failures == 0u) &&
           (report->readiness_runtime_cfg_failures == 0u) &&
           (report->readiness_runtime_software_tmr_failures == 0u) &&
           (report->readiness_runtime_ecc_failures == 0u) &&
           (report->readiness_runtime_physical_domain_failures == 0u) &&
           (report->readiness_runtime_tmr_memory_domain_failures == 0u) &&
           (report->readiness_runtime_hardware_tmr_failures == 0u) &&
           (report->readiness_runtime_identity_failures == 0u) &&
           (report->readiness_runtime_attestation_failures == 0u) &&
           (report->readiness_runtime_observation_digest_failures == 0u);
}

static bool llps_memory_safety_report_is_software_ready(
    const llps_memory_safety_report_t * const report) {
    return llps_memory_report_core_guards_ready(report) &&
           llps_memory_report_startup_coverage_ready(report) &&
           llps_memory_report_tmr_spacing_ready(report) &&
           llps_memory_report_runtime_domains_ready(report) &&
           llps_memory_report_physical_frames_ready(report) &&
           llps_memory_report_safety_counters_ready(report) &&
           llps_memory_report_runtime_failures_clear(report);
}

static bool llps_context_requires_payload_ecc(
    const llps_platform_evidence_context_t * const context) {
    return (context != NULL) &&
           ((context->platform_evidence_mode ==
             LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) ||
            (context->platform_evidence_mode ==
             LLPS_PLATFORM_EVIDENCE_MODE_HYBRID)) &&
           context->software_ecc_enabled;
}

bool llps_evidence_platform_snapshot_is_software_ready(
    const llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return false;
    }

    return (evidence->process_memory_locked == 1u) &&
           (evidence->tmr_memory_locked == 1u) &&
           (evidence->tmr_memory_prefaulted == 1u) &&
           (evidence->tmr_memory_prefault_pages != 0u) &&
           (evidence->tmr_memory_hardened == 1u) &&
           (evidence->tmr_startup_self_test_passed == 1u) &&
           (evidence->tmr_startup_self_test_coverage ==
            LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE) &&
           (evidence->tmr_startup_self_test_required_coverage ==
            LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE) &&
           (evidence->tmr_memory_resident == 1u) &&
           (evidence->tmr_memory_resident_pages != 0u) &&
           (evidence->tmr_memory_residency_fingerprint != 0u) &&
           (evidence->tmr_memory_physical_frames_distinct == 1u) &&
           (evidence->tmr_memory_physical_frames_spaced == 1u) &&
           (evidence->tmr_memory_physical_frame_pages != 0u) &&
           (evidence->tmr_memory_physical_frame_probe_failures == 0u) &&
           (evidence->tmr_memory_physical_frame_required_distance != 0u) &&
           (evidence->tmr_memory_physical_frame_min_distance >=
            evidence->tmr_memory_physical_frame_required_distance) &&
           ((evidence->tmr_memory_physical_frame_pair_coverage &
             LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) ==
            LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) &&
           (evidence->tmr_memory_physical_frame_distance_01 >=
            evidence->tmr_memory_physical_frame_required_distance) &&
           (evidence->tmr_memory_physical_frame_distance_02 >=
            evidence->tmr_memory_physical_frame_required_distance) &&
           (evidence->tmr_memory_physical_frame_distance_12 >=
            evidence->tmr_memory_physical_frame_required_distance) &&
           (evidence->tmr_memory_physical_frame_fingerprint != 0u) &&
           (evidence->tmr_layout_fingerprint == llps_tmr_layout_fingerprint());
}

bool llps_evidence_platform_snapshot_has_identity(
    const llps_platform_safety_evidence_t * const evidence) {
    return (evidence != NULL) &&
           (evidence->platform_boot_fingerprint != 0u) &&
           (evidence->platform_identity_fingerprint != 0u) &&
           (evidence->executable_image_fingerprint != 0u);
}

static bool llps_evidence_physical_domain_distance_shape_is_valid(
    const llps_platform_safety_evidence_t * const evidence) {
    uint64_t pair_sum = 0u;

    if (evidence == NULL) {
        return false;
    }

    if ((evidence->physical_domain_distance_entries <
         LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN) ||
        (evidence->physical_domain_distance_entries == UINT64_MAX) ||
        (evidence->physical_domain_distance_sum == 0u) ||
        (evidence->physical_domain_distance_sum == UINT64_MAX) ||
        ((evidence->physical_domain_distance_pair_coverage &
          LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL) !=
         LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL) ||
        (evidence->physical_domain_distance_01 == 0u) ||
        (evidence->physical_domain_distance_02 == 0u) ||
        (evidence->physical_domain_distance_12 == 0u)) {
        return false;
    }

    if ((UINT64_MAX - evidence->physical_domain_distance_01) <
        evidence->physical_domain_distance_02) {
        return false;
    }

    pair_sum = evidence->physical_domain_distance_01 +
               evidence->physical_domain_distance_02;
    if ((UINT64_MAX - pair_sum) <
        evidence->physical_domain_distance_12) {
        return false;
    }

    pair_sum += evidence->physical_domain_distance_12;
    if (pair_sum > (UINT64_MAX / 2u)) {
        return false;
    }

    return evidence->physical_domain_distance_sum >= (pair_sum * 2u);
}

bool llps_evidence_platform_snapshot_has_physical_domain_binding(
    const llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return false;
    }
    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) {
        return true;
    }

    return llps_domain_ids_are_distinct(evidence->physical_memory_domain_ids) &&
           (evidence->physical_domain_observation_fingerprint != 0u) &&
           ((evidence->physical_domain_topology_coverage &
             LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) ==
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) &&
           (evidence->physical_domain_observed_count ==
            LLPS_SESSION_TMR_BANK_COUNT) &&
           (evidence->physical_domain_memtotal_kib != 0u) &&
           llps_evidence_physical_domain_distance_shape_is_valid(evidence);
}

bool llps_evidence_platform_snapshot_has_tmr_domain_binding(
    const llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return false;
    }
    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) {
        return true;
    }

    return (evidence->tmr_memory_domain_observation_fingerprint != 0u) &&
           (evidence->tmr_memory_domain_pages_checked != 0u) &&
           (evidence->tmr_memory_domain_mismatch_count == 0u) &&
           (evidence->tmr_memory_domain_probe_failures == 0u) &&
           ((evidence->tmr_memory_domain_region_coverage &
             LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) ==
            LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) &&
           llps_platform_domain_inverses_are_valid(
               evidence->tmr_memory_observed_domain_ids,
               evidence->tmr_memory_observed_domain_ids_inverse) &&
           llps_domain_ids_match(evidence->tmr_memory_observed_domain_ids,
                                 evidence->physical_memory_domain_ids);
}

bool llps_evidence_platform_snapshot_has_hardware_tmr(
    const llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return false;
    }
    if ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) == 0u) {
        return true;
    }

    return llps_domain_ids_are_distinct(evidence->hardware_tmr_domain_ids) &&
           llps_domain_id_is_disjoint_from_set(
               evidence->hardware_tmr_domain_ids,
               evidence->hardware_tmr_voter_domain_id) &&
           llps_domain_id_sets_are_disjoint(evidence->physical_memory_domain_ids,
                                            evidence->hardware_tmr_domain_ids) &&
           llps_domain_id_is_disjoint_from_set(
               evidence->physical_memory_domain_ids,
	               evidence->hardware_tmr_voter_domain_id);
}

static uint32_t llps_readiness_missing_invalid_evidence_mask(void) {
    return LLPS_READINESS_MISSING_EVIDENCE_VALID |
           LLPS_READINESS_MISSING_ECC_MEMORY |
           LLPS_READINESS_MISSING_ECC_CLEAN |
           LLPS_READINESS_MISSING_PHYS_SEP |
           LLPS_READINESS_MISSING_HW_TMR |
           LLPS_READINESS_MISSING_LAYOUT_BINDING |
           LLPS_READINESS_MISSING_ATTESTATION_BINDING |
           LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING |
           LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING |
           LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING |
           LLPS_READINESS_MISSING_BOOT_BINDING |
           LLPS_READINESS_MISSING_PLATFORM_ID_BINDING |
           LLPS_READINESS_MISSING_EXECUTABLE_BINDING |
           LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST;
}

static void llps_readiness_report_fill_basics(
    const llps_platform_evidence_context_t * const context,
    const llps_memory_safety_report_t * const memory_report,
    const llps_platform_safety_evidence_t * const evidence,
    llps_readiness_report_t * const report,
    uint32_t * const missing) {
    report->memory = *memory_report;
    report->software_tmr_ready =
        llps_memory_safety_report_is_software_ready(&report->memory);
    report->evidence_mac_valid =
        llps_platform_safety_evidence_mac_is_valid_in_context(context,
                                                              evidence);
    report->payload_ecc_ready =
        !llps_context_requires_payload_ecc(context) ||
        context->payload_ecc_enabled;
    report->configured_evidence_request_bound =
        llps_platform_safety_evidence_request_is_bound_in_context(context,
                                                                  evidence);
    report->configured_platform_observation_digest_bound =
        llps_platform_safety_evidence_observation_digest_is_bound_in_context(
            context,
            evidence);
    if (!report->software_tmr_ready) {
        *missing |= LLPS_READINESS_MISSING_SOFTWARE_TMR;
    }
    if (!report->memory.readiness_runtime_monitor_enabled) {
        *missing |= LLPS_READINESS_MISSING_RUNTIME_MONITOR;
    }
}

static void llps_readiness_report_fill_edac(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->ecc_memory_ready =
        (evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) != 0u;
    report->ecc_counters_clean =
        (evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u;
    report->edac_controller_count = evidence->edac_controller_count;
    report->edac_dimm_count = evidence->edac_dimm_count;
    report->edac_scrub_rate_count = evidence->edac_scrub_rate_count;
    report->edac_controller_counter_coverage =
        evidence->edac_controller_counter_coverage != 0u;
    report->edac_dimm_mode_coverage =
        evidence->edac_dimm_mode_coverage != 0u;
    report->edac_dimm_counter_coverage =
        evidence->edac_dimm_counter_coverage != 0u;
    report->edac_scrub_rate_coverage =
        evidence->edac_scrub_rate_coverage != 0u;
    report->edac_corrected_error_count = evidence->edac_corrected_error_count;
    report->edac_uncorrected_error_count =
        evidence->edac_uncorrected_error_count;
    report->edac_dimm_corrected_error_count =
        evidence->edac_dimm_corrected_error_count;
    report->edac_dimm_uncorrected_error_count =
        evidence->edac_dimm_uncorrected_error_count;
    report->edac_scrub_rate_sum = evidence->edac_scrub_rate_sum;
}

static void llps_readiness_report_fill_domain_independence(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->physical_memory_domains_distinct =
        llps_domain_ids_are_distinct(evidence->physical_memory_domain_ids);
    report->hardware_tmr_domains_distinct =
        llps_domain_ids_are_distinct(evidence->hardware_tmr_domain_ids);
    report->hardware_tmr_voter_domain_independent =
        llps_domain_id_is_disjoint_from_set(
            evidence->hardware_tmr_domain_ids,
            evidence->hardware_tmr_voter_domain_id);
    report->hardware_tmr_domains_independent =
        llps_domain_id_sets_are_disjoint(evidence->physical_memory_domain_ids,
                                         evidence->hardware_tmr_domain_ids) &&
        llps_domain_id_is_disjoint_from_set(
            evidence->physical_memory_domain_ids,
            evidence->hardware_tmr_voter_domain_id);
}

static void llps_readiness_report_fill_binding_flags(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->platform_evidence_layout_bound =
        evidence->tmr_layout_fingerprint == llps_tmr_layout_fingerprint();
    report->platform_evidence_edac_bound =
        (evidence->edac_observation_fingerprint != 0u) &&
        report->edac_dimm_mode_coverage &&
        report->edac_scrub_rate_coverage &&
        (evidence->observed_flags != 0u);
    report->platform_evidence_physical_domain_bound =
        ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) ||
        ((evidence->physical_domain_observation_fingerprint != 0u) &&
         ((evidence->physical_domain_topology_coverage &
           LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) ==
          LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) &&
         (evidence->physical_domain_observed_count ==
          LLPS_SESSION_TMR_BANK_COUNT) &&
         (evidence->physical_domain_memtotal_kib != 0u) &&
         llps_evidence_physical_domain_distance_shape_is_valid(evidence));
}

static void llps_readiness_report_fill_tmr_domain_binding(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->platform_evidence_tmr_memory_domain_bound =
        ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) ||
        ((evidence->tmr_memory_domain_observation_fingerprint != 0u) &&
         (evidence->tmr_memory_domain_pages_checked != 0u) &&
         (evidence->tmr_memory_domain_mismatch_count == 0u) &&
         (evidence->tmr_memory_domain_probe_failures == 0u) &&
         ((evidence->tmr_memory_domain_region_coverage &
           LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) ==
          LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) &&
         llps_platform_domain_inverses_are_valid(
             evidence->tmr_memory_observed_domain_ids,
             evidence->tmr_memory_observed_domain_ids_inverse) &&
         llps_domain_ids_match(evidence->tmr_memory_observed_domain_ids,
                               evidence->physical_memory_domain_ids));
}

static void llps_readiness_report_fill_identity(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->platform_attestation_bound =
        evidence->attestation_fingerprint != 0u;
    report->platform_boot_bound = evidence->platform_boot_fingerprint != 0u;
    report->platform_identity_bound =
        evidence->platform_identity_fingerprint != 0u;
    report->executable_image_bound =
        evidence->executable_image_fingerprint != 0u;
    report->platform_evidence_boot_fingerprint =
        evidence->platform_boot_fingerprint;
    report->platform_evidence_identity_fingerprint =
        evidence->platform_identity_fingerprint;
    report->executable_image_fingerprint =
        evidence->executable_image_fingerprint;
    report->platform_evidence_observation_digest = evidence->observation_digest;
    report->platform_evidence_mode = evidence->platform_evidence_mode;
}

static bool llps_readiness_software_self_test_ready(
    const llps_platform_safety_evidence_t * const evidence) {
    return (evidence->software_evidence_self_test_required_coverage == 0u) ||
           ((evidence->software_evidence_self_test_passed == 1u) &&
            (evidence->software_evidence_schema_version ==
             LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION) &&
            ((evidence->software_evidence_self_test_coverage &
              evidence->software_evidence_self_test_required_coverage) ==
             evidence->software_evidence_self_test_required_coverage) &&
            (evidence->software_dimm_observation_fingerprint != 0u) &&
            (((evidence->software_evidence_self_test_required_coverage &
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING) == 0u) ||
             (evidence->software_numa_profile_fingerprint != 0u)));
}

static void llps_readiness_report_fill_software_evidence(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->software_evidence_self_test_ready =
        llps_readiness_software_self_test_ready(evidence);
    report->software_evidence_schema_version =
        evidence->software_evidence_schema_version;
    report->software_evidence_self_test_coverage =
        evidence->software_evidence_self_test_coverage;
    report->software_evidence_self_test_required_coverage =
        evidence->software_evidence_self_test_required_coverage;
    report->software_ecc_controller_count =
        evidence->software_ecc_controller_count;
    report->software_dimm_bank_count = evidence->software_dimm_bank_count;
    report->software_ecc_scrub_rate = evidence->software_ecc_scrub_rate;
    report->software_dimm_generation = evidence->software_dimm_generation;
    report->software_dimm_scrub_generation =
        evidence->software_dimm_scrub_generation;
    report->software_dimm_fault_injection_coverage =
        evidence->software_dimm_fault_injection_coverage;
    report->software_fault_injection_mode =
        evidence->software_fault_injection_mode;
    report->software_dimm_observation_fingerprint =
        evidence->software_dimm_observation_fingerprint;
    report->software_numa_profile_fingerprint =
        evidence->software_numa_profile_fingerprint;
    report->evidence_mac_key_fingerprint =
        evidence->evidence_mac_key_fingerprint;
}

static void llps_readiness_report_fill_physical_domain(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->hardware_tmr_voter_domain_id =
        evidence->hardware_tmr_voter_domain_id;
    report->physical_domain_topology_coverage =
        evidence->physical_domain_topology_coverage;
    report->physical_domain_observed_count =
        evidence->physical_domain_observed_count;
    report->physical_domain_memtotal_kib =
        evidence->physical_domain_memtotal_kib;
    report->physical_domain_distance_entries =
        evidence->physical_domain_distance_entries;
    report->physical_domain_distance_sum =
        evidence->physical_domain_distance_sum;
    report->physical_domain_distance_pair_coverage =
        evidence->physical_domain_distance_pair_coverage;
    report->physical_domain_distance_01 = evidence->physical_domain_distance_01;
    report->physical_domain_distance_02 = evidence->physical_domain_distance_02;
    report->physical_domain_distance_12 = evidence->physical_domain_distance_12;
}

static void llps_readiness_report_fill_ready_flags(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence) {
    report->physical_memory_separation_ready =
        ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) &&
        report->physical_memory_domains_distinct &&
        report->platform_evidence_physical_domain_bound &&
        report->platform_evidence_tmr_memory_domain_bound;
    report->independent_hardware_tmr_ready =
        ((evidence->attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) &&
        report->hardware_tmr_domains_distinct &&
        report->hardware_tmr_voter_domain_independent &&
        report->hardware_tmr_domains_independent;
}

static void llps_readiness_report_add_missing_from_flags(
    const llps_readiness_report_t * const report,
    uint32_t * const missing) {
    if (!report->ecc_memory_ready) {
        *missing |= LLPS_READINESS_MISSING_ECC_MEMORY;
    }
    if (!report->ecc_counters_clean) {
        *missing |= LLPS_READINESS_MISSING_ECC_CLEAN;
    }
    if (!report->physical_memory_separation_ready) {
        *missing |= LLPS_READINESS_MISSING_PHYS_SEP;
    }
    if (!report->independent_hardware_tmr_ready) {
        *missing |= LLPS_READINESS_MISSING_HW_TMR;
    }
    if (!report->platform_evidence_layout_bound) {
        *missing |= LLPS_READINESS_MISSING_LAYOUT_BINDING;
    }
    if (!report->platform_attestation_bound) {
        *missing |= LLPS_READINESS_MISSING_ATTESTATION_BINDING;
    }
    if (!report->platform_evidence_physical_domain_bound) {
        *missing |= LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING;
    }
    if (!report->platform_evidence_tmr_memory_domain_bound) {
        *missing |= LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING;
    }
}

static void llps_readiness_report_add_identity_missing(
    const llps_readiness_report_t * const report,
    uint32_t * const missing) {
    if (!report->platform_boot_bound) {
        *missing |= LLPS_READINESS_MISSING_BOOT_BINDING;
    }
    if (!report->platform_identity_bound) {
        *missing |= LLPS_READINESS_MISSING_PLATFORM_ID_BINDING;
    }
    if (!report->executable_image_bound) {
        *missing |= LLPS_READINESS_MISSING_EXECUTABLE_BINDING;
    }
    if (!report->software_evidence_self_test_ready) {
        *missing |= LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST;
    }
}

static void llps_readiness_report_fill_valid_evidence(
    llps_readiness_report_t * const report,
    const llps_platform_safety_evidence_t * const evidence,
    uint32_t * const missing) {
    llps_readiness_report_fill_edac(report, evidence);
    llps_readiness_report_fill_domain_independence(report, evidence);
    llps_readiness_report_fill_binding_flags(report, evidence);
    llps_readiness_report_fill_tmr_domain_binding(report, evidence);
    llps_readiness_report_fill_identity(report, evidence);
    llps_readiness_report_fill_software_evidence(report, evidence);
    llps_readiness_report_fill_physical_domain(report, evidence);
    llps_readiness_report_fill_ready_flags(report, evidence);
    llps_readiness_report_add_missing_from_flags(report, missing);
    llps_readiness_report_add_identity_missing(report, missing);
}

llps_status_t llps_build_readiness_report_in_context(
    const llps_platform_evidence_context_t * const context,
    const llps_memory_safety_report_t * const memory_report,
    const llps_platform_safety_evidence_t * const evidence,
    llps_readiness_report_t * const out_report) {
    bool evidence_valid = false;
    uint32_t missing = 0u;

    if ((memory_report == NULL) || (out_report == NULL)) {
        return LLPS_E_NULL;
    }

    (void)memset(out_report, 0, sizeof(*out_report));
    llps_readiness_report_fill_basics(context,
                                      memory_report,
                                      evidence,
                                      out_report,
                                      &missing);

    evidence_valid =
        llps_platform_safety_evidence_is_valid_in_context(context, evidence);
    out_report->platform_evidence_valid = evidence_valid;
    if (!evidence_valid) {
        missing |= llps_readiness_missing_invalid_evidence_mask();
    } else {
        llps_readiness_report_fill_valid_evidence(out_report,
                                                  evidence,
                                                  &missing);
    }
    if (!out_report->evidence_mac_valid) {
        missing |= LLPS_READINESS_MISSING_EVIDENCE_MAC;
    }
    if (!out_report->payload_ecc_ready) {
        missing |= LLPS_READINESS_MISSING_PAYLOAD_ECC;
    }

    out_report->missing_requirements = missing;
    out_report->gate_passed = missing == 0u;

    return LLPS_OK;
}
