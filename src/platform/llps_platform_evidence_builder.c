/**
 * @file src/platform/llps_platform_evidence_builder.c
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
#include <string.h>

static void llps_platform_evidence_clear_mac(
    llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        evidence->evidence_mac[i] = 0u;
        evidence->evidence_mac_inverse[i] = UINT8_MAX;
    }
}

static llps_status_t llps_platform_evidence_apply_mac(
    const llps_platform_evidence_context_t * const context,
    llps_platform_safety_evidence_t * const evidence) {
    uint8_t mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint32_t key_fingerprint = 0u;

    if ((context == NULL) || (evidence == NULL)) {
        return LLPS_E_NULL;
    }

    if (!context->evidence_mac_enabled) {
        return LLPS_OK;
    }

    if (!llps_evidence_hmac_sha256_file(context->evidence_mac_key_path,
                                        evidence,
                                        mac,
                                        &key_fingerprint) ||
        (key_fingerprint != evidence->evidence_mac_key_fingerprint)) {
        return LLPS_E_IO;
    }

    for (size_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        evidence->evidence_mac[i] = mac[i];
        evidence->evidence_mac_inverse[i] = (uint8_t)(~mac[i]);
    }

    return LLPS_OK;
}

llps_status_t llps_make_platform_safety_evidence_raw_in_context(
    const llps_platform_evidence_context_t * const context,
    const uint32_t flags,
    const uint32_t observed_flags,
    const uint32_t attested_flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const uint32_t known_flags = llps_platform_safety_evidence_known_flags();
    const uint32_t effective_flags = observed_flags | attested_flags;
    bool current_ecc_present = false;
    bool current_ecc_clean = false;
    uint32_t current_observed_flags = 0u;
    uint32_t current_edac_fingerprint = 0u;
    uint32_t current_boot_fingerprint = 0u;
    uint32_t current_identity_fingerprint = 0u;
    uint32_t current_executable_fingerprint = 0u;
    uint32_t current_process_memory_locked = 0u;
    uint32_t current_tmr_memory_locked = 0u;
    uint32_t current_tmr_memory_prefaulted = 0u;
    uint64_t current_tmr_memory_prefault_pages = 0u;
    uint32_t current_tmr_memory_hardened = 0u;
    uint32_t current_tmr_startup_self_test_passed = 0u;
    uint32_t current_tmr_startup_self_test_coverage = 0u;
    llps_edac_observation_t current_edac_observation = { 0 };
    bool current_physical_domains_observed = false;
    uint32_t current_physical_domain_fingerprint = 0u;
    uint32_t current_physical_domain_topology_coverage = 0u;
    uint32_t current_physical_domain_observed_count = 0u;
    uint64_t current_physical_domain_memtotal_kib = 0u;
    uint64_t current_physical_domain_distance_entries = 0u;
    uint64_t current_physical_domain_distance_sum = 0u;
    uint32_t current_physical_domain_distance_pair_coverage = 0u;
    uint64_t current_physical_domain_distance_01 = 0u;
    uint64_t current_physical_domain_distance_02 = 0u;
    uint64_t current_physical_domain_distance_12 = 0u;
    bool current_tmr_memory_domains_bound = false;
    uint32_t current_tmr_memory_domain_fingerprint = 0u;
    bool current_tmr_memory_resident = false;
    uint64_t current_tmr_memory_resident_pages = 0u;
    uint32_t current_tmr_memory_residency_fingerprint = 0u;
    bool current_tmr_memory_physical_frames_distinct = false;
    bool current_tmr_memory_physical_frames_spaced = false;
    uint64_t current_tmr_memory_physical_frame_pages = 0u;
    uint64_t current_tmr_memory_physical_frame_probe_failures = 0u;
    uint64_t current_tmr_memory_physical_frame_min_distance = 0u;
    uint64_t current_tmr_memory_physical_frame_required_distance = 0u;
    uint64_t current_tmr_memory_physical_frame_distance_01 = 0u;
    uint64_t current_tmr_memory_physical_frame_distance_02 = 0u;
    uint64_t current_tmr_memory_physical_frame_distance_12 = 0u;
    uint32_t current_tmr_memory_physical_frame_pair_coverage = 0u;
    uint32_t current_tmr_memory_physical_frame_fingerprint = 0u;
    uint64_t current_tmr_memory_domain_pages_checked = 0u;
    uint64_t current_tmr_memory_domain_mismatch_count = 0u;
    uint64_t current_tmr_memory_domain_probe_failures = 0u;
    uint32_t current_tmr_memory_domain_region_coverage = 0u;
    uint32_t current_tmr_memory_observed_domains[LLPS_SESSION_TMR_BANK_COUNT] =
        { 0u, 0u, 0u };
    uint32_t attestation_fingerprint = 0u;
    uint32_t evidence_mac_key_fingerprint = 0u;
    llps_software_evidence_observation_t software_observation;
    bool software_ready = false;
    bool use_software_ecc = false;
    bool use_software_numa = false;

    if (out_evidence == NULL) {
        return LLPS_E_NULL;
    }

    if (context == NULL) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_NULL;
    }

    if (!llps_platform_evidence_mode_is_valid(context->platform_evidence_mode)) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_RANGE;
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
                                   physical_memory_domain_ids,
                                   &software_observation);
    software_ready =
        llps_software_evidence_observation_is_ready(&software_observation);
    use_software_ecc =
        context->software_ecc_enabled &&
        llps_platform_evidence_mode_uses_software(
            context->platform_evidence_mode) &&
        software_ready;
    use_software_numa =
        context->software_numa_enabled &&
        llps_platform_evidence_mode_uses_software(
            context->platform_evidence_mode) &&
        software_ready;

    if (context->evidence_mac_enabled) {
        if (!llps_hmac_key_fingerprint_file(context->evidence_mac_key_path,
                                            &evidence_mac_key_fingerprint)) {
            (void)memset(out_evidence, 0, sizeof(*out_evidence));
            return LLPS_E_IO;
        }
    }

    if (use_software_ecc) {
        llps_edac_synthesize_ecc(context->software_ecc_controller_count,
                                 context->software_ecc_dimm_count,
                                 context->software_ecc_scrub_rate,
                                 context->software_ecc_controller_corrected_error_count,
                                 context->software_ecc_controller_uncorrected_error_count,
                                 context->software_ecc_dimm_corrected_error_count,
                                 context->software_ecc_dimm_uncorrected_error_count,
                                 &current_ecc_present,
                                 &current_ecc_clean,
                                 &current_edac_fingerprint,
                                 &current_edac_observation);
    } else if (context->platform_evidence_mode !=
               LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
        llps_edac_probe_ecc(context->edac_sysfs_root,
                            &current_ecc_present,
                            &current_ecc_clean,
                            &current_edac_fingerprint,
                            &current_edac_observation);
    }
    current_observed_flags =
        llps_edac_observed_flags(current_ecc_present,
                                  current_ecc_clean);
    current_boot_fingerprint =
        llps_platform_boot_fingerprint(context->boot_id_path);
    current_identity_fingerprint =
        llps_platform_identity_fingerprint(context->platform_id_path);
    if ((current_identity_fingerprint == 0u) &&
        (context->platform_evidence_mode ==
         LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC)) {
        current_identity_fingerprint =
            llps_platform_synthetic_identity_fingerprint(
                evidence_id,
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
                physical_memory_domain_ids,
                hardware_tmr_domain_ids,
                hardware_tmr_voter_domain_id);
    }
    current_executable_fingerprint =
        llps_platform_executable_image_fingerprint(
            context->executable_image_path);
    current_process_memory_locked =
        llps_bool_to_u32(llps_guarded_bool_read(g_process_memory_locked,
                                                g_process_memory_locked_inverse));
    current_tmr_memory_locked =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_locked,
                                                g_tmr_memory_locked_inverse));
    current_tmr_memory_prefaulted =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_prefaulted,
                                                g_tmr_memory_prefaulted_inverse));
    current_tmr_memory_prefault_pages =
        llps_tmr_memory_prefault_pages_read();
    current_tmr_memory_hardened =
        llps_bool_to_u32(llps_guarded_bool_read(g_tmr_memory_hardened,
                                                g_tmr_memory_hardened_inverse));
    current_tmr_startup_self_test_passed =
        llps_bool_to_u32(llps_guarded_bool_read(
            g_tmr_startup_self_test_passed,
            g_tmr_startup_self_test_passed_inverse));
    if (llps_tmr_startup_self_test_coverage_is_valid()) {
        current_tmr_startup_self_test_coverage =
            g_tmr_startup_self_test_coverage;
    }
    llps_observe_tmr_memory_residency(
        &current_tmr_memory_resident,
        &current_tmr_memory_resident_pages,
        &current_tmr_memory_residency_fingerprint);
    llps_observe_tmr_physical_frames(
        &current_tmr_memory_physical_frames_distinct,
        &current_tmr_memory_physical_frames_spaced,
        &current_tmr_memory_physical_frame_pages,
        &current_tmr_memory_physical_frame_probe_failures,
        &current_tmr_memory_physical_frame_min_distance,
        &current_tmr_memory_physical_frame_required_distance,
        &current_tmr_memory_physical_frame_distance_01,
        &current_tmr_memory_physical_frame_distance_02,
        &current_tmr_memory_physical_frame_distance_12,
        &current_tmr_memory_physical_frame_pair_coverage,
        &current_tmr_memory_physical_frame_fingerprint);
    if ((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) {
        if (use_software_numa) {
            llps_numa_synthesize_physical_memory_domains(
                physical_memory_domain_ids,
                context->software_numa_memtotal_kib,
                context->software_numa_local_distance,
                context->software_numa_remote_distance,
                &current_physical_domains_observed,
                &current_physical_domain_fingerprint,
                &current_physical_domain_topology_coverage,
                &current_physical_domain_observed_count,
                &current_physical_domain_memtotal_kib,
                &current_physical_domain_distance_entries,
                &current_physical_domain_distance_sum,
                &current_physical_domain_distance_pair_coverage,
                &current_physical_domain_distance_01,
                &current_physical_domain_distance_02,
                &current_physical_domain_distance_12);
        } else if (context->platform_evidence_mode !=
                   LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
            llps_numa_probe_physical_memory_domains(
                context->numa_sysfs_root,
                physical_memory_domain_ids,
                &current_physical_domains_observed,
                &current_physical_domain_fingerprint,
                &current_physical_domain_topology_coverage,
                &current_physical_domain_observed_count,
                &current_physical_domain_memtotal_kib,
                &current_physical_domain_distance_entries,
                &current_physical_domain_distance_sum,
                &current_physical_domain_distance_pair_coverage,
                &current_physical_domain_distance_01,
                &current_physical_domain_distance_02,
                &current_physical_domain_distance_12);
        }
        if (use_software_numa) {
            llps_synthesize_tmr_memory_domains(
                physical_memory_domain_ids,
                &current_tmr_memory_domains_bound,
                &current_tmr_memory_domain_fingerprint,
                current_tmr_memory_observed_domains,
                &current_tmr_memory_domain_pages_checked,
                &current_tmr_memory_domain_mismatch_count,
                &current_tmr_memory_domain_probe_failures,
                &current_tmr_memory_domain_region_coverage);
        } else {
            llps_probe_tmr_memory_domains(
                physical_memory_domain_ids,
                &current_tmr_memory_domains_bound,
                &current_tmr_memory_domain_fingerprint,
                current_tmr_memory_observed_domains,
                &current_tmr_memory_domain_pages_checked,
                &current_tmr_memory_domain_mismatch_count,
                &current_tmr_memory_domain_probe_failures,
                &current_tmr_memory_domain_region_coverage);
        }
    }

    if (llps_compute_platform_attestation_fingerprint(
            attested_flags,
            evidence_id,
            physical_memory_domain_ids,
            hardware_tmr_domain_ids,
            hardware_tmr_voter_domain_id,
            &attestation_fingerprint) != LLPS_OK) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_RANGE;
    }

    if ((evidence_id == 0u) ||
        ((flags & ~known_flags) != 0u) ||
        ((observed_flags & ~LLPS_PLATFORM_EVIDENCE_OBSERVED_MASK) != 0u) ||
        ((attested_flags & ~LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) != 0u) ||
        (flags != effective_flags) ||
        ((observed_flags != 0u) &&
         (observed_flags != current_observed_flags)) ||
        (((observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u) &&
        ((observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u)) ||
        (((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) &&
         !llps_domain_ids_are_zero(physical_memory_domain_ids)) ||
        (((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) == 0u) &&
         (!llps_domain_ids_are_zero(hardware_tmr_domain_ids) ||
          (hardware_tmr_voter_domain_id != 0u))) ||
        (((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) &&
         (!llps_domain_ids_are_distinct(physical_memory_domain_ids) ||
          !current_physical_domains_observed ||
          !current_tmr_memory_domains_bound)) ||
        (((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) &&
         (!llps_domain_ids_are_distinct(hardware_tmr_domain_ids) ||
          !llps_domain_id_is_disjoint_from_set(hardware_tmr_domain_ids,
                                               hardware_tmr_voter_domain_id))) ||
        ((attested_flags == LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) &&
         (!llps_domain_id_sets_are_disjoint(physical_memory_domain_ids,
                                            hardware_tmr_domain_ids) ||
          !llps_domain_id_is_disjoint_from_set(physical_memory_domain_ids,
                                               hardware_tmr_voter_domain_id)))) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_RANGE;
    }

    (void)memset(out_evidence, 0, sizeof(*out_evidence));
    out_evidence->magic = LLPS_PLATFORM_EVIDENCE_MAGIC;
    out_evidence->version = LLPS_PLATFORM_EVIDENCE_VERSION;
    out_evidence->flags = flags;
    out_evidence->flags_inverse = ~flags;
    out_evidence->observed_flags = observed_flags;
    out_evidence->observed_flags_inverse = ~observed_flags;
    out_evidence->edac_observation_fingerprint = current_edac_fingerprint;
    out_evidence->edac_observation_fingerprint_inverse =
        ~current_edac_fingerprint;
    out_evidence->edac_controller_count =
        current_edac_observation.controller_count;
    out_evidence->edac_controller_count_inverse =
        ~current_edac_observation.controller_count;
    out_evidence->edac_dimm_count = current_edac_observation.dimm_count;
    out_evidence->edac_dimm_count_inverse =
        ~current_edac_observation.dimm_count;
    out_evidence->edac_scrub_rate_count =
        current_edac_observation.scrub_rate_count;
    out_evidence->edac_scrub_rate_count_inverse =
        ~current_edac_observation.scrub_rate_count;
    out_evidence->edac_controller_counter_coverage =
        current_edac_observation.controller_counter_coverage;
    out_evidence->edac_controller_counter_coverage_inverse =
        ~current_edac_observation.controller_counter_coverage;
    out_evidence->edac_dimm_mode_coverage =
        current_edac_observation.dimm_mode_coverage;
    out_evidence->edac_dimm_mode_coverage_inverse =
        ~current_edac_observation.dimm_mode_coverage;
    out_evidence->edac_dimm_counter_coverage =
        current_edac_observation.dimm_counter_coverage;
    out_evidence->edac_dimm_counter_coverage_inverse =
        ~current_edac_observation.dimm_counter_coverage;
    out_evidence->edac_scrub_rate_coverage =
        current_edac_observation.scrub_rate_coverage;
    out_evidence->edac_scrub_rate_coverage_inverse =
        ~current_edac_observation.scrub_rate_coverage;
    out_evidence->edac_corrected_error_count =
        current_edac_observation.corrected_error_count;
    out_evidence->edac_corrected_error_count_inverse =
        ~current_edac_observation.corrected_error_count;
    out_evidence->edac_uncorrected_error_count =
        current_edac_observation.uncorrected_error_count;
    out_evidence->edac_uncorrected_error_count_inverse =
        ~current_edac_observation.uncorrected_error_count;
    out_evidence->edac_dimm_corrected_error_count =
        current_edac_observation.dimm_corrected_error_count;
    out_evidence->edac_dimm_corrected_error_count_inverse =
        ~current_edac_observation.dimm_corrected_error_count;
    out_evidence->edac_dimm_uncorrected_error_count =
        current_edac_observation.dimm_uncorrected_error_count;
    out_evidence->edac_dimm_uncorrected_error_count_inverse =
        ~current_edac_observation.dimm_uncorrected_error_count;
    out_evidence->edac_scrub_rate_sum =
        current_edac_observation.scrub_rate_sum;
    out_evidence->edac_scrub_rate_sum_inverse =
        ~current_edac_observation.scrub_rate_sum;
    out_evidence->platform_boot_fingerprint = current_boot_fingerprint;
    out_evidence->platform_boot_fingerprint_inverse =
        ~current_boot_fingerprint;
    out_evidence->platform_identity_fingerprint = current_identity_fingerprint;
    out_evidence->platform_identity_fingerprint_inverse =
        ~current_identity_fingerprint;
    out_evidence->executable_image_fingerprint = current_executable_fingerprint;
    out_evidence->executable_image_fingerprint_inverse =
        ~current_executable_fingerprint;
    out_evidence->process_memory_locked = current_process_memory_locked;
    out_evidence->process_memory_locked_inverse =
        ~current_process_memory_locked;
    out_evidence->tmr_memory_locked = current_tmr_memory_locked;
    out_evidence->tmr_memory_locked_inverse = ~current_tmr_memory_locked;
    out_evidence->tmr_memory_prefaulted = current_tmr_memory_prefaulted;
    out_evidence->tmr_memory_prefaulted_inverse =
        ~current_tmr_memory_prefaulted;
    out_evidence->tmr_memory_prefault_pages =
        current_tmr_memory_prefault_pages;
    out_evidence->tmr_memory_prefault_pages_inverse =
        ~current_tmr_memory_prefault_pages;
    out_evidence->tmr_memory_hardened = current_tmr_memory_hardened;
    out_evidence->tmr_memory_hardened_inverse =
        ~current_tmr_memory_hardened;
    out_evidence->tmr_startup_self_test_passed =
        current_tmr_startup_self_test_passed;
    out_evidence->tmr_startup_self_test_passed_inverse =
        ~current_tmr_startup_self_test_passed;
    out_evidence->tmr_startup_self_test_coverage =
        current_tmr_startup_self_test_coverage;
    out_evidence->tmr_startup_self_test_coverage_inverse =
        ~current_tmr_startup_self_test_coverage;
    out_evidence->tmr_startup_self_test_required_coverage =
        LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE;
    out_evidence->tmr_startup_self_test_required_coverage_inverse =
        ~out_evidence->tmr_startup_self_test_required_coverage;
    out_evidence->platform_evidence_mode = context->platform_evidence_mode;
    out_evidence->platform_evidence_mode_inverse =
        ~out_evidence->platform_evidence_mode;
    out_evidence->software_evidence_schema_version =
        software_observation.schema_version;
    out_evidence->software_evidence_schema_version_inverse =
        ~software_observation.schema_version;
    out_evidence->software_evidence_self_test_passed =
        software_observation.passed ? 1u : 0u;
    out_evidence->software_evidence_self_test_passed_inverse =
        ~out_evidence->software_evidence_self_test_passed;
    out_evidence->software_evidence_self_test_coverage =
        software_observation.coverage;
    out_evidence->software_evidence_self_test_coverage_inverse =
        ~software_observation.coverage;
    out_evidence->software_evidence_self_test_required_coverage =
        software_observation.required_coverage;
    out_evidence->software_evidence_self_test_required_coverage_inverse =
        ~software_observation.required_coverage;
    out_evidence->software_ecc_controller_count =
        software_observation.controller_count;
    out_evidence->software_ecc_controller_count_inverse =
        ~software_observation.controller_count;
    out_evidence->software_dimm_bank_count = software_observation.bank_count;
    out_evidence->software_dimm_bank_count_inverse =
        ~software_observation.bank_count;
    out_evidence->software_ecc_scrub_rate = software_observation.scrub_rate;
    out_evidence->software_ecc_scrub_rate_inverse =
        ~software_observation.scrub_rate;
    out_evidence->software_dimm_generation = software_observation.generation;
    out_evidence->software_dimm_generation_inverse =
        ~software_observation.generation;
    out_evidence->software_dimm_scrub_generation =
        software_observation.scrub_generation;
    out_evidence->software_dimm_scrub_generation_inverse =
        ~software_observation.scrub_generation;
    out_evidence->software_dimm_fault_injection_coverage =
        software_observation.fault_injection_coverage;
    out_evidence->software_dimm_fault_injection_coverage_inverse =
        ~software_observation.fault_injection_coverage;
    out_evidence->software_fault_injection_mode =
        software_observation.fault_injection_mode;
    out_evidence->software_fault_injection_mode_inverse =
        ~software_observation.fault_injection_mode;
    out_evidence->software_dimm_observation_fingerprint =
        software_observation.fingerprint;
    out_evidence->software_dimm_observation_fingerprint_inverse =
        ~software_observation.fingerprint;
    out_evidence->software_numa_profile_fingerprint =
        software_observation.numa_profile_fingerprint;
    out_evidence->software_numa_profile_fingerprint_inverse =
        ~software_observation.numa_profile_fingerprint;
    out_evidence->physical_domain_observation_fingerprint =
        current_physical_domain_fingerprint;
    out_evidence->physical_domain_observation_fingerprint_inverse =
        ~current_physical_domain_fingerprint;
    out_evidence->physical_domain_topology_coverage =
        current_physical_domain_topology_coverage;
    out_evidence->physical_domain_topology_coverage_inverse =
        ~current_physical_domain_topology_coverage;
    out_evidence->physical_domain_observed_count =
        current_physical_domain_observed_count;
    out_evidence->physical_domain_observed_count_inverse =
        ~current_physical_domain_observed_count;
    out_evidence->physical_domain_memtotal_kib =
        current_physical_domain_memtotal_kib;
    out_evidence->physical_domain_memtotal_kib_inverse =
        ~current_physical_domain_memtotal_kib;
    out_evidence->physical_domain_distance_entries =
        current_physical_domain_distance_entries;
    out_evidence->physical_domain_distance_entries_inverse =
        ~current_physical_domain_distance_entries;
    out_evidence->physical_domain_distance_sum =
        current_physical_domain_distance_sum;
    out_evidence->physical_domain_distance_sum_inverse =
        ~current_physical_domain_distance_sum;
    out_evidence->physical_domain_distance_pair_coverage =
        current_physical_domain_distance_pair_coverage;
    out_evidence->physical_domain_distance_pair_coverage_inverse =
        ~current_physical_domain_distance_pair_coverage;
    out_evidence->physical_domain_distance_01 =
        current_physical_domain_distance_01;
    out_evidence->physical_domain_distance_01_inverse =
        ~current_physical_domain_distance_01;
    out_evidence->physical_domain_distance_02 =
        current_physical_domain_distance_02;
    out_evidence->physical_domain_distance_02_inverse =
        ~current_physical_domain_distance_02;
    out_evidence->physical_domain_distance_12 =
        current_physical_domain_distance_12;
    out_evidence->physical_domain_distance_12_inverse =
        ~current_physical_domain_distance_12;
    out_evidence->tmr_memory_domain_observation_fingerprint =
        current_tmr_memory_domain_fingerprint;
    out_evidence->tmr_memory_domain_observation_fingerprint_inverse =
        ~current_tmr_memory_domain_fingerprint;
    out_evidence->tmr_memory_resident =
        llps_bool_to_u32(current_tmr_memory_resident);
    out_evidence->tmr_memory_resident_inverse =
        ~out_evidence->tmr_memory_resident;
    out_evidence->tmr_memory_resident_pages =
        current_tmr_memory_resident_pages;
    out_evidence->tmr_memory_resident_pages_inverse =
        ~current_tmr_memory_resident_pages;
    out_evidence->tmr_memory_residency_fingerprint =
        current_tmr_memory_residency_fingerprint;
    out_evidence->tmr_memory_residency_fingerprint_inverse =
        ~current_tmr_memory_residency_fingerprint;
    out_evidence->tmr_memory_physical_frames_distinct =
        llps_bool_to_u32(current_tmr_memory_physical_frames_distinct);
    out_evidence->tmr_memory_physical_frames_distinct_inverse =
        ~out_evidence->tmr_memory_physical_frames_distinct;
    out_evidence->tmr_memory_physical_frames_spaced =
        llps_bool_to_u32(current_tmr_memory_physical_frames_spaced);
    out_evidence->tmr_memory_physical_frames_spaced_inverse =
        ~out_evidence->tmr_memory_physical_frames_spaced;
    out_evidence->tmr_memory_physical_frame_pages =
        current_tmr_memory_physical_frame_pages;
    out_evidence->tmr_memory_physical_frame_pages_inverse =
        ~current_tmr_memory_physical_frame_pages;
    out_evidence->tmr_memory_physical_frame_probe_failures =
        current_tmr_memory_physical_frame_probe_failures;
    out_evidence->tmr_memory_physical_frame_probe_failures_inverse =
        ~current_tmr_memory_physical_frame_probe_failures;
    out_evidence->tmr_memory_physical_frame_min_distance =
        current_tmr_memory_physical_frame_min_distance;
    out_evidence->tmr_memory_physical_frame_min_distance_inverse =
        ~current_tmr_memory_physical_frame_min_distance;
    out_evidence->tmr_memory_physical_frame_required_distance =
        current_tmr_memory_physical_frame_required_distance;
    out_evidence->tmr_memory_physical_frame_required_distance_inverse =
        ~current_tmr_memory_physical_frame_required_distance;
    out_evidence->tmr_memory_physical_frame_distance_01 =
        current_tmr_memory_physical_frame_distance_01;
    out_evidence->tmr_memory_physical_frame_distance_01_inverse =
        ~current_tmr_memory_physical_frame_distance_01;
    out_evidence->tmr_memory_physical_frame_distance_02 =
        current_tmr_memory_physical_frame_distance_02;
    out_evidence->tmr_memory_physical_frame_distance_02_inverse =
        ~current_tmr_memory_physical_frame_distance_02;
    out_evidence->tmr_memory_physical_frame_distance_12 =
        current_tmr_memory_physical_frame_distance_12;
    out_evidence->tmr_memory_physical_frame_distance_12_inverse =
        ~current_tmr_memory_physical_frame_distance_12;
    out_evidence->tmr_memory_physical_frame_pair_coverage =
        current_tmr_memory_physical_frame_pair_coverage;
    out_evidence->tmr_memory_physical_frame_pair_coverage_inverse =
        ~current_tmr_memory_physical_frame_pair_coverage;
    out_evidence->tmr_memory_physical_frame_fingerprint =
        current_tmr_memory_physical_frame_fingerprint;
    out_evidence->tmr_memory_physical_frame_fingerprint_inverse =
        ~current_tmr_memory_physical_frame_fingerprint;
    out_evidence->tmr_memory_domain_pages_checked =
        current_tmr_memory_domain_pages_checked;
    out_evidence->tmr_memory_domain_pages_checked_inverse =
        ~current_tmr_memory_domain_pages_checked;
    out_evidence->tmr_memory_domain_mismatch_count =
        current_tmr_memory_domain_mismatch_count;
    out_evidence->tmr_memory_domain_mismatch_count_inverse =
        ~current_tmr_memory_domain_mismatch_count;
    out_evidence->tmr_memory_domain_probe_failures =
        current_tmr_memory_domain_probe_failures;
    out_evidence->tmr_memory_domain_probe_failures_inverse =
        ~current_tmr_memory_domain_probe_failures;
    out_evidence->tmr_memory_domain_region_coverage =
        current_tmr_memory_domain_region_coverage;
    out_evidence->tmr_memory_domain_region_coverage_inverse =
        ~current_tmr_memory_domain_region_coverage;
    out_evidence->attested_flags = attested_flags;
    out_evidence->attested_flags_inverse = ~attested_flags;
    out_evidence->attestation_fingerprint = attestation_fingerprint;
    out_evidence->attestation_fingerprint_inverse =
        ~attestation_fingerprint;
    out_evidence->evidence_id = evidence_id;
    out_evidence->evidence_id_inverse = ~evidence_id;
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        const uint32_t physical_domain =
            (physical_memory_domain_ids != NULL) ?
            physical_memory_domain_ids[i] :
            0u;
        const uint32_t hardware_domain =
            (hardware_tmr_domain_ids != NULL) ?
            hardware_tmr_domain_ids[i] :
            0u;

        out_evidence->physical_memory_domain_ids[i] = physical_domain;
        out_evidence->physical_memory_domain_ids_inverse[i] =
            ~physical_domain;
        out_evidence->hardware_tmr_domain_ids[i] = hardware_domain;
        out_evidence->hardware_tmr_domain_ids_inverse[i] = ~hardware_domain;
        out_evidence->tmr_memory_observed_domain_ids[i] =
            current_tmr_memory_observed_domains[i];
        out_evidence->tmr_memory_observed_domain_ids_inverse[i] =
            ~current_tmr_memory_observed_domains[i];
    }
    out_evidence->hardware_tmr_voter_domain_id = hardware_tmr_voter_domain_id;
    out_evidence->hardware_tmr_voter_domain_id_inverse =
        ~hardware_tmr_voter_domain_id;
    out_evidence->tmr_layout_fingerprint = llps_tmr_layout_fingerprint();
    out_evidence->tmr_layout_fingerprint_inverse =
        ~out_evidence->tmr_layout_fingerprint;
    out_evidence->evidence_mac_enabled =
        context->evidence_mac_enabled ? 1u : 0u;
    out_evidence->evidence_mac_enabled_inverse =
        ~out_evidence->evidence_mac_enabled;
    out_evidence->evidence_mac_key_fingerprint = evidence_mac_key_fingerprint;
    out_evidence->evidence_mac_key_fingerprint_inverse =
        ~evidence_mac_key_fingerprint;
    llps_platform_evidence_clear_mac(out_evidence);
    out_evidence->observation_digest =
        llps_platform_safety_evidence_compute_observation_digest(out_evidence);
    out_evidence->observation_digest_inverse =
        ~out_evidence->observation_digest;
    out_evidence->crc = llps_platform_safety_evidence_compute_crc(out_evidence);
    out_evidence->crc_inverse = ~out_evidence->crc;

    if (llps_platform_evidence_apply_mac(context, out_evidence) != LLPS_OK) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_IO;
    }

    return LLPS_OK;
}

llps_status_t llps_make_platform_safety_evidence_in_context(
    const llps_platform_evidence_context_t * const context,
    const uint32_t flags,
    const uint64_t evidence_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const uint32_t zero_domains[LLPS_SESSION_TMR_BANK_COUNT] = { 0u, 0u, 0u };

    return llps_make_platform_safety_evidence_ex_in_context(
        context,
        flags,
        evidence_id,
        zero_domains,
        zero_domains,
        0u,
        out_evidence);
}

llps_status_t llps_make_platform_safety_evidence_ex_in_context(
    const llps_platform_evidence_context_t * const context,
    const uint32_t flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    if (out_evidence == NULL) {
        return LLPS_E_NULL;
    }

    if (context == NULL) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_NULL;
    }

    if ((flags & LLPS_PLATFORM_EVIDENCE_OBSERVED_MASK) != 0u) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_RANGE;
    }

    return llps_make_platform_safety_evidence_raw_in_context(
        context,
        flags,
        0u,
        flags,
        evidence_id,
        physical_memory_domain_ids,
        hardware_tmr_domain_ids,
        hardware_tmr_voter_domain_id,
        out_evidence);
}

static llps_status_t llps_collect_platform_evidence_input_status(
    const llps_platform_evidence_context_t * const context,
    const uint32_t requested_flags,
    const uint64_t evidence_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    if (out_evidence == NULL) {
        return LLPS_E_NULL;
    }
    if (context == NULL) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_NULL;
    }
    if ((evidence_id == 0u) ||
        ((requested_flags & ~LLPS_PLATFORM_EVIDENCE_REQUIRED) != 0u) ||
        !llps_platform_evidence_mode_is_valid(context->platform_evidence_mode)) {
        (void)memset(out_evidence, 0, sizeof(*out_evidence));
        return LLPS_E_RANGE;
    }
    return LLPS_OK;
}

static bool llps_collect_platform_evidence_software_ready(
    const llps_platform_evidence_context_t * const context,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    llps_software_evidence_observation_t observation;

    if (context == NULL) {
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
                                   physical_memory_domain_ids,
                                   &observation);
    return llps_software_evidence_observation_is_ready(&observation);
}

static uint32_t llps_collect_platform_evidence_observed_flags(
    const llps_platform_evidence_context_t * const context,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    bool ecc_present = false;
    bool ecc_clean = false;
    uint32_t edac_fingerprint = 0u;
    const bool use_software_ecc =
        (context != NULL) &&
        context->software_ecc_enabled &&
        llps_platform_evidence_mode_uses_software(
            context->platform_evidence_mode) &&
        llps_collect_platform_evidence_software_ready(
            context,
            physical_memory_domain_ids);

    if (use_software_ecc) {
        llps_edac_synthesize_ecc(context->software_ecc_controller_count,
                                 context->software_ecc_dimm_count,
                                 context->software_ecc_scrub_rate,
                                 context->software_ecc_controller_corrected_error_count,
                                 context->software_ecc_controller_uncorrected_error_count,
                                 context->software_ecc_dimm_corrected_error_count,
                                 context->software_ecc_dimm_uncorrected_error_count,
                                 &ecc_present,
                                 &ecc_clean,
                                 &edac_fingerprint,
                                 NULL);
    } else if ((context != NULL) &&
               (context->platform_evidence_mode !=
                LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC)) {
        llps_edac_probe_ecc(context->edac_sysfs_root,
                            &ecc_present,
                            &ecc_clean,
                            &edac_fingerprint,
                            NULL);
    }

    (void)edac_fingerprint;
    return llps_edac_observed_flags(ecc_present, ecc_clean);
}

llps_status_t llps_collect_platform_safety_evidence_in_context(
    const llps_platform_evidence_context_t * const context,
    const uint32_t requested_flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t * const out_evidence) {
    const uint32_t attested_flags =
        requested_flags & LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK;
    llps_status_t status = LLPS_OK;

    status = llps_collect_platform_evidence_input_status(context,
                                                         requested_flags,
                                                         evidence_id,
                                                         out_evidence);
    if (status != LLPS_OK) {
        return status;
    }

    const uint32_t observed_flags =
        llps_collect_platform_evidence_observed_flags(
            context,
            physical_memory_domain_ids);

    return llps_make_platform_safety_evidence_raw_in_context(
        context,
        observed_flags | attested_flags,
        observed_flags,
        attested_flags,
        evidence_id,
        physical_memory_domain_ids,
        hardware_tmr_domain_ids,
        hardware_tmr_voter_domain_id,
        out_evidence);
}
