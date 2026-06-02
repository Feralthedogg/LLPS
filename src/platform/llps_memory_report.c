/**
 * @file src/platform/llps_memory_report.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_memory_report.h"

#include "llps_control_flag.h"
#include "llps_free_list_tmr.h"
#include "llps_guard.h"
#include "llps_memory.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_runtime_latches.h"
#include "llps_safety_counters.h"
#include "llps_session_tmr.h"
#include "llps_tmr_layout.h"
#include "llps_tmr_observer.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    bool runtime_cfg_valid;
    bool control_flag_valid;
    bool free_list_valid;
    bool shutdown_requested;
} llps_memory_report_redundant_state_t;

typedef struct {
    bool resident;
    uint64_t resident_pages;
    uint32_t residency_fingerprint;
    bool physical_frames_distinct;
    bool physical_frames_spaced;
    uint64_t physical_frame_pages;
    uint64_t physical_frame_probe_failures;
    uint64_t physical_frame_min_distance;
    uint64_t physical_frame_required_distance;
    uint64_t physical_frame_distance_01;
    uint64_t physical_frame_distance_02;
    uint64_t physical_frame_distance_12;
    uint32_t physical_frame_pair_coverage;
    uint32_t physical_frame_fingerprint;
    uint64_t domain_pages_checked;
    uint64_t domain_mismatch_count;
    uint64_t domain_probe_failures;
    uint32_t domain_region_coverage;
} llps_memory_report_probe_state_t;

static void llps_memory_report_collect_redundant_state(
    llps_yml_config_t * const runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t * const free_sessions_count,
    llps_memory_report_redundant_state_t * const state) {
    state->runtime_cfg_valid = llps_runtime_cfg_reconcile(runtime_cfg);
    state->control_flag_valid =
        llps_control_flag_reconcile(&state->shutdown_requested);
    state->free_list_valid =
        llps_free_list_reconcile(free_sessions,
                                 free_sessions_count,
                                 runtime_cfg);
}

static void llps_memory_report_probe_domains(
    llps_yml_config_t * const runtime_cfg,
    llps_memory_report_probe_state_t * const probes) {
    bool unused_bound = false;
    uint32_t unused_fingerprint = 0u;
    uint32_t unused_domains[LLPS_SESSION_TMR_BANK_COUNT];

    if (!llps_config_requests_physical_memory_separation(runtime_cfg)) {
        return;
    }

    if ((runtime_cfg->software_numa_enabled != 0u) &&
        (runtime_cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL)) {
        llps_synthesize_tmr_memory_domains(
            runtime_cfg->platform_physical_memory_domains,
            &unused_bound,
            &unused_fingerprint,
            unused_domains,
            &probes->domain_pages_checked,
            &probes->domain_mismatch_count,
            &probes->domain_probe_failures,
            &probes->domain_region_coverage);
    } else {
        llps_probe_tmr_memory_domains(
            runtime_cfg->platform_physical_memory_domains,
            &unused_bound,
            &unused_fingerprint,
            unused_domains,
            &probes->domain_pages_checked,
            &probes->domain_mismatch_count,
            &probes->domain_probe_failures,
            &probes->domain_region_coverage);
    }
}

static void llps_memory_report_collect_probes(
    llps_yml_config_t * const runtime_cfg,
    const bool runtime_cfg_valid,
    llps_memory_report_probe_state_t * const probes) {
    (void)memset(probes, 0, sizeof(*probes));
    if (runtime_cfg_valid) {
        (void)llps_refresh_tmr_memory_domain_binding(runtime_cfg);
        llps_memory_report_probe_domains(runtime_cfg, probes);
    }
    llps_probe_tmr_memory_residency(&probes->resident,
                                    &probes->resident_pages,
                                    &probes->residency_fingerprint);
    llps_probe_tmr_physical_frames(&probes->physical_frames_distinct,
                                   &probes->physical_frames_spaced,
                                   &probes->physical_frame_pages,
                                   &probes->physical_frame_probe_failures,
                                   &probes->physical_frame_min_distance,
                                   &probes->physical_frame_required_distance,
                                   &probes->physical_frame_distance_01,
                                   &probes->physical_frame_distance_02,
                                   &probes->physical_frame_distance_12,
                                   &probes->physical_frame_pair_coverage,
                                   &probes->physical_frame_fingerprint);
}

static void llps_memory_report_fill_redundant_state(
    llps_memory_safety_report_t * const report,
    const llps_memory_report_redundant_state_t * const state,
    const llps_yml_config_t * const runtime_cfg) {
    report->runtime_cfg_tmr_valid = state->runtime_cfg_valid;
    report->control_flag_tmr_valid = state->control_flag_valid;
    report->free_list_tmr_valid = state->free_list_valid;
    report->shutdown_requested = state->shutdown_requested;
    report->tmr_layout_valid = llps_tmr_metadata_layout_is_valid();
    report->process_memory_locked =
        llps_guarded_bool_read(g_process_memory_locked,
                               g_process_memory_locked_inverse);
    report->tmr_memory_locked =
        llps_guarded_bool_read(g_tmr_memory_locked,
                               g_tmr_memory_locked_inverse);
    report->tmr_memory_prefaulted =
        llps_guarded_bool_read(g_tmr_memory_prefaulted,
                               g_tmr_memory_prefaulted_inverse);
    report->tmr_memory_domains_bound =
        llps_guarded_bool_read(g_tmr_memory_domains_bound,
                               g_tmr_memory_domains_bound_inverse);
    report->tmr_memory_observed_domains_valid =
        llps_tmr_memory_observed_domains_are_valid();
    report->tmr_memory_hardened =
        llps_guarded_bool_read(g_tmr_memory_hardened,
                               g_tmr_memory_hardened_inverse);
    report->readiness_runtime_monitor_enabled =
        runtime_cfg->require_readiness != 0u;
    report->runtime_safety_latches_valid =
        llps_runtime_safety_latches_are_valid();
}

static void llps_memory_report_fill_startup_and_banks(
    llps_memory_safety_report_t * const report) {
    const uintptr_t addr0 = (uintptr_t)(const void *)&g_session_tmr_region0;
    const uintptr_t addr1 = (uintptr_t)(const void *)&g_session_tmr_region1;
    const uintptr_t addr2 = (uintptr_t)(const void *)&g_session_tmr_region2;

    report->tmr_startup_self_test_passed =
        llps_guarded_bool_read(g_tmr_startup_self_test_passed,
                               g_tmr_startup_self_test_passed_inverse);
    report->tmr_startup_self_test_coverage_valid =
        llps_tmr_startup_self_test_coverage_is_valid();
    report->tmr_memory_prefault_pages_valid =
        llps_tmr_memory_prefault_pages_is_valid();
    report->tmr_bank_guard_valid[0] =
        llps_session_tmr_region_guard_is_valid(0u);
    report->tmr_bank_guard_valid[1] =
        llps_session_tmr_region_guard_is_valid(1u);
    report->tmr_bank_guard_valid[2] =
        llps_session_tmr_region_guard_is_valid(2u);
    report->tmr_bank_distance_01 =
        (uint64_t)llps_abs_addr_distance(addr0, addr1);
    report->tmr_bank_distance_02 =
        (uint64_t)llps_abs_addr_distance(addr0, addr2);
    report->tmr_bank_distance_12 =
        (uint64_t)llps_abs_addr_distance(addr1, addr2);
    report->tmr_metadata_min_bank_distance =
        llps_tmr_metadata_min_bank_distance();
}

static void llps_memory_report_fill_probe_state(
    llps_memory_safety_report_t * const report,
    const llps_memory_report_probe_state_t * const probes) {
    report->tmr_memory_resident = probes->resident;
    report->tmr_memory_resident_pages = probes->resident_pages;
    report->tmr_memory_residency_fingerprint =
        probes->residency_fingerprint;
    report->tmr_memory_physical_frames_distinct =
        probes->physical_frames_distinct;
    report->tmr_memory_physical_frames_spaced =
        probes->physical_frames_spaced;
    report->tmr_memory_physical_frame_pages =
        probes->physical_frame_pages;
    report->tmr_memory_physical_frame_probe_failures =
        probes->physical_frame_probe_failures;
    report->tmr_memory_physical_frame_min_distance =
        probes->physical_frame_min_distance;
    report->tmr_memory_physical_frame_required_distance =
        probes->physical_frame_required_distance;
    report->tmr_memory_physical_frame_distance_01 =
        probes->physical_frame_distance_01;
    report->tmr_memory_physical_frame_distance_02 =
        probes->physical_frame_distance_02;
    report->tmr_memory_physical_frame_distance_12 =
        probes->physical_frame_distance_12;
    report->tmr_memory_physical_frame_pair_coverage =
        probes->physical_frame_pair_coverage;
    report->tmr_memory_physical_frame_fingerprint =
        probes->physical_frame_fingerprint;
}

static void llps_memory_report_fill_domain_state(
    llps_memory_safety_report_t * const report,
    const llps_memory_report_probe_state_t * const probes) {
    report->tmr_memory_domain_bind_failures =
        g_memory_safety_counters.tmr_memory_domain_bind_failures;
    report->tmr_memory_domain_observation_fingerprint =
        llps_tmr_memory_domain_observation_fingerprint_is_valid() ?
        g_tmr_memory_domain_observation_fingerprint :
        0u;
    report->tmr_memory_domain_pages_checked = probes->domain_pages_checked;
    report->tmr_memory_domain_mismatch_count = probes->domain_mismatch_count;
    report->tmr_memory_domain_probe_failures = probes->domain_probe_failures;
    report->tmr_memory_domain_region_coverage =
        probes->domain_region_coverage;
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        report->tmr_memory_observed_domain_ids[i] =
            g_tmr_memory_observed_domain_ids[i];
    }
}

static void llps_memory_report_fill_counter_block_a(
    llps_memory_safety_report_t * const report) {
    report->tmr_single_bank_repairs =
        g_memory_safety_counters.tmr_single_bank_repairs;
    report->tmr_majority_failures =
        g_memory_safety_counters.tmr_majority_failures;
    report->tmr_region_guard_faults =
        g_memory_safety_counters.tmr_region_guard_faults;
    report->tmr_layout_failures =
        g_memory_safety_counters.tmr_layout_failures;
    report->process_memory_lock_failures =
        g_memory_safety_counters.process_memory_lock_failures;
    report->tmr_memory_lock_failures =
        g_memory_safety_counters.tmr_memory_lock_failures;
    report->tmr_memory_prefault_pages =
        llps_tmr_memory_prefault_pages_read();
    report->tmr_memory_prefault_failures =
        g_memory_safety_counters.tmr_memory_prefault_failures;
    report->tmr_memory_residency_failures =
        g_memory_safety_counters.tmr_memory_residency_failures;
    report->tmr_memory_physical_frame_faults =
        g_memory_safety_counters.tmr_memory_physical_frame_faults;
}

static void llps_memory_report_fill_counter_block_b(
    llps_memory_safety_report_t * const report) {
    report->tmr_startup_self_test_coverage =
        g_tmr_startup_self_test_coverage;
    report->tmr_startup_self_test_required_coverage =
        LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE;
    report->tmr_memory_harden_failures =
        g_memory_safety_counters.tmr_memory_harden_failures;
    report->contract_violations =
        g_memory_safety_counters.contract_violations;
    report->free_list_single_bank_repairs =
        g_memory_safety_counters.free_list_single_bank_repairs;
    report->free_list_majority_failures =
        g_memory_safety_counters.free_list_majority_failures;
    report->runtime_cfg_single_bank_repairs =
        g_memory_safety_counters.runtime_cfg_single_bank_repairs;
    report->runtime_cfg_majority_failures =
        g_memory_safety_counters.runtime_cfg_majority_failures;
    report->control_flag_single_bank_repairs =
        g_memory_safety_counters.control_flag_single_bank_repairs;
    report->control_flag_majority_failures =
        g_memory_safety_counters.control_flag_majority_failures;
    report->secded_single_bit_repairs =
        g_memory_safety_counters.secded_single_bit_repairs;
    report->secded_double_bit_failures =
        g_memory_safety_counters.secded_double_bit_failures;
}

static void llps_memory_report_fill_scrub_counters(
    llps_memory_safety_report_t * const report) {
    report->tmr_scrub_passes = g_memory_safety_counters.tmr_scrub_passes;
    report->tmr_scrub_sessions_checked =
        g_memory_safety_counters.tmr_scrub_sessions_checked;
    report->tmr_scrub_fail_closed_sessions =
        g_memory_safety_counters.tmr_scrub_fail_closed_sessions;
    report->payload_ecc_scrub_passes =
        g_memory_safety_counters.payload_ecc_scrub_passes;
    report->payload_ecc_scrub_sessions_checked =
        g_memory_safety_counters.payload_ecc_scrub_sessions_checked;
    report->payload_ecc_scrub_fail_closed_sessions =
        g_memory_safety_counters.payload_ecc_scrub_fail_closed_sessions;
}

static void llps_memory_report_fill_runtime_pass_counters(
    llps_memory_safety_report_t * const report) {
    report->readiness_runtime_monitor_passes =
        g_memory_safety_counters.readiness_runtime_monitor_passes;
    report->readiness_runtime_software_evidence_patrol_passes =
        g_memory_safety_counters
            .readiness_runtime_software_evidence_patrol_passes;
    report->readiness_runtime_synthetic_ecc_topology_patrol_passes =
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_passes;
    report->readiness_runtime_synthetic_ecc_topology_patrol_failures =
        g_memory_safety_counters
            .readiness_runtime_synthetic_ecc_topology_patrol_failures;
    report->readiness_runtime_synthetic_fault_patrol_passes =
        g_memory_safety_counters
            .readiness_runtime_synthetic_fault_patrol_passes;
    report->readiness_runtime_synthetic_fault_patrol_failures =
        g_memory_safety_counters
            .readiness_runtime_synthetic_fault_patrol_failures;
    report->readiness_runtime_synthetic_numa_patrol_passes =
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_passes;
    report->readiness_runtime_synthetic_numa_patrol_failures =
        g_memory_safety_counters
            .readiness_runtime_synthetic_numa_patrol_failures;
}

static void llps_memory_report_fill_runtime_failure_counters(
    llps_memory_safety_report_t * const report) {
    report->readiness_runtime_monitor_failures =
        g_memory_safety_counters.readiness_runtime_monitor_failures;
    report->readiness_runtime_cfg_failures =
        g_memory_safety_counters.readiness_runtime_cfg_failures;
    report->readiness_runtime_software_tmr_failures =
        g_memory_safety_counters.readiness_runtime_software_tmr_failures;
    report->readiness_runtime_ecc_failures =
        g_memory_safety_counters.readiness_runtime_ecc_failures;
    report->readiness_runtime_physical_domain_failures =
        g_memory_safety_counters.readiness_runtime_physical_domain_failures;
    report->readiness_runtime_tmr_memory_domain_failures =
        g_memory_safety_counters.readiness_runtime_tmr_memory_domain_failures;
    report->readiness_runtime_hardware_tmr_failures =
        g_memory_safety_counters.readiness_runtime_hardware_tmr_failures;
    report->readiness_runtime_identity_failures =
        g_memory_safety_counters.readiness_runtime_identity_failures;
    report->readiness_runtime_attestation_failures =
        g_memory_safety_counters.readiness_runtime_attestation_failures;
    report->readiness_runtime_observation_digest_failures =
        g_memory_safety_counters.readiness_runtime_observation_digest_failures;
}

static void llps_memory_report_fill_counters(
    llps_memory_safety_report_t * const report) {
    report->memory_safety_counters_valid =
        llps_memory_safety_counters_are_valid();
    report->memory_safety_counters_fingerprint =
        llps_memory_safety_counters_compute_crc(&g_memory_safety_counters);
    llps_memory_report_fill_counter_block_a(report);
    llps_memory_report_fill_counter_block_b(report);
    llps_memory_report_fill_scrub_counters(report);
    llps_memory_report_fill_runtime_pass_counters(report);
    llps_memory_report_fill_runtime_failure_counters(report);
}

llps_status_t llps_build_memory_safety_report(
    llps_yml_config_t * const runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t * const free_sessions_count,
    llps_memory_safety_report_t * const out_report) {
    llps_memory_report_redundant_state_t state = { false, false, false, true };
    llps_memory_report_probe_state_t probes;

    if ((runtime_cfg == NULL) || (free_sessions == NULL) ||
        (free_sessions_count == NULL) || (out_report == NULL)) {
        return LLPS_E_NULL;
    }

    llps_memory_report_collect_redundant_state(runtime_cfg,
                                               free_sessions,
                                               free_sessions_count,
                                               &state);
    llps_memory_report_collect_probes(runtime_cfg,
                                      state.runtime_cfg_valid,
                                      &probes);
    (void)memset(out_report, 0, sizeof(*out_report));
    llps_memory_report_fill_redundant_state(out_report, &state, runtime_cfg);
    llps_memory_report_fill_startup_and_banks(out_report);
    llps_memory_report_fill_probe_state(out_report, &probes);
    llps_memory_report_fill_domain_state(out_report, &probes);
    llps_memory_report_fill_counters(out_report);

    return LLPS_OK;
}
