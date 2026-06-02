/**
 * @file src/readiness/llps_readiness_config.c
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#include "llps_readiness_config.h"

#include "llps_control_flag.h"
#include "llps_free_list_tmr.h"
#include "llps_guard.h"
#include "llps_memory.h"
#include "llps_readiness.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_runtime_latches.h"
#include "llps_safety_counters.h"
#include "llps_session_tmr.h"
#include "llps_readiness_runtime_failures.h"
#include "llps_tmr_layout.h"
#include "llps_tmr_platform.h"

#include <stdint.h>
#include <stdio.h>

static llps_status_t llps_readiness_collect_configured_evidence(
    const llps_yml_config_t * const cfg,
    llps_platform_safety_evidence_t * const evidence) {
    if ((cfg == NULL) || (evidence == NULL)) {
        return LLPS_E_NULL;
    }

    return llps_collect_platform_safety_evidence(
        cfg->platform_safety_flags,
        cfg->platform_safety_evidence_id,
        cfg->platform_physical_memory_domains,
        cfg->platform_hardware_tmr_domains,
        cfg->platform_hardware_tmr_voter_domain,
        evidence);
}

static llps_status_t llps_require_configured_readiness_report(
    const llps_yml_config_t * const cfg) {
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    llps_status_t status = LLPS_OK;

    if (cfg == NULL) {
        return LLPS_E_NULL;
    }

    if (cfg->require_readiness == 0u) {
        return LLPS_OK;
    }

    status = llps_readiness_collect_configured_evidence(cfg, &evidence);
    if (status != LLPS_OK) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(evidence collection status %d)\n",
                      (int)status);
        return status;
    }

    status = llps_get_readiness_report(&evidence, &report);
    if (status != LLPS_OK) {
        return status;
    }

    if (!report.configured_evidence_request_bound) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(configured evidence request mismatch)\n");
        return LLPS_E_STATE;
    }

    if (!report.gate_passed) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(missing mask 0x%08x)\n",
                      (unsigned)report.missing_requirements);
        return LLPS_E_STATE;
    }

    if (!report.configured_platform_observation_digest_bound) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(observation digest mismatch configured=0x%08x "
                      "observed=0x%08x)\n",
                      (unsigned)cfg->platform_observation_digest,
                      (unsigned)evidence.observation_digest);
        return LLPS_E_STATE;
    }

    return LLPS_OK;
}

llps_status_t llps_require_configured_readiness(
    const llps_yml_config_t * const cfg) {
    if (cfg == NULL) {
        return LLPS_E_NULL;
    }
    if (cfg->require_readiness == 0u) {
        return LLPS_OK;
    }
    return llps_require_configured_readiness_report(cfg);
}

static uint32_t llps_readiness_runtime_tmr_memory_failure_mask(
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t mask = 0u;

    if (evidence == NULL) {
        return LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR;
    }
    if ((evidence->tmr_memory_resident != 1u) ||
        (evidence->tmr_memory_resident_pages == 0u) ||
        (evidence->tmr_memory_residency_fingerprint == 0u)) {
        mask |= LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR |
                LLPS_READINESS_RUNTIME_DETAIL_TMR_RESIDENCY;
    }
    if ((evidence->tmr_memory_physical_frames_distinct != 1u) ||
        (evidence->tmr_memory_physical_frames_spaced != 1u) ||
        (evidence->tmr_memory_physical_frame_pages == 0u) ||
        (evidence->tmr_memory_physical_frame_probe_failures != 0u) ||
        (evidence->tmr_memory_physical_frame_required_distance == 0u) ||
        (evidence->tmr_memory_physical_frame_min_distance <
         evidence->tmr_memory_physical_frame_required_distance) ||
        ((evidence->tmr_memory_physical_frame_pair_coverage &
          LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) !=
         LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL)) {
        mask |= LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR |
                LLPS_READINESS_RUNTIME_DETAIL_TMR_PHYSICAL_FRAME;
    }
    return mask;
}

static uint32_t llps_readiness_runtime_snapshot_failure_mask(
    const llps_yml_config_t * const cfg,
    const llps_platform_safety_evidence_t * const evidence) {
    uint32_t failure_mask = 0u;

    if ((cfg == NULL) || (evidence == NULL)) {
        return LLPS_READINESS_RUNTIME_FAILURE_CFG;
    }
    if ((cfg->platform_observation_digest == 0u) ||
        (cfg->platform_observation_digest != evidence->observation_digest)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_OBSERVATION_DIGEST;
    }
    if (!llps_evidence_platform_snapshot_is_software_ready(evidence)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR;
    }
    failure_mask |= llps_readiness_runtime_tmr_memory_failure_mask(evidence);
    if (((evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_MEMORY) == 0u) ||
        ((evidence->observed_flags & LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) == 0u)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_ECC;
    }
    if (!llps_evidence_platform_snapshot_has_physical_domain_binding(evidence)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_PHYSICAL_DOMAIN;
    }
    if (!llps_evidence_platform_snapshot_has_tmr_domain_binding(evidence)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_TMR_MEMORY_DOMAIN |
                        LLPS_READINESS_RUNTIME_DETAIL_TMR_DOMAIN_BIND;
    }
    if (!llps_evidence_platform_snapshot_has_hardware_tmr(evidence)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_HW_TMR;
    }
    if (!llps_evidence_platform_snapshot_has_identity(evidence)) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_IDENTITY;
    }
    if (evidence->attestation_fingerprint == 0u) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION;
    }
    return failure_mask;
}

llps_status_t llps_check_configured_readiness_platform_snapshot(
    const llps_yml_config_t * const cfg,
    uint32_t * const out_failure_mask) {
    llps_platform_safety_evidence_t evidence;
    llps_status_t status = LLPS_OK;
    uint32_t failure_mask = 0u;

    if (out_failure_mask == NULL) {
        return LLPS_E_NULL;
    }
    *out_failure_mask = 0u;

    if (cfg == NULL) {
        *out_failure_mask = LLPS_READINESS_RUNTIME_FAILURE_CFG;
        return LLPS_E_NULL;
    }
    if (cfg->require_readiness == 0u) {
        return LLPS_OK;
    }

    status = llps_readiness_collect_configured_evidence(cfg, &evidence);
    if (status != LLPS_OK) {
        *out_failure_mask =
            llps_readiness_runtime_collection_failure_mask_from_cfg(cfg);
        return status;
    }

    failure_mask = llps_readiness_runtime_snapshot_failure_mask(cfg,
                                                                &evidence);
    *out_failure_mask = failure_mask;
    return (failure_mask == 0u) ? LLPS_OK : LLPS_E_STATE;
}

static bool llps_readiness_runtime_fast_reconciles(
    llps_yml_config_t * const runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t * const free_sessions_count) {
    bool shutdown_requested = true;

    return llps_runtime_cfg_reconcile(runtime_cfg) &&
           llps_control_flag_reconcile(&shutdown_requested) &&
           llps_free_list_reconcile(free_sessions,
                                    free_sessions_count,
                                    runtime_cfg) &&
           !shutdown_requested;
}

static bool llps_readiness_runtime_fast_payload_policy_ok(
    const llps_yml_config_t * const runtime_cfg) {
    if (runtime_cfg == NULL) {
        return false;
    }

    return (runtime_cfg->require_readiness == 0u) ||
           (runtime_cfg->software_ecc_enabled == 0u) ||
           (runtime_cfg->payload_ecc_enabled != 0u);
}

static bool llps_readiness_runtime_fast_tmr_layout_ok(void) {
    const uintptr_t addr0 = (uintptr_t)(const void *)&g_session_tmr_region0;
    const uintptr_t addr1 = (uintptr_t)(const void *)&g_session_tmr_region1;
    const uintptr_t addr2 = (uintptr_t)(const void *)&g_session_tmr_region2;

    return llps_tmr_metadata_layout_is_valid() &&
           llps_session_tmr_region_guard_is_valid(0u) &&
           llps_session_tmr_region_guard_is_valid(1u) &&
           llps_session_tmr_region_guard_is_valid(2u) &&
           ((uint64_t)llps_abs_addr_distance(addr0, addr1) >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES) &&
           ((uint64_t)llps_abs_addr_distance(addr0, addr2) >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES) &&
           ((uint64_t)llps_abs_addr_distance(addr1, addr2) >=
            LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
}

static bool llps_readiness_runtime_fast_latches_ok(void) {
    return llps_guarded_bool_read(g_process_memory_locked,
                                  g_process_memory_locked_inverse) &&
           llps_guarded_bool_read(g_tmr_memory_locked,
                                  g_tmr_memory_locked_inverse) &&
           llps_guarded_bool_read(g_tmr_memory_prefaulted,
                                  g_tmr_memory_prefaulted_inverse) &&
           llps_tmr_memory_prefault_pages_is_valid() &&
           (llps_tmr_memory_prefault_pages_read() != 0u) &&
           llps_guarded_bool_read(g_tmr_memory_hardened,
                                  g_tmr_memory_hardened_inverse) &&
           llps_guarded_bool_read(g_tmr_startup_self_test_passed,
                                  g_tmr_startup_self_test_passed_inverse) &&
           llps_tmr_startup_self_test_coverage_is_valid() &&
           (g_tmr_startup_self_test_coverage ==
            LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE) &&
           llps_runtime_safety_latches_are_valid();
}

static bool llps_readiness_runtime_fast_counters_ok(void) {
    return llps_memory_safety_counters_are_valid() &&
           (g_memory_safety_counters.tmr_majority_failures == 0u) &&
           (g_memory_safety_counters.tmr_region_guard_faults == 0u) &&
           (g_memory_safety_counters.tmr_layout_failures == 0u) &&
           (g_memory_safety_counters.process_memory_lock_failures == 0u) &&
           (g_memory_safety_counters.tmr_memory_lock_failures == 0u) &&
           (g_memory_safety_counters.tmr_memory_prefault_failures == 0u) &&
           (g_memory_safety_counters.tmr_memory_residency_failures == 0u) &&
           (g_memory_safety_counters.tmr_memory_physical_frame_faults == 0u) &&
           (g_memory_safety_counters.tmr_memory_domain_bind_failures == 0u) &&
           (g_memory_safety_counters.tmr_memory_harden_failures == 0u) &&
           (g_memory_safety_counters.contract_violations == 0u) &&
           (g_memory_safety_counters.free_list_majority_failures == 0u) &&
           (g_memory_safety_counters.runtime_cfg_majority_failures == 0u) &&
           (g_memory_safety_counters.control_flag_majority_failures == 0u) &&
           (g_memory_safety_counters.tmr_scrub_passes != 0u) &&
           (g_memory_safety_counters.tmr_scrub_sessions_checked != 0u) &&
           (g_memory_safety_counters.tmr_scrub_fail_closed_sessions == 0u);
}

static bool llps_readiness_runtime_fast_readiness_counters_ok(void) {
    return (g_memory_safety_counters
                .readiness_runtime_synthetic_ecc_topology_patrol_failures ==
            0u) &&
           (g_memory_safety_counters
                .readiness_runtime_synthetic_fault_patrol_failures == 0u) &&
           (g_memory_safety_counters
                .readiness_runtime_synthetic_numa_patrol_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_monitor_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_cfg_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_software_tmr_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_ecc_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_physical_domain_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_tmr_memory_domain_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_hardware_tmr_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_identity_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_attestation_failures == 0u) &&
           (g_memory_safety_counters.readiness_runtime_observation_digest_failures == 0u);
}

bool llps_readiness_runtime_fast_software_ready(
    llps_yml_config_t * const runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t * const free_sessions_count) {
    if ((runtime_cfg == NULL) || (free_sessions == NULL) ||
        (free_sessions_count == NULL)) {
        return false;
    }

    if (!llps_readiness_runtime_fast_reconciles(runtime_cfg,
                                                free_sessions,
                                                free_sessions_count)) {
        return false;
    }
    if (!llps_readiness_runtime_fast_payload_policy_ok(runtime_cfg)) {
        return false;
    }

    return llps_readiness_runtime_fast_tmr_layout_ok() &&
           llps_readiness_runtime_fast_latches_ok() &&
           llps_readiness_runtime_fast_counters_ok() &&
           llps_readiness_runtime_fast_readiness_counters_ok();
}
