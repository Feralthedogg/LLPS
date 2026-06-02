/**
 * @file src/session/llps_safety_counters.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_safety_counters.h"

#include "llps_crc.h"

#include <stdint.h>
#include <string.h>

llps_memory_safety_counters_t g_memory_safety_counters;
uint32_t g_memory_safety_counters_crc = 0u;
uint32_t g_memory_safety_counters_crc_inverse = UINT32_MAX;

static uint32_t llps_memory_safety_counters_crc_tmr(
    uint32_t crc,
    const llps_memory_safety_counters_t * const counters) {
    crc = llps_crc32_update_u64(crc, counters->tmr_single_bank_repairs);
    crc = llps_crc32_update_u64(crc, counters->tmr_majority_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_region_guard_faults);
    crc = llps_crc32_update_u64(crc, counters->tmr_layout_failures);
    crc = llps_crc32_update_u64(crc, counters->process_memory_lock_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_lock_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_prefault_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_residency_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_physical_frame_faults);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_domain_bind_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_memory_harden_failures);
    crc = llps_crc32_update_u64(crc, counters->contract_violations);
    return crc;
}

static uint32_t llps_memory_safety_counters_crc_session(
    uint32_t crc,
    const llps_memory_safety_counters_t * const counters) {
    crc = llps_crc32_update_u64(crc, counters->free_list_single_bank_repairs);
    crc = llps_crc32_update_u64(crc, counters->free_list_majority_failures);
    crc = llps_crc32_update_u64(crc, counters->runtime_cfg_single_bank_repairs);
    crc = llps_crc32_update_u64(crc, counters->runtime_cfg_majority_failures);
    crc = llps_crc32_update_u64(crc, counters->control_flag_single_bank_repairs);
    crc = llps_crc32_update_u64(crc, counters->control_flag_majority_failures);
    crc = llps_crc32_update_u64(crc, counters->secded_single_bit_repairs);
    crc = llps_crc32_update_u64(crc, counters->secded_double_bit_failures);
    crc = llps_crc32_update_u64(crc, counters->tmr_scrub_passes);
    crc = llps_crc32_update_u64(crc, counters->tmr_scrub_sessions_checked);
    crc = llps_crc32_update_u64(crc, counters->tmr_scrub_fail_closed_sessions);
    crc = llps_crc32_update_u64(crc, counters->payload_ecc_scrub_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->payload_ecc_scrub_sessions_checked);
    crc = llps_crc32_update_u64(
        crc,
        counters->payload_ecc_scrub_fail_closed_sessions);
    return crc;
}

static uint32_t llps_memory_safety_counters_crc_readiness(
    uint32_t crc,
    const llps_memory_safety_counters_t * const counters) {
    crc = llps_crc32_update_u64(crc, counters->readiness_runtime_monitor_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_software_evidence_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_ecc_topology_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_ecc_topology_patrol_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_fault_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_fault_patrol_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_numa_patrol_passes);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_synthetic_numa_patrol_failures);
    crc = llps_crc32_update_u64(crc, counters->readiness_runtime_monitor_failures);
    crc = llps_crc32_update_u64(crc, counters->readiness_runtime_cfg_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_software_tmr_failures);
    crc = llps_crc32_update_u64(crc, counters->readiness_runtime_ecc_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_physical_domain_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_tmr_memory_domain_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_hardware_tmr_failures);
    crc = llps_crc32_update_u64(crc, counters->readiness_runtime_identity_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_attestation_failures);
    crc = llps_crc32_update_u64(
        crc,
        counters->readiness_runtime_observation_digest_failures);
    return crc;
}

uint32_t llps_memory_safety_counters_compute_crc(
    const llps_memory_safety_counters_t * const counters) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (counters == NULL) {
        return 0u;
    }

    crc = llps_memory_safety_counters_crc_tmr(crc, counters);
    crc = llps_memory_safety_counters_crc_session(crc, counters);
    crc = llps_memory_safety_counters_crc_readiness(crc, counters);
    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

void llps_memory_safety_counters_reset(void) {
    (void)memset(&g_memory_safety_counters,
                 0,
                 sizeof(g_memory_safety_counters));
    llps_memory_safety_counters_seal();
}

void llps_memory_safety_counters_seal(void) {
    g_memory_safety_counters_crc =
        llps_memory_safety_counters_compute_crc(&g_memory_safety_counters);
    g_memory_safety_counters_crc_inverse = ~g_memory_safety_counters_crc;
}

bool llps_memory_safety_counters_are_valid(void) {
    const uint32_t crc =
        llps_memory_safety_counters_compute_crc(&g_memory_safety_counters);

    return (g_memory_safety_counters_crc_inverse ==
            ~g_memory_safety_counters_crc) &&
           (g_memory_safety_counters_crc == crc) &&
           (crc != 0u);
}
