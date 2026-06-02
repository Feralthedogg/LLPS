/**
 * @file src/readiness/llps_readiness_runtime_failures.c
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#include "llps_readiness_runtime_failures.h"

#include "llps_safety_counters.h"

#include <stddef.h>

void llps_readiness_runtime_monitor_count_failure_mask(
    const uint32_t failure_mask) {
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_CFG) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_cfg_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_software_tmr_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_ECC) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_PHYSICAL_DOMAIN) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_physical_domain_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_TMR_MEMORY_DOMAIN) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_tmr_memory_domain_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_HW_TMR) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_hardware_tmr_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_IDENTITY) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_identity_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_attestation_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_FAILURE_OBSERVATION_DIGEST) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(
            readiness_runtime_observation_digest_failures);
    }
}

void llps_readiness_runtime_monitor_count_failure_details(
    const uint32_t failure_mask) {
    if ((failure_mask & LLPS_READINESS_RUNTIME_DETAIL_TMR_RESIDENCY) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_residency_failures);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_DETAIL_TMR_PHYSICAL_FRAME) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_physical_frame_faults);
    }
    if ((failure_mask & LLPS_READINESS_RUNTIME_DETAIL_TMR_DOMAIN_BIND) != 0u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
    }
}

uint32_t llps_readiness_runtime_collection_failure_mask_from_cfg(
    const llps_yml_config_t * const cfg) {
    uint32_t failure_mask = LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION;

    if (cfg == NULL) {
        return LLPS_READINESS_RUNTIME_FAILURE_CFG;
    }
    if ((cfg->platform_safety_flags &
         (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY |
          LLPS_PLATFORM_EVIDENCE_ECC_CLEAN)) != 0u) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_ECC;
    }
    if ((cfg->platform_safety_flags &
         LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_PHYSICAL_DOMAIN |
                        LLPS_READINESS_RUNTIME_FAILURE_TMR_MEMORY_DOMAIN;
    }
    if ((cfg->platform_safety_flags &
         LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) {
        failure_mask |= LLPS_READINESS_RUNTIME_FAILURE_HW_TMR;
    }

    return failure_mask;
}
