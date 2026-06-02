/**
 * @file src/internal/llps_readiness_runtime_failures.h
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#ifndef LLPS_READINESS_RUNTIME_FAILURES_H
#define LLPS_READINESS_RUNTIME_FAILURES_H

#include "llps.h"

#include <stdint.h>

#define LLPS_READINESS_RUNTIME_FAILURE_CFG (1u << 0u)
#define LLPS_READINESS_RUNTIME_FAILURE_SOFTWARE_TMR (1u << 1u)
#define LLPS_READINESS_RUNTIME_FAILURE_ECC (1u << 2u)
#define LLPS_READINESS_RUNTIME_FAILURE_PHYSICAL_DOMAIN (1u << 3u)
#define LLPS_READINESS_RUNTIME_FAILURE_TMR_MEMORY_DOMAIN (1u << 4u)
#define LLPS_READINESS_RUNTIME_FAILURE_HW_TMR (1u << 5u)
#define LLPS_READINESS_RUNTIME_FAILURE_IDENTITY (1u << 6u)
#define LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION (1u << 7u)
#define LLPS_READINESS_RUNTIME_FAILURE_OBSERVATION_DIGEST (1u << 8u)
#define LLPS_READINESS_RUNTIME_DETAIL_TMR_RESIDENCY (1u << 16u)
#define LLPS_READINESS_RUNTIME_DETAIL_TMR_PHYSICAL_FRAME (1u << 17u)
#define LLPS_READINESS_RUNTIME_DETAIL_TMR_DOMAIN_BIND (1u << 18u)

/** @brief Increment readiness runtime failure counters from a missing mask. */
void llps_readiness_runtime_monitor_count_failure_mask(uint32_t failure_mask);
/** @brief Increment detailed readiness runtime failure counters from a mask. */
void llps_readiness_runtime_monitor_count_failure_details(uint32_t failure_mask);
/** @brief Convert runtime configuration validity into a failure mask. */
uint32_t llps_readiness_runtime_collection_failure_mask_from_cfg(
    const llps_yml_config_t *cfg);

#endif /* LLPS_READINESS_RUNTIME_FAILURES_H */
