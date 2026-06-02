/**
 * @file src/internal/llps_safety_counters.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_SAFETY_COUNTERS_H
#define LLPS_SAFETY_COUNTERS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t tmr_single_bank_repairs;
    uint64_t tmr_majority_failures;
    uint64_t tmr_region_guard_faults;
    uint64_t tmr_layout_failures;
    uint64_t process_memory_lock_failures;
    uint64_t tmr_memory_lock_failures;
    uint64_t tmr_memory_prefault_failures;
    uint64_t tmr_memory_residency_failures;
    uint64_t tmr_memory_physical_frame_faults;
    uint64_t tmr_memory_domain_bind_failures;
    uint64_t tmr_memory_harden_failures;
    uint64_t contract_violations;
    uint64_t free_list_single_bank_repairs;
    uint64_t free_list_majority_failures;
    uint64_t runtime_cfg_single_bank_repairs;
    uint64_t runtime_cfg_majority_failures;
    uint64_t control_flag_single_bank_repairs;
    uint64_t control_flag_majority_failures;
    uint64_t secded_single_bit_repairs;
    uint64_t secded_double_bit_failures;
    uint64_t tmr_scrub_passes;
    uint64_t tmr_scrub_sessions_checked;
    uint64_t tmr_scrub_fail_closed_sessions;
    uint64_t payload_ecc_scrub_passes;
    uint64_t payload_ecc_scrub_sessions_checked;
    uint64_t payload_ecc_scrub_fail_closed_sessions;
    uint64_t readiness_runtime_monitor_passes;
    uint64_t readiness_runtime_software_evidence_patrol_passes;
    uint64_t readiness_runtime_synthetic_ecc_topology_patrol_passes;
    uint64_t readiness_runtime_synthetic_ecc_topology_patrol_failures;
    uint64_t readiness_runtime_synthetic_fault_patrol_passes;
    uint64_t readiness_runtime_synthetic_fault_patrol_failures;
    uint64_t readiness_runtime_synthetic_numa_patrol_passes;
    uint64_t readiness_runtime_synthetic_numa_patrol_failures;
    uint64_t readiness_runtime_monitor_failures;
    uint64_t readiness_runtime_cfg_failures;
    uint64_t readiness_runtime_software_tmr_failures;
    uint64_t readiness_runtime_ecc_failures;
    uint64_t readiness_runtime_physical_domain_failures;
    uint64_t readiness_runtime_tmr_memory_domain_failures;
    uint64_t readiness_runtime_hardware_tmr_failures;
    uint64_t readiness_runtime_identity_failures;
    uint64_t readiness_runtime_attestation_failures;
    uint64_t readiness_runtime_observation_digest_failures;
} llps_memory_safety_counters_t;

extern llps_memory_safety_counters_t g_memory_safety_counters;
extern uint32_t g_memory_safety_counters_crc;
extern uint32_t g_memory_safety_counters_crc_inverse;

/** @brief Compute the CRC for the guarded memory-safety counter block. */
uint32_t llps_memory_safety_counters_compute_crc(
    const llps_memory_safety_counters_t *counters);
/** @brief Reset all memory-safety counters and reseal the guard. */
void llps_memory_safety_counters_reset(void);
/** @brief Recompute and store the counter block CRC and inverse. */
void llps_memory_safety_counters_seal(void);
/** @brief Validate the counter block CRC and inverse guard. */
bool llps_memory_safety_counters_are_valid(void);

/** @brief Increment one safety counter and reseal when the block was valid. */
#define LLPS_MEMORY_SAFETY_COUNTER_INC(counter_field) \
    do { \
        const bool llps_counter_block_was_valid = \
            llps_memory_safety_counters_are_valid(); \
        ++g_memory_safety_counters.counter_field; \
        if (llps_counter_block_was_valid) { \
            llps_memory_safety_counters_seal(); \
        } \
    } while (false)

#endif /* LLPS_SAFETY_COUNTERS_H */
