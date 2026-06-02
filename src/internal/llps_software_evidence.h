/**
 * @file src/internal/llps_software_evidence.h
 * @brief Self-tested synthetic platform evidence helpers.
 */

#ifndef LLPS_SOFTWARE_EVIDENCE_H
#define LLPS_SOFTWARE_EVIDENCE_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool required;
    bool passed;
    uint32_t schema_version;
    uint32_t coverage;
    uint32_t required_coverage;
    uint32_t controller_count;
    uint32_t bank_count;
    uint64_t scrub_rate;
    uint32_t generation;
    uint32_t scrub_generation;
    uint32_t fault_injection_coverage;
    uint32_t fault_injection_mode;
    uint32_t fingerprint;
    uint32_t numa_profile_fingerprint;
} llps_software_evidence_observation_t;

bool llps_platform_evidence_mode_is_valid(uint32_t mode);
bool llps_platform_evidence_mode_uses_software(uint32_t mode);
const char *llps_platform_evidence_mode_text(uint32_t mode);
const char *llps_platform_evidence_scope_text(uint32_t mode);
const char *llps_software_fault_injection_mode_text(uint32_t mode);
const char *llps_ecc_evidence_scope_text(uint32_t mode,
                                         bool software_ecc_enabled);
const char *llps_physical_memory_evidence_scope_text(
    uint32_t mode,
    bool software_numa_enabled);
const char *llps_independent_tmr_evidence_scope_text(uint32_t mode);
void llps_software_evidence_observe(
    uint32_t mode,
    bool software_ecc_enabled,
    uint32_t software_ecc_controller_count,
    uint32_t software_ecc_dimm_count,
    uint64_t software_ecc_scrub_rate,
    bool software_numa_enabled,
    uint64_t software_numa_memtotal_kib,
    uint64_t software_numa_local_distance,
    uint64_t software_numa_remote_distance,
    uint32_t software_fault_injection_mode,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    llps_software_evidence_observation_t *out_observation);
bool llps_software_evidence_observation_is_ready(
    const llps_software_evidence_observation_t *observation);

#endif /* LLPS_SOFTWARE_EVIDENCE_H */
