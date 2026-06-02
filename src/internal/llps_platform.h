/**
 * @file src/internal/llps_platform.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_PLATFORM_H
#define LLPS_PLATFORM_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

#define LLPS_BOOT_ID_PATH                 "/proc/sys/kernel/random/boot_id"
#define LLPS_BOOT_ID_TEXT_BYTES           (64u)
#define LLPS_PLATFORM_ID_PATH             "/sys/class/dmi/id/product_uuid"
#define LLPS_PLATFORM_ID_TEXT_BYTES        (128u)
#define LLPS_EXECUTABLE_PATH_BYTES         (1024u)
#define LLPS_EXECUTABLE_READ_BYTES         (4096u)

/** @brief Compute a stable fingerprint for the current boot identity. */
uint32_t llps_platform_boot_fingerprint(const char *boot_id_path);
/** @brief Compute a stable fingerprint for the current platform identity. */
uint32_t llps_platform_identity_fingerprint(const char *platform_id_path);
/** @brief Compute deterministic platform identity for synthetic evidence mode. */
uint32_t llps_platform_synthetic_identity_fingerprint(
    uint64_t evidence_id,
    bool software_ecc_enabled,
    uint32_t software_ecc_controller_count,
    uint32_t software_ecc_dimm_count,
    uint64_t software_ecc_scrub_rate,
    uint64_t software_ecc_controller_corrected_error_count,
    uint64_t software_ecc_controller_uncorrected_error_count,
    uint64_t software_ecc_dimm_corrected_error_count,
    uint64_t software_ecc_dimm_uncorrected_error_count,
    bool software_numa_enabled,
    uint64_t software_numa_memtotal_kib,
    uint64_t software_numa_local_distance,
    uint64_t software_numa_remote_distance,
    uint32_t software_fault_injection_mode,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id);
/** @brief Compute a bounded fingerprint of the running executable image. */
uint32_t llps_platform_executable_image_fingerprint(
    const char *executable_image_path);

#endif /* LLPS_PLATFORM_H */
