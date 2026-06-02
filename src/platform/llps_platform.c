/**
 * @file src/platform/llps_platform.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_platform.h"

#include "llps_crc.h"
#include "llps_domain.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/dyld.h>
#endif
#include <unistd.h>

#define LLPS_SYNTHETIC_IDENTITY_MAGIC (0x51D7E17u)

static bool llps_platform_attestation_inputs_invalid(
    const uint32_t flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id) {
    const uint32_t attested_flags =
        flags & LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK;

    return ((flags & ~LLPS_PLATFORM_EVIDENCE_REQUIRED) != 0u) ||
           ((attested_flags != 0u) && (evidence_id == 0u)) ||
           (((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) == 0u) &&
            !llps_domain_ids_are_zero(physical_memory_domain_ids)) ||
           (((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) == 0u) &&
            (!llps_domain_ids_are_zero(hardware_tmr_domain_ids) ||
             (hardware_tmr_voter_domain_id != 0u))) ||
           (((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) &&
            !llps_domain_ids_are_distinct(physical_memory_domain_ids)) ||
           (((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) &&
            (!llps_domain_ids_are_distinct(hardware_tmr_domain_ids) ||
             !llps_domain_id_is_disjoint_from_set(hardware_tmr_domain_ids,
                                                  hardware_tmr_voter_domain_id))) ||
           ((attested_flags == LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK) &&
            (!llps_domain_id_sets_are_disjoint(physical_memory_domain_ids,
                                               hardware_tmr_domain_ids) ||
             !llps_domain_id_is_disjoint_from_set(physical_memory_domain_ids,
                                                  hardware_tmr_voter_domain_id)));
}

static uint32_t llps_platform_attestation_domains_crc(
    uint32_t crc,
    const uint32_t attested_flags,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_BANK_COUNT);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        const uint32_t physical_domain =
            (physical_memory_domain_ids != NULL) ?
            physical_memory_domain_ids[i] :
            0u;
        const uint32_t hardware_domain =
            (hardware_tmr_domain_ids != NULL) ?
            hardware_tmr_domain_ids[i] :
            0u;

        crc = llps_crc32_update_u32(
            crc,
            ((attested_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u) ?
            physical_domain :
            0u);
        crc = llps_crc32_update_u32(
            crc,
            ((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) ?
            hardware_domain :
            0u);
    }
    return crc;
}

llps_status_t llps_compute_platform_attestation_fingerprint(
    const uint32_t flags,
    const uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id,
    uint32_t * const out_fingerprint) {
    const uint32_t attested_flags =
        flags & LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK;
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (out_fingerprint == NULL) {
        return LLPS_E_NULL;
    }

    *out_fingerprint = 0u;

    if (llps_platform_attestation_inputs_invalid(flags,
                                                 evidence_id,
                                                 physical_memory_domain_ids,
                                                 hardware_tmr_domain_ids,
                                                 hardware_tmr_voter_domain_id)) {
        return LLPS_E_RANGE;
    }

    if (attested_flags == 0u) {
        return LLPS_OK;
    }

    crc = llps_crc32_update_u32(crc, LLPS_PLATFORM_EVIDENCE_MAGIC);
    crc = llps_crc32_update_u32(crc, LLPS_PLATFORM_EVIDENCE_VERSION);
    crc = llps_crc32_update_u32(crc, attested_flags);
    crc = llps_crc32_update_u64(crc, evidence_id);
    crc = llps_platform_attestation_domains_crc(crc,
                                                attested_flags,
                                                physical_memory_domain_ids,
                                                hardware_tmr_domain_ids);
    crc = llps_crc32_update_u32(
        crc,
        ((attested_flags & LLPS_PLATFORM_EVIDENCE_HW_TMR) != 0u) ?
        hardware_tmr_voter_domain_id :
        0u);

    *out_fingerprint = llps_nonzero_fingerprint(
        crc ^ LLPS_SESSION_CRC_XOROUT);
    return LLPS_OK;
}

static uint32_t llps_platform_text_file_fingerprint(const char * const path,
                                                    const size_t text_cap) {
    char text[LLPS_PLATFORM_ID_TEXT_BYTES];
    FILE *fp = NULL;
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if ((path == NULL) ||
        (text_cap == 0u) ||
        (text_cap > sizeof(text))) {
        return 0u;
    }

    (void)memset(text, 0, sizeof(text));
    fp = fopen(path, "r");
    if (fp == NULL) {
        return 0u;
    }

    if (fgets(text, (int)text_cap, fp) == NULL) {
        (void)fclose(fp);
        return 0u;
    }

    if (fclose(fp) != 0) {
        return 0u;
    }

    for (size_t i = 0u; i < text_cap; ++i) {
        if ((text[i] == '\n') || (text[i] == '\r')) {
            text[i] = '\0';
            break;
        }
        if (text[i] == '\0') {
            break;
        }
    }

    if (text[0] == '\0') {
        return 0u;
    }

    crc = llps_crc32_update_cstr_bounded(crc, text, text_cap);
    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}

uint32_t llps_platform_boot_fingerprint(const char * const boot_id_path) {
    return llps_platform_text_file_fingerprint(boot_id_path,
                                               LLPS_BOOT_ID_TEXT_BYTES);
}

uint32_t llps_platform_identity_fingerprint(const char * const platform_id_path) {
    return llps_platform_text_file_fingerprint(platform_id_path,
                                               LLPS_PLATFORM_ID_TEXT_BYTES);
}

uint32_t llps_platform_synthetic_identity_fingerprint(
    const uint64_t evidence_id,
    const bool software_ecc_enabled,
    const uint32_t software_ecc_controller_count,
    const uint32_t software_ecc_dimm_count,
    const uint64_t software_ecc_scrub_rate,
    const uint64_t software_ecc_controller_corrected_error_count,
    const uint64_t software_ecc_controller_uncorrected_error_count,
    const uint64_t software_ecc_dimm_corrected_error_count,
    const uint64_t software_ecc_dimm_uncorrected_error_count,
    const bool software_numa_enabled,
    const uint64_t software_numa_memtotal_kib,
    const uint64_t software_numa_local_distance,
    const uint64_t software_numa_remote_distance,
    const uint32_t software_fault_injection_mode,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_voter_domain_id) {
    const uint64_t effective_local_distance =
        (software_numa_local_distance != 0u) ?
        software_numa_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t effective_remote_distance =
        (software_numa_remote_distance != 0u) ?
        software_numa_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if ((evidence_id == 0u) ||
        !software_ecc_enabled ||
        (software_ecc_controller_count == 0u) ||
        (software_ecc_controller_count >
         LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) ||
        (software_ecc_dimm_count == 0u) ||
        (software_ecc_controller_count > software_ecc_dimm_count) ||
        (software_ecc_scrub_rate == 0u) ||
        (software_ecc_scrub_rate > LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX) ||
        !software_numa_enabled ||
        (software_numa_memtotal_kib == 0u) ||
        (effective_local_distance == 0u) ||
        (effective_remote_distance <= effective_local_distance) ||
        (effective_local_distance > LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ||
        (effective_remote_distance > LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ||
        (software_fault_injection_mode >
         LLPS_SOFTWARE_FAULT_INJECTION_MAX) ||
        (physical_memory_domain_ids == NULL) ||
        (hardware_tmr_domain_ids == NULL)) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, LLPS_SYNTHETIC_IDENTITY_MAGIC);
    crc = llps_crc32_update_u32(crc, LLPS_PLATFORM_EVIDENCE_MAGIC);
    crc = llps_crc32_update_u32(crc, LLPS_PLATFORM_EVIDENCE_VERSION);
    crc = llps_crc32_update_u64(crc, evidence_id);
    crc = llps_crc32_update_u32(crc, software_ecc_controller_count);
    crc = llps_crc32_update_u32(crc, software_ecc_dimm_count);
    crc = llps_crc32_update_u64(crc, software_ecc_scrub_rate);
    crc = llps_crc32_update_u64(
        crc,
        software_ecc_controller_corrected_error_count);
    crc = llps_crc32_update_u64(
        crc,
        software_ecc_controller_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc,
                                software_ecc_dimm_corrected_error_count);
    crc = llps_crc32_update_u64(crc,
                                software_ecc_dimm_uncorrected_error_count);
    crc = llps_crc32_update_u64(crc, software_numa_memtotal_kib);
    crc = llps_crc32_update_u64(crc, effective_local_distance);
    crc = llps_crc32_update_u64(crc, effective_remote_distance);
    crc = llps_crc32_update_u32(crc, software_fault_injection_mode);
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_BANK_COUNT);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        crc = llps_crc32_update_u32(crc, physical_memory_domain_ids[i]);
        crc = llps_crc32_update_u32(crc, hardware_tmr_domain_ids[i]);
    }
    crc = llps_crc32_update_u32(crc, hardware_tmr_voter_domain_id);

    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}

static bool llps_platform_resolve_executable_path(
    const char * const executable_image_path,
    char path[LLPS_EXECUTABLE_PATH_BYTES]) {
    if (path == NULL) {
        return false;
    }

    (void)memset(path, 0, LLPS_EXECUTABLE_PATH_BYTES);

    if (executable_image_path != NULL) {
        (void)strncpy(path,
                      executable_image_path,
                      LLPS_EXECUTABLE_PATH_BYTES - 1u);
        path[LLPS_EXECUTABLE_PATH_BYTES - 1u] = '\0';
        return path[0] != '\0';
    }

#if defined(__linux__)
    {
        const ssize_t n =
            readlink("/proc/self/exe", path, LLPS_EXECUTABLE_PATH_BYTES - 1u);
        if (n <= 0) {
            path[0] = '\0';
            return false;
        }
        path[(size_t)n] = '\0';
        return true;
    }
#elif defined(__APPLE__) && defined(__MACH__)
    {
        uint32_t size = LLPS_EXECUTABLE_PATH_BYTES;
        if (_NSGetExecutablePath(path, &size) != 0) {
            path[0] = '\0';
            return false;
        }
        path[LLPS_EXECUTABLE_PATH_BYTES - 1u] = '\0';
        return path[0] != '\0';
    }
#else
    return false;
#endif
}

uint32_t llps_platform_executable_image_fingerprint(
    const char * const executable_image_path) {
    char path[LLPS_EXECUTABLE_PATH_BYTES];
    uint8_t buf[LLPS_EXECUTABLE_READ_BYTES];
    FILE *fp = NULL;
    uint32_t crc = LLPS_SESSION_CRC_INIT;
    uint64_t total_bytes = 0u;
    bool read_error = false;

    if (!llps_platform_resolve_executable_path(executable_image_path, path)) {
        return 0u;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_cstr_bounded(crc,
                                         path,
                                         LLPS_EXECUTABLE_PATH_BYTES);
    for (uint64_t read_cycle = 0u; read_cycle < UINT64_MAX; ++read_cycle) {
        const size_t n = fread(buf, 1u, sizeof(buf), fp);

        if (n > 0u) {
            for (size_t i = 0u; i < n; ++i) {
                crc = llps_crc32_update_byte(crc, buf[i]);
            }
            total_bytes += (uint64_t)n;
        }
        if (n < sizeof(buf)) {
            if (ferror(fp) != 0) {
                read_error = true;
            }
            break;
        }
    }

    if (fclose(fp) != 0) {
        return 0u;
    }
    if (read_error || (total_bytes == 0u)) {
        return 0u;
    }

    crc = llps_crc32_update_u64(crc, total_bytes);
    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}
