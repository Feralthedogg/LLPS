/**
 * @file src/internal/llps_edac.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_EDAC_H
#define LLPS_EDAC_H

#include <stdbool.h>
#include <stdint.h>

#define LLPS_EDAC_SYSFS_ROOT              "/sys/devices/system/edac/mc"
#define LLPS_EDAC_COUNTER_TEXT_BYTES      (32u)
#define LLPS_EDAC_MODE_TEXT_BYTES         (64u)
#define LLPS_EDAC_PATH_BYTES              (256u)

typedef struct {
    uint32_t controller_count;
    uint32_t dimm_count;
    uint32_t scrub_rate_count;
    uint32_t controller_counter_coverage;
    uint32_t dimm_mode_coverage;
    uint32_t dimm_counter_coverage;
    uint32_t scrub_rate_coverage;
    uint64_t corrected_error_count;
    uint64_t uncorrected_error_count;
    uint64_t dimm_corrected_error_count;
    uint64_t dimm_uncorrected_error_count;
    uint64_t scrub_rate_sum;
} llps_edac_observation_t;

/** @brief Clear an EDAC observation to a deterministic empty state. */
void llps_edac_observation_clear(llps_edac_observation_t *observation);
/** @brief Encode platform evidence flags from observed EDAC state. */
uint32_t llps_edac_observed_flags(bool ecc_present, bool ecc_clean);
/** @brief Probe EDAC sysfs for ECC presence, counters, and fingerprint data. */
void llps_edac_probe_ecc(const char *root,
                         bool *out_ecc_present,
                         bool *out_counters_clean,
                         uint32_t *out_observation_fingerprint,
                         llps_edac_observation_t *out_observation);
/** @brief Build operator-configured synthetic ECC evidence. */
void llps_edac_synthesize_ecc(uint32_t controller_count,
                              uint32_t dimm_count,
                              uint64_t scrub_rate,
                              uint64_t controller_corrected_error_count,
                              uint64_t controller_uncorrected_error_count,
                              uint64_t dimm_corrected_error_count,
                              uint64_t dimm_uncorrected_error_count,
                              bool *out_ecc_present,
                              bool *out_counters_clean,
                              uint32_t *out_observation_fingerprint,
                              llps_edac_observation_t *out_observation);

#endif /* LLPS_EDAC_H */
