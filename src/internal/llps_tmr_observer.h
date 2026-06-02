/**
 * @file src/internal/llps_tmr_observer.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_OBSERVER_H
#define LLPS_TMR_OBSERVER_H

#include "llps.h"
#include "llps_tmr_probe.h"

#include <stdbool.h>
#include <stdint.h>

extern bool g_tmr_memory_domain_probe_override_enabled;
extern uint32_t
    g_tmr_memory_domain_probe_override_domains[LLPS_SESSION_TMR_BANK_COUNT];
extern bool g_tmr_memory_residency_probe_override_enabled;
extern bool g_tmr_memory_residency_probe_override_resident;
extern bool g_tmr_physical_frame_probe_synthetic_enabled;
extern bool g_tmr_physical_frame_probe_override_alias;

/** @brief Enable or disable software-backed TMR placement observations. */
void llps_configure_tmr_software_memory_observation(
    bool enabled,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]);
/** @brief Probe TMR memory residency and return raw platform observation data. */
void llps_probe_tmr_memory_residency(bool *out_resident,
                                     uint64_t *out_resident_pages,
                                     uint32_t *out_residency_fingerprint);
/** @brief Observe TMR memory residency and update guarded runtime latches. */
void llps_observe_tmr_memory_residency(bool *out_resident,
                                       uint64_t *out_resident_pages,
                                       uint32_t *out_residency_fingerprint);
/** @brief Probe whether TMR bank pages map to distinct physical frames. */
void llps_probe_tmr_physical_frames(bool *out_distinct,
                                    bool *out_spaced,
                                    uint64_t *out_pages,
                                    uint64_t *out_probe_failures,
                                    uint64_t *out_min_distance,
                                    uint64_t *out_required_distance,
                                    uint64_t *out_distance_01,
                                    uint64_t *out_distance_02,
                                    uint64_t *out_distance_12,
                                    uint32_t *out_pair_coverage,
                                    uint32_t *out_fingerprint);
/** @brief Observe physical-frame separation and update guarded latches. */
void llps_observe_tmr_physical_frames(bool *out_distinct,
                                      bool *out_spaced,
                                      uint64_t *out_pages,
                                      uint64_t *out_probe_failures,
                                      uint64_t *out_min_distance,
                                      uint64_t *out_required_distance,
                                      uint64_t *out_distance_01,
                                      uint64_t *out_distance_02,
                                      uint64_t *out_distance_12,
                                      uint32_t *out_pair_coverage,
                                      uint32_t *out_fingerprint);
/** @brief Return true when configuration requires physical memory separation. */
bool llps_config_requests_physical_memory_separation(
    const llps_yml_config_t *cfg);
/** @brief Probe TMR memory-domain binding evidence for all configured banks. */
void llps_probe_tmr_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool *out_domains_bound,
    uint32_t *out_observation_fingerprint,
    uint32_t out_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint64_t *out_pages_checked,
    uint64_t *out_mismatch_count,
    uint64_t *out_probe_failures,
    uint32_t *out_region_coverage);
/** @brief Synthesize software-backed TMR memory-domain evidence. */
void llps_synthesize_tmr_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool *out_domains_bound,
    uint32_t *out_observation_fingerprint,
    uint32_t out_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint64_t *out_pages_checked,
    uint64_t *out_mismatch_count,
    uint64_t *out_probe_failures,
    uint32_t *out_region_coverage);
/** @brief Bind TMR memory regions to configured memory domains when supported. */
bool llps_bind_tmr_memory_to_configured_domains(
    const llps_yml_config_t *cfg);
/** @brief Reprobe configured TMR memory-domain binding and refresh latches. */
bool llps_refresh_tmr_memory_domain_binding(
    const llps_yml_config_t *cfg);
/** @brief Apply supported platform hardening to TMR metadata memory. */
bool llps_harden_tmr_memory(void);

#endif /* LLPS_TMR_OBSERVER_H */
