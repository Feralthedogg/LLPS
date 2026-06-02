/**
 * @file src/internal/llps_evidence.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_EVIDENCE_H
#define LLPS_EVIDENCE_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

/** @brief Return all platform evidence flags known by this build. */
uint32_t llps_platform_safety_evidence_known_flags(void);
/** @brief Validate domain ID arrays against their bitwise inverses. */
bool llps_platform_domain_inverses_are_valid(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t ids_inverse[LLPS_SESSION_TMR_BANK_COUNT]);
/** @brief Compute the CRC for one bound platform evidence record. */
uint32_t llps_platform_safety_evidence_compute_crc(
    const llps_platform_safety_evidence_t *evidence);
/** @brief Compute the observation digest subset of a platform evidence record. */
uint32_t llps_platform_safety_evidence_compute_observation_digest(
    const llps_platform_safety_evidence_t *evidence);

#endif /* LLPS_EVIDENCE_H */
