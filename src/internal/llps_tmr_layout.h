/**
 * @file src/internal/llps_tmr_layout.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_LAYOUT_H
#define LLPS_TMR_LAYOUT_H

#include <stdbool.h>
#include <stdint.h>

/** @brief Return the absolute distance between two addresses. */
static inline uintptr_t llps_abs_addr_distance(uintptr_t lhs, uintptr_t rhs) {
    return (lhs >= rhs) ? (lhs - rhs) : (rhs - lhs);
}
/** @brief Return the minimum pairwise distance in a three-bank TMR triplet. */
uintptr_t llps_tmr_triplet_min_bank_distance(const void *bank0,
                                             const void *bank1,
                                             const void *bank2);
/** @brief Validate that a three-bank TMR triplet satisfies spacing policy. */
bool llps_tmr_triplet_layout_is_valid(const void *bank0,
                                      const void *bank1,
                                      const void *bank2);
/** @brief Return the observed minimum metadata-bank address distance. */
uint64_t llps_tmr_metadata_min_bank_distance(void);
/** @brief Compute a fingerprint of protected TMR metadata layout. */
uint32_t llps_tmr_layout_fingerprint(void);
/** @brief Validate session TMR bank layout and spacing. */
bool llps_session_tmr_layout_is_valid(void);
/** @brief Validate all TMR metadata-bank layouts and spacing. */
bool llps_tmr_metadata_layout_is_valid(void);

#endif /* LLPS_TMR_LAYOUT_H */
