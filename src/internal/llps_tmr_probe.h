/**
 * @file src/internal/llps_tmr_probe.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_PROBE_H
#define LLPS_TMR_PROBE_H

#include "llps_tmr_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t pages_checked;
    uint64_t resident_pages;
    uint64_t nonresident_pages;
    uint64_t probe_failures;
    uint32_t page_mix;
    uint32_t page_sum;
} llps_tmr_memory_residency_probe_t;

typedef struct {
    uint64_t pages_checked;
    uint64_t distinct_pages;
    uint64_t duplicate_pages;
    uint64_t probe_failures;
    uint64_t min_cross_bank_distance;
    uint64_t pair_min_distances[LLPS_TMR_PHYSICAL_FRAME_PAIR_COUNT];
    uint32_t pair_coverage_mask;
    bool min_cross_bank_distance_seen;
    uint32_t page_mix;
    uint32_t page_sum;
    uint64_t observed_pfns[LLPS_TMR_PHYSICAL_FRAME_MAX_PAGES];
    uint32_t observed_pfn_bank_ids[LLPS_TMR_PHYSICAL_FRAME_MAX_PAGES];
    size_t observed_pfn_count;
} llps_tmr_physical_frame_probe_t;

/** @brief Initialize a TMR memory residency probe accumulator. */
void llps_tmr_memory_residency_probe_init(
    llps_tmr_memory_residency_probe_t *probe);
/** @brief Fold one page residency observation into an accumulator. */
void llps_tmr_memory_residency_probe_note_page(
    llps_tmr_memory_residency_probe_t *probe,
    uint32_t region_id,
    uintptr_t page_addr,
    bool probe_ok,
    bool resident);

/** @brief Initialize a TMR physical-frame probe accumulator. */
void llps_tmr_physical_frame_probe_init(
    llps_tmr_physical_frame_probe_t *probe);
/** @brief Return the absolute distance between two unsigned 64-bit values. */
uint64_t llps_abs_u64_distance(uint64_t lhs, uint64_t rhs);
/** @brief Map a pair of TMR bank IDs to a stable pair-distance index. */
bool llps_tmr_physical_frame_pair_index(uint32_t lhs_bank_id,
                                        uint32_t rhs_bank_id,
                                        size_t *out_index);
/** @brief Fold one cross-bank PFN distance into an accumulator. */
void llps_tmr_physical_frame_probe_note_distance(
    llps_tmr_physical_frame_probe_t *probe,
    uint32_t lhs_bank_id,
    uint32_t rhs_bank_id,
    uint64_t distance);
/** @brief Return the minimum PFN spacing required by policy. */
uint64_t llps_tmr_physical_frame_required_distance_pages(void);
/** @brief Return true when a PFN has already been seen in a probe. */
bool llps_tmr_physical_frame_probe_seen(
    const llps_tmr_physical_frame_probe_t *probe,
    uint64_t pfn);
/** @brief Fold one page PFN observation into an accumulator. */
void llps_tmr_physical_frame_probe_note_page(
    llps_tmr_physical_frame_probe_t *probe,
    uint32_t region_id,
    uint32_t bank_id,
    uintptr_t page_addr,
    bool probe_ok,
    uint64_t pfn);

#endif /* LLPS_TMR_PROBE_H */
