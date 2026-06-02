/**
 * @file src/internal/llps_tmr_memory_regions.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_MEMORY_REGIONS_H
#define LLPS_TMR_MEMORY_REGIONS_H

#include "llps.h"

#include <stddef.h>
#include <stdint.h>

#define LLPS_TMR_MEMORY_REGION_COUNT \
    (LLPS_SESSION_TMR_BANK_COUNT * 4u)

typedef struct {
    void *addr;
    size_t len;
    uint32_t region_id;
    uint32_t bank_id;
} llps_tmr_memory_region_t;

void llps_tmr_memory_regions_snapshot(
    llps_tmr_memory_region_t out_regions[LLPS_TMR_MEMORY_REGION_COUNT]);

#endif /* LLPS_TMR_MEMORY_REGIONS_H */
