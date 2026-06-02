/**
 * @file src/internal/llps_tmr_vote.h
 * @brief Shared TMR majority-vote helper contract.
 *
 * @details
 * TMR modules compute typed equality at each call site, then use this helper
 * only for the fixed three-bank pair selection. That keeps the call graph
 * static and avoids callback-based indirect calls in the TMR core.
 */

#ifndef LLPS_TMR_VOTE_H
#define LLPS_TMR_VOTE_H

#include "llps_config.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Locate any valid two-bank majority among three fixed TMR banks.
 *
 * @details
 * Callers pass already-computed typed equality results for bank pairs 0-1,
 * 0-2, and 1-2. The helper never performs an indirect comparison call.
 *
 * @param valid Three validity flags, one per TMR bank.
 * @param equal_01 True when bank 0 and bank 1 snapshots match.
 * @param equal_02 True when bank 0 and bank 2 snapshots match.
 * @param equal_12 True when bank 1 and bank 2 snapshots match.
 * @param out_majority_index Destination bank index for the majority value.
 *
 * @return true when a two-bank majority exists.
 */
bool llps_tmr_vote_find_matching_pair(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    bool equal_01,
    bool equal_02,
    bool equal_12,
    uint32_t *out_majority_index);

#endif /* LLPS_TMR_VOTE_H */
