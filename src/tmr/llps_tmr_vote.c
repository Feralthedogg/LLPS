/**
 * @file src/tmr/llps_tmr_vote.c
 * @brief Shared TMR majority-vote helper implementation.
 *
 * @details
 * The helper performs only the common fixed bank-pair selection. Callers still
 * decide how to validate banks, compare typed snapshot payloads, repair
 * outliers, and account safety counters.
 */

#include "llps_tmr_vote.h"

#include <stddef.h>

bool llps_tmr_vote_find_matching_pair(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    const bool equal_01,
    const bool equal_02,
    const bool equal_12,
    uint32_t * const out_majority_index) {
    if ((valid == NULL) || (out_majority_index == NULL)) {
        return false;
    }

    if (valid[0u] && valid[1u] && equal_01) {
        *out_majority_index = 0u;
        return true;
    }
    if (valid[0u] && valid[2u] && equal_02) {
        *out_majority_index = 0u;
        return true;
    }
    if (valid[1u] && valid[2u] && equal_12) {
        *out_majority_index = 1u;
        return true;
    }

    return false;
}
