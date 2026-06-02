/**
 * @file src/platform/llps_domain.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_domain.h"

#include <stddef.h>
#include <stdint.h>

bool llps_domain_ids_are_distinct(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (ids == NULL) {
        return false;
    }

    return (ids[0] != 0u) &&
           (ids[1] != 0u) &&
           (ids[2] != 0u) &&
           (ids[0] != ids[1]) &&
           (ids[0] != ids[2]) &&
           (ids[1] != ids[2]);
}

bool llps_domain_ids_are_zero(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (ids == NULL) {
        return true;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (ids[i] != 0u) {
            return false;
        }
    }

    return true;
}

bool llps_domain_id_sets_are_disjoint(
    const uint32_t lhs[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t rhs[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        for (size_t j = 0u; j < LLPS_SESSION_TMR_BANK_COUNT; ++j) {
            if ((lhs[i] == 0u) || (rhs[j] == 0u) || (lhs[i] == rhs[j])) {
                return false;
            }
        }
    }

    return true;
}

bool llps_domain_id_is_disjoint_from_set(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t domain_id) {
    if ((ids == NULL) || (domain_id == 0u)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if ((ids[i] == 0u) || (ids[i] == domain_id)) {
            return false;
        }
    }

    return true;
}

bool llps_domain_ids_match(
    const uint32_t lhs[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t rhs[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }

    return true;
}
