/**
 * @file src/internal/llps_domain.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_DOMAIN_H
#define LLPS_DOMAIN_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

bool llps_domain_ids_are_distinct(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]);
bool llps_domain_ids_are_zero(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT]);
bool llps_domain_id_sets_are_disjoint(
    const uint32_t lhs[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t rhs[LLPS_SESSION_TMR_BANK_COUNT]);
bool llps_domain_id_is_disjoint_from_set(
    const uint32_t ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t domain_id);
bool llps_domain_ids_match(
    const uint32_t lhs[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t rhs[LLPS_SESSION_TMR_BANK_COUNT]);

#endif /* LLPS_DOMAIN_H */
