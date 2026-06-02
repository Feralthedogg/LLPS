/**
 * @file src/internal/llps_llam_contract.h
 * @brief LLAM runtime policy checks required by LLPS internals.
 */

#ifndef LLPS_LLAM_CONTRACT_H
#define LLPS_LLAM_CONTRACT_H

#include "llam/runtime.h"

#include <stdbool.h>

bool llps_llam_runtime_stats_satisfy_single_worker_contract(
    const llam_runtime_stats_t *stats);

#endif /* LLPS_LLAM_CONTRACT_H */
