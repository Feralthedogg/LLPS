/**
 * @file src/support/llps_llam_contract.c
 * @brief Shared LLAM runtime policy predicates.
 */

#include "llps_llam_contract.h"

bool llps_llam_runtime_stats_satisfy_single_worker_contract(
    const llam_runtime_stats_t * const stats) {
    if (stats == NULL) {
        return false;
    }

    return (stats->active_workers == 1u) &&
           (stats->online_workers == 1u) &&
           (stats->online_workers_floor == 1u) &&
           (stats->online_workers_min == 1u) &&
           (stats->online_workers_max == 1u) &&
           (stats->active_nodes == 1u) &&
           (stats->dynamic_workers == 0u) &&
           (stats->worker_rings == 0u) &&
           (stats->worker_rings_multishot == 0u) &&
           (stats->lockfree_normq == 0u) &&
           (stats->sqpoll == 0u);
}
