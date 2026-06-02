/**
 * @file src/internal/llps_readiness_monitor_worker.h
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#ifndef LLPS_READINESS_MONITOR_WORKER_H
#define LLPS_READINESS_MONITOR_WORKER_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

#if !defined(LLPS_TEST_HOOKS)
/** @brief Start the background runtime readiness monitor worker. */
bool llps_readiness_runtime_monitor_worker_start(void);
/** @brief Request the readiness monitor worker to stop and join its task. */
void llps_readiness_runtime_monitor_worker_stop(void);
/** @brief Poll the latest monitor result or collect synchronously on timeout. */
llps_status_t llps_readiness_runtime_monitor_worker_poll(
    const llps_yml_config_t *cfg,
    uint64_t now_ns,
    uint64_t timeout_ns,
    uint32_t *out_failure_mask,
    bool *out_result_consumed);
#endif

#endif /* LLPS_READINESS_MONITOR_WORKER_H */
