/**
 * @file src/internal/llps_readiness_config.h
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#ifndef LLPS_READINESS_CONFIG_H
#define LLPS_READINESS_CONFIG_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

llps_status_t llps_require_configured_readiness(
    const llps_yml_config_t *cfg);
llps_status_t llps_check_configured_readiness_platform_snapshot(
    const llps_yml_config_t *cfg,
    uint32_t *out_failure_mask);
bool llps_readiness_runtime_fast_software_ready(
    llps_yml_config_t *runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t *free_sessions_count);

#endif /* LLPS_READINESS_CONFIG_H */
