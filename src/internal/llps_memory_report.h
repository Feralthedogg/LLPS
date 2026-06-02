/**
 * @file src/internal/llps_memory_report.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_MEMORY_REPORT_H
#define LLPS_MEMORY_REPORT_H

#include "llps.h"

#include <stdint.h>

llps_status_t llps_build_memory_safety_report(
    llps_yml_config_t *runtime_cfg,
    uint32_t free_sessions[LLPS_MAX_CLIENTS],
    uint32_t *free_sessions_count,
    llps_memory_safety_report_t *out_report);

#endif /* LLPS_MEMORY_REPORT_H */
