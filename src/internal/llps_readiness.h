/**
 * @file src/internal/llps_readiness.h
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#ifndef LLPS_READINESS_H
#define LLPS_READINESS_H

#include "llps.h"
#include "llps_platform_evidence_runtime.h"

#include <stdbool.h>

bool llps_evidence_platform_snapshot_is_software_ready(
    const llps_platform_safety_evidence_t *evidence);
bool llps_evidence_platform_snapshot_has_identity(
    const llps_platform_safety_evidence_t *evidence);
bool llps_evidence_platform_snapshot_has_physical_domain_binding(
    const llps_platform_safety_evidence_t *evidence);
bool llps_evidence_platform_snapshot_has_tmr_domain_binding(
    const llps_platform_safety_evidence_t *evidence);
bool llps_evidence_platform_snapshot_has_hardware_tmr(
    const llps_platform_safety_evidence_t *evidence);
llps_status_t llps_build_readiness_report_in_context(
    const llps_platform_evidence_context_t *context,
    const llps_memory_safety_report_t *memory_report,
    const llps_platform_safety_evidence_t *evidence,
    llps_readiness_report_t *out_report);

#endif /* LLPS_READINESS_H */
