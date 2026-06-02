/**
 * @file src/internal/llps_ip_audit.h
 * @brief PXF audit logging for proxied client and backend endpoints.
 *
 * @details
 * Audit code stays isolated from the proxy pump so observability can evolve
 * without changing data forwarding semantics.
 */

#ifndef LLPS_IP_AUDIT_H
#define LLPS_IP_AUDIT_H

#include "llps_internal.h"
#include "yml_parser.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    LLPS_IP_AUDIT_ACCEPT = 0,
    LLPS_IP_AUDIT_DROP,
    LLPS_IP_AUDIT_BACKEND_CONNECT,
    LLPS_IP_AUDIT_BACKEND_FAIL,
    LLPS_IP_AUDIT_CLOSE,
    LLPS_IP_AUDIT_EVENT_TYPE_COUNT
} llps_ip_audit_event_type_t;

typedef struct {
    llps_ip_audit_event_type_t type;
    uint64_t request_no;
    uint64_t time_ns;
    uint64_t duration_ns;
    uint32_t session_id;
    char client_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint16_t client_port;
    char listen_host[LLPS_YML_MAX_IP_TEXT];
    uint16_t listen_port;
    char target_host[LLPS_YML_MAX_IP_TEXT];
    uint16_t target_port;
    char backend_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint16_t backend_port;
    char reason[32];
} llps_ip_audit_event_t;

typedef struct {
    char event[32];
    uint64_t time_ns;
    uint32_t status;
    uint32_t failure_mask;
    uint64_t monitor_passes;
    uint64_t software_evidence_patrol_passes;
    uint64_t synthetic_ecc_topology_patrol_passes;
    uint64_t synthetic_ecc_topology_patrol_failures;
    uint64_t synthetic_fault_patrol_passes;
    uint64_t synthetic_fault_patrol_failures;
    uint64_t synthetic_numa_patrol_passes;
    uint64_t synthetic_numa_patrol_failures;
    uint32_t require_readiness;
    uint32_t platform_evidence_mode;
    uint32_t software_ecc_enabled;
    uint32_t software_numa_enabled;
    uint32_t software_fault_injection_mode;
} llps_ip_audit_evidence_event_t;

/** @brief Initialize the PXF endpoint audit sink from runtime configuration. */
bool llps_ip_audit_init(const llps_yml_config_t *cfg,
                        const char *resolved_backend_ip);
/** @brief Flush and close the PXF endpoint audit sink. */
void llps_ip_audit_shutdown(void);
/** @brief Return true when endpoint audit logging is enabled and writable. */
bool llps_ip_audit_enabled(void);
/** @brief Append one normalized endpoint audit event. */
bool llps_ip_audit_record(const llps_ip_audit_event_t *event);
/** @brief Append one runtime readiness evidence event. */
bool llps_ip_audit_record_evidence(
    const llps_ip_audit_evidence_event_t *event);

#endif /* LLPS_IP_AUDIT_H */
