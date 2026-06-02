/**
 * @file include/llps/llps.h
 * @brief Public LLPS proxy API, readiness evidence, and safety report types.
 *
 * @details
 * The public surface stays separate from private session storage so
 * applications can depend on LLPS without reaching into implementation
 * state.
 */

#ifndef LLPS_H
#define LLPS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Magic value identifying a populated platform evidence record. */
#define LLPS_PLATFORM_EVIDENCE_MAGIC       (0x5AFE4EEDu)
/** @brief Public platform evidence ABI version. */
#define LLPS_PLATFORM_EVIDENCE_VERSION     (55u)
/** @brief Maximum statically allocated concurrent sessions. */
#define LLPS_MAX_CLIENTS                   (256u)
/** @brief Maximum per-direction session buffer capacity. */
#define LLPS_BUFFER_SIZE                   (4096u)
/** @brief Payload shadow-ECC word size. */
#define LLPS_PAYLOAD_ECC_WORD_BYTES        (8u)
/** @brief Shadow SECDED code count for one per-direction payload buffer. */
#define LLPS_PAYLOAD_ECC_WORD_COUNT \
    ((LLPS_BUFFER_SIZE + (LLPS_PAYLOAD_ECC_WORD_BYTES - 1u)) / \
     LLPS_PAYLOAD_ECC_WORD_BYTES)
/** @brief Software TMR metadata bank count for critical control state. */
#define LLPS_SESSION_TMR_BANK_COUNT        (3u)
/** @brief Maximum DNS host/FQDN or IPv4 text length including NUL. */
#define LLPS_YML_MAX_HOST_TEXT             (256u)
/** @brief Backward-compatible endpoint text capacity. */
#define LLPS_YML_MAX_IP_TEXT               LLPS_YML_MAX_HOST_TEXT
/** @brief Maximum audit path text length including NUL. */
#define LLPS_YML_MAX_PATH_TEXT             (256u)
/** @brief Sentinel for an unknown physical or hardware-TMR domain. */
#define LLPS_TMR_MEMORY_DOMAIN_UNKNOWN     UINT32_MAX
/** @brief Maximum configured synthetic ECC DIMM count. */
#define LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX   (1024u)
/** @brief Default synthetic ECC controller count. */
#define LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_DEFAULT (1u)
/** @brief Maximum configured synthetic ECC controller count. */
#define LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX (256u)
/** @brief Default scrub-rate value for synthetic ECC DIMM evidence. */
#define LLPS_SOFTWARE_ECC_SCRUB_RATE_DEFAULT (4096u)
/** @brief Maximum configured synthetic ECC scrub-rate evidence value. */
#define LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX \
    (UINT64_MAX / (uint64_t)LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX)
/** @brief Maximum configured synthetic KiB per NUMA domain. */
#define LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX \
    (UINT64_MAX / (uint64_t)LLPS_SESSION_TMR_BANK_COUNT)
/** @brief Default local distance in synthetic NUMA topology evidence. */
#define LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT  (10u)
/** @brief Default remote distance in synthetic NUMA topology evidence. */
#define LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT (20u)
/** @brief Maximum synthetic NUMA distance accepted from config. */
#define LLPS_SOFTWARE_NUMA_DISTANCE_MAX            (1000000u)
/** @brief Use only real platform observations. */
#define LLPS_PLATFORM_EVIDENCE_MODE_REAL      (0u)
/** @brief Use only configured, self-tested software evidence. */
#define LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC (1u)
/** @brief Use configured software evidence where enabled, otherwise real probes. */
#define LLPS_PLATFORM_EVIDENCE_MODE_HYBRID    (2u)
/** @brief Software ECC/NUMA fault-model schema bound into evidence records. */
#define LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION  (1u)
/** @brief Do not export configured synthetic fault-injection coverage. */
#define LLPS_SOFTWARE_FAULT_INJECTION_OFF      (0u)
/** @brief Export single-fault repair coverage from synthetic evidence. */
#define LLPS_SOFTWARE_FAULT_INJECTION_SINGLE   (1u)
/** @brief Export double-fault fail-closed coverage from synthetic evidence. */
#define LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE   (2u)
/** @brief Export the full configured synthetic fault model. */
#define LLPS_SOFTWARE_FAULT_INJECTION_FULL     (3u)
/** @brief Maximum software fault-injection mode accepted from config. */
#define LLPS_SOFTWARE_FAULT_INJECTION_MAX \
    LLPS_SOFTWARE_FAULT_INJECTION_FULL
/** @brief Evidence HMAC byte count. */
#define LLPS_PLATFORM_EVIDENCE_MAC_BYTES      (32u)
/** @brief Maximum evidence MAC key file size. */
#define LLPS_EVIDENCE_MAC_KEY_BYTES_MAX       (128u)

/**
 * @brief Platform evidence policy bits and masks.
 *
 * @details
 * Platform evidence policy:
 * - These bits are proof requirements, not proof of danger by themselves.
 * - With require_readiness disabled, unavailable Linux observations are
 *   reported as unproven evidence and the proxy may still run normally.
 * - With require_readiness enabled, any requested but unobserved or
 *   unbound evidence is treated fail-closed and startup/runtime readiness is
 *   rejected.
 * - LLPS_PLATFORM_EVIDENCE_HW_TMR is an external attestation binding. LLPS can
 *   bind operator-provided hardware-TMR domain IDs to the current host/boot/
 *   binary/evidence digest, but it does not itself prove DRAM channel, memory
 *   controller, CPU package, or independent hardware voter containment.
 */
#define LLPS_PLATFORM_EVIDENCE_ECC_MEMORY  (1u << 0u)
#define LLPS_PLATFORM_EVIDENCE_ECC_CLEAN   (1u << 1u)
#define LLPS_PLATFORM_EVIDENCE_PHYS_SEP    (1u << 2u)
#define LLPS_PLATFORM_EVIDENCE_HW_TMR      (1u << 3u)
#define LLPS_PLATFORM_EVIDENCE_REQUIRED \
    (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY | \
     LLPS_PLATFORM_EVIDENCE_ECC_CLEAN | \
     LLPS_PLATFORM_EVIDENCE_PHYS_SEP | \
     LLPS_PLATFORM_EVIDENCE_HW_TMR)
#define LLPS_PLATFORM_EVIDENCE_OBSERVED_MASK \
    (LLPS_PLATFORM_EVIDENCE_ECC_MEMORY | LLPS_PLATFORM_EVIDENCE_ECC_CLEAN)
#define LLPS_PLATFORM_EVIDENCE_EXTERNAL_MASK \
    (LLPS_PLATFORM_EVIDENCE_PHYS_SEP | LLPS_PLATFORM_EVIDENCE_HW_TMR)

#define LLPS_READINESS_MISSING_SOFTWARE_TMR     (1u << 0u)
#define LLPS_READINESS_MISSING_ECC_MEMORY       (1u << 1u)
#define LLPS_READINESS_MISSING_ECC_CLEAN        (1u << 2u)
#define LLPS_READINESS_MISSING_PHYS_SEP         (1u << 3u)
#define LLPS_READINESS_MISSING_HW_TMR           (1u << 4u)
#define LLPS_READINESS_MISSING_EVIDENCE_VALID   (1u << 5u)
#define LLPS_READINESS_MISSING_LAYOUT_BINDING   (1u << 6u)
#define LLPS_READINESS_MISSING_ATTESTATION_BINDING \
    (1u << 7u)
#define LLPS_READINESS_MISSING_PHYS_DOMAIN_BINDING \
    (1u << 8u)
#define LLPS_READINESS_MISSING_TMR_MEMORY_DOMAIN_BINDING \
    (1u << 9u)
#define LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING \
    (1u << 10u)
#define LLPS_READINESS_MISSING_BOOT_BINDING \
    (1u << 11u)
#define LLPS_READINESS_MISSING_PLATFORM_ID_BINDING \
    (1u << 12u)
#define LLPS_READINESS_MISSING_EXECUTABLE_BINDING \
    (1u << 13u)
#define LLPS_READINESS_MISSING_RUNTIME_MONITOR \
    (1u << 14u)
#define LLPS_READINESS_MISSING_SOFTWARE_EVIDENCE_SELF_TEST \
    (1u << 15u)
#define LLPS_READINESS_MISSING_EVIDENCE_MAC \
    (1u << 16u)
#define LLPS_READINESS_MISSING_PAYLOAD_ECC \
    (1u << 17u)

#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_SINGLE_REPAIR \
    (1u << 0u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_FAIL_CLOSED \
    (1u << 1u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR \
    (1u << 2u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED \
    (1u << 3u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB \
    (1u << 4u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP \
    (1u << 5u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY \
    (1u << 6u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DATA_BIT_SWEEP \
    (1u << 7u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_ECC_BIT_SWEEP \
    (1u << 8u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_BIT_SWEEP \
    (1u << 9u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB_CORRUPTION \
    (1u << 10u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_RUNTIME_PATROL \
    (1u << 11u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_STALE_METADATA_FAIL_CLOSED \
    (1u << 12u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING \
    (1u << 13u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING \
    (1u << 14u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING \
    (1u << 15u)
#define LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE \
    (LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_SINGLE_REPAIR | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_FAIL_CLOSED | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DATA_BIT_SWEEP | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_ECC_BIT_SWEEP | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_BIT_SWEEP | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB_CORRUPTION | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_RUNTIME_PATROL | \
     LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_STALE_METADATA_FAIL_CLOSED)

#define LLPS_TMR_SELF_TEST_SESSION_SINGLE_REPAIR \
    (1u << 0u)
#define LLPS_TMR_SELF_TEST_SESSION_DUAL_FAIL_CLOSED \
    (1u << 1u)
#define LLPS_TMR_SELF_TEST_SESSION_NO_MAJORITY_FAIL_CLOSED \
    (1u << 2u)
#define LLPS_TMR_SELF_TEST_RUNTIME_CFG_SINGLE_REPAIR \
    (1u << 3u)
#define LLPS_TMR_SELF_TEST_RUNTIME_CFG_DUAL_FAIL_CLOSED \
    (1u << 4u)
#define LLPS_TMR_SELF_TEST_RUNTIME_CFG_NO_MAJORITY_FAIL_CLOSED \
    (1u << 5u)
#define LLPS_TMR_SELF_TEST_FREE_LIST_SINGLE_REPAIR \
    (1u << 6u)
#define LLPS_TMR_SELF_TEST_FREE_LIST_DUAL_FAIL_CLOSED \
    (1u << 7u)
#define LLPS_TMR_SELF_TEST_FREE_LIST_NO_MAJORITY_FAIL_CLOSED \
    (1u << 8u)
#define LLPS_TMR_SELF_TEST_CONTROL_FLAG_SINGLE_REPAIR \
    (1u << 9u)
#define LLPS_TMR_SELF_TEST_CONTROL_FLAG_DUAL_FAIL_CLOSED \
    (1u << 10u)
#define LLPS_TMR_SELF_TEST_REQUIRED_COVERAGE \
    (LLPS_TMR_SELF_TEST_SESSION_SINGLE_REPAIR | \
     LLPS_TMR_SELF_TEST_SESSION_DUAL_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_SESSION_NO_MAJORITY_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_RUNTIME_CFG_SINGLE_REPAIR | \
     LLPS_TMR_SELF_TEST_RUNTIME_CFG_DUAL_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_RUNTIME_CFG_NO_MAJORITY_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_FREE_LIST_SINGLE_REPAIR | \
     LLPS_TMR_SELF_TEST_FREE_LIST_DUAL_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_FREE_LIST_NO_MAJORITY_FAIL_CLOSED | \
     LLPS_TMR_SELF_TEST_CONTROL_FLAG_SINGLE_REPAIR | \
     LLPS_TMR_SELF_TEST_CONTROL_FLAG_DUAL_FAIL_CLOSED)

/** @brief Public status codes returned by LLPS API calls. */
typedef enum {
    LLPS_OK = 0,   /**< Operation completed successfully. */
    LLPS_E_NULL,   /**< Caller passed a required NULL pointer. */
    LLPS_E_RANGE,  /**< Caller supplied an out-of-range value. */
    LLPS_E_STATE,  /**< Runtime state or protected metadata is invalid. */
    LLPS_E_SOCKET, /**< Socket creation, configuration, or ownership failed. */
    LLPS_E_IO,     /**< File or socket I/O failed. */
    LLPS_E_RUNTIME /**< LLAM scheduler/runtime integration failure. */
} llps_status_t;

/** @brief Parser and validation result codes for LLPS YAML configuration. */
typedef enum {
    LLPS_YML_OK = 0,       /**< Configuration loaded successfully. */
    LLPS_YML_E_NULL,       /**< Caller passed a required NULL pointer. */
    LLPS_YML_E_OPEN,       /**< Configuration file could not be opened. */
    LLPS_YML_E_READ,       /**< Configuration file read failed. */
    LLPS_YML_E_CLOSE,      /**< Configuration file close failed. */
    LLPS_YML_E_TOO_LARGE,  /**< Configuration exceeded bounded file size. */
    LLPS_YML_E_TOO_MANY_LINES, /**< Configuration exceeded bounded line count. */
    LLPS_YML_E_LINE_TOO_LONG,  /**< One line exceeded parser bounds. */
    LLPS_YML_E_SYNTAX,     /**< YAML subset syntax was invalid. */
    LLPS_YML_E_KEY,        /**< Key was unknown or malformed. */
    LLPS_YML_E_DUPLICATE,  /**< Key was specified more than once. */
    LLPS_YML_E_REQUIRED,   /**< Required key was missing. */
    LLPS_YML_E_RANGE,      /**< Numeric value was outside LLPS bounds. */
    LLPS_YML_E_STRING      /**< Text value was invalid or too long. */
} llps_yml_status_t;

/**
 * @brief Fully normalized LLPS runtime configuration.
 *
 * @details
 * Text fields are NUL-terminated fixed-size arrays. Endpoint host fields may
 * contain IPv4 literals or DNS names; numeric bounds are validated before the
 * structure reaches runtime initialization.
 */
typedef struct {
    uint32_t max_clients;      /**< Maximum concurrent sessions. */
    uint32_t buffer_size;      /**< Per-direction session buffer capacity. */
    uint32_t payload_ecc_enabled; /**< Nonzero protects payload buffers. */

    char listen_host[LLPS_YML_MAX_IP_TEXT]; /**< Listener IPv4 or DNS host. */
    uint16_t listen_port;      /**< Listener TCP port. */

    char target_ip[LLPS_YML_MAX_IP_TEXT]; /**< Backend IPv4 or DNS host. */
    uint16_t target_port;      /**< Backend TCP port. */

    uint32_t listen_backlog;   /**< listen(2) backlog value. */
    uint32_t accept_batch_max; /**< Maximum accepts per scheduler pass. */
    uint32_t session_idle_timeout_ms; /**< Idle session fail-closed budget. */
    /** Maximum active sessions per client IP, or zero for disabled. */
    uint32_t max_sessions_per_client_ip;
    /** Maximum new sessions per client IP per window, or zero disabled. */
    uint32_t max_new_sessions_per_client_ip_per_window;
    /** Client-IP new-session rate-limit window in milliseconds. */
    uint32_t client_ip_rate_window_ms;
    /** Require first client payload before backend connect; zero disables. */
    uint32_t client_preface_timeout_ms;
    /** Validate first preface as Protocol handshake; zero disables. */
    uint32_t protocol_handshake_gate_enabled;
    uint32_t ip_audit_enabled; /**< Nonzero enables PXF endpoint audit logs. */
    char ip_audit_path[LLPS_YML_MAX_PATH_TEXT]; /**< PXF audit output path. */
    uint32_t audit_mac_enabled; /**< Nonzero authenticates audit records. */
    char audit_mac_key_path[LLPS_YML_MAX_PATH_TEXT]; /**< Audit MAC key path. */

    uint32_t require_readiness; /**< Nonzero makes readiness fail-closed. */
    uint32_t platform_safety_flags; /**< Requested platform evidence flags. */
    uint64_t platform_safety_evidence_id; /**< Operator evidence identifier. */
    uint32_t platform_attestation_fingerprint; /**< External attestation bind. */
    uint32_t platform_observation_digest; /**< Expected host observation digest. */
    uint32_t platform_evidence_mode; /**< Real, synthetic, or hybrid evidence. */
    /** Physical memory domain IDs. */
    uint32_t platform_physical_memory_domains[LLPS_SESSION_TMR_BANK_COUNT];
    /** Hardware TMR domain IDs. */
    uint32_t platform_hardware_tmr_domains[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t platform_hardware_tmr_voter_domain; /**< Hardware voter domain. */
    uint32_t software_ecc_enabled; /**< Nonzero uses configured ECC evidence. */
    uint32_t software_ecc_controller_count; /**< Synthetic ECC controllers. */
    uint32_t software_ecc_dimm_count; /**< Synthetic ECC DIMM evidence count. */
    uint64_t software_ecc_scrub_rate; /**< Per-controller ECC scrub-rate evidence. */
    uint64_t software_ecc_controller_corrected_error_count; /**< Synthetic CE count. */
    uint64_t software_ecc_controller_uncorrected_error_count; /**< Synthetic UE count. */
    uint64_t software_ecc_dimm_corrected_error_count; /**< Synthetic DIMM CE count. */
    uint64_t software_ecc_dimm_uncorrected_error_count; /**< Synthetic DIMM UE count. */
    uint32_t software_numa_enabled; /**< Nonzero uses configured NUMA evidence. */
    uint64_t software_numa_memtotal_kib; /**< Synthetic KiB per NUMA domain. */
    uint64_t software_numa_local_distance; /**< Synthetic local NUMA distance. */
    uint64_t software_numa_remote_distance; /**< Synthetic remote NUMA distance. */
    uint32_t software_fault_injection_mode; /**< Exported synthetic fault model. */
    uint32_t evidence_mac_enabled; /**< Nonzero authenticates evidence. */
    char evidence_mac_key_path[LLPS_YML_MAX_PATH_TEXT]; /**< MAC key path. */
} llps_yml_config_t;

/**
 * @brief Runtime memory and TMR health snapshot.
 *
 * @details
 * This report is process-local diagnostic state. It is useful for operations,
 * tests, and readiness explanations, but it is not a cryptographic attestation
 * and should not be treated as remote proof by itself.
 */
typedef struct {
    bool runtime_cfg_tmr_valid;
    bool control_flag_tmr_valid;
    bool free_list_tmr_valid;
    bool shutdown_requested;
    bool tmr_layout_valid;
    bool process_memory_locked;
    bool tmr_memory_locked;
    bool tmr_memory_prefaulted;
    bool tmr_memory_domains_bound;
    bool tmr_memory_observed_domains_valid;
    bool tmr_memory_resident;
    bool tmr_memory_physical_frames_distinct;
    bool tmr_memory_physical_frames_spaced;
    bool tmr_memory_hardened;
    bool tmr_startup_self_test_passed;
    bool tmr_startup_self_test_coverage_valid;
    bool readiness_runtime_monitor_enabled;
    bool runtime_safety_latches_valid;
    bool memory_safety_counters_valid;
    bool tmr_memory_prefault_pages_valid;
    bool tmr_bank_guard_valid[LLPS_SESSION_TMR_BANK_COUNT];
    uint64_t tmr_bank_distance_01;
    uint64_t tmr_bank_distance_02;
    uint64_t tmr_bank_distance_12;
    uint64_t tmr_metadata_min_bank_distance;
    uint64_t tmr_single_bank_repairs;
    uint64_t tmr_majority_failures;
    uint64_t tmr_region_guard_faults;
    uint64_t tmr_layout_failures;
    uint64_t process_memory_lock_failures;
    uint64_t tmr_memory_lock_failures;
    uint64_t tmr_memory_prefault_pages;
    uint64_t tmr_memory_prefault_failures;
    uint64_t tmr_memory_resident_pages;
    uint64_t tmr_memory_residency_failures;
    uint64_t tmr_memory_physical_frame_faults;
    uint32_t tmr_memory_residency_fingerprint;
    uint64_t tmr_memory_physical_frame_pages;
    uint64_t tmr_memory_physical_frame_probe_failures;
    uint64_t tmr_memory_physical_frame_min_distance;
    uint64_t tmr_memory_physical_frame_required_distance;
    uint64_t tmr_memory_physical_frame_distance_01;
    uint64_t tmr_memory_physical_frame_distance_02;
    uint64_t tmr_memory_physical_frame_distance_12;
    uint32_t tmr_memory_physical_frame_pair_coverage;
    uint32_t tmr_memory_physical_frame_fingerprint;
    uint64_t tmr_memory_domain_bind_failures;
    uint32_t tmr_memory_domain_observation_fingerprint;
    uint64_t tmr_memory_domain_pages_checked;
    uint64_t tmr_memory_domain_mismatch_count;
    uint64_t tmr_memory_domain_probe_failures;
    uint32_t tmr_memory_domain_region_coverage;
    uint32_t tmr_memory_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t tmr_startup_self_test_coverage;
    uint32_t tmr_startup_self_test_required_coverage;
    uint64_t tmr_memory_harden_failures;
    uint64_t contract_violations;
    uint64_t free_list_single_bank_repairs;
    uint64_t free_list_majority_failures;
    uint64_t runtime_cfg_single_bank_repairs;
    uint64_t runtime_cfg_majority_failures;
    uint64_t control_flag_single_bank_repairs;
    uint64_t control_flag_majority_failures;
    uint64_t secded_single_bit_repairs;
    uint64_t secded_double_bit_failures;
    uint64_t tmr_scrub_passes;
    uint64_t tmr_scrub_sessions_checked;
    uint64_t tmr_scrub_fail_closed_sessions;
    uint64_t payload_ecc_scrub_passes;
    uint64_t payload_ecc_scrub_sessions_checked;
    uint64_t payload_ecc_scrub_fail_closed_sessions;
    uint64_t readiness_runtime_monitor_passes;
    uint64_t readiness_runtime_software_evidence_patrol_passes;
    uint64_t readiness_runtime_synthetic_ecc_topology_patrol_passes;
    uint64_t readiness_runtime_synthetic_ecc_topology_patrol_failures;
    uint64_t readiness_runtime_synthetic_fault_patrol_passes;
    uint64_t readiness_runtime_synthetic_fault_patrol_failures;
    uint64_t readiness_runtime_synthetic_numa_patrol_passes;
    uint64_t readiness_runtime_synthetic_numa_patrol_failures;
    uint64_t readiness_runtime_monitor_failures;
    uint64_t readiness_runtime_cfg_failures;
    uint64_t readiness_runtime_software_tmr_failures;
    uint64_t readiness_runtime_ecc_failures;
    uint64_t readiness_runtime_physical_domain_failures;
    uint64_t readiness_runtime_tmr_memory_domain_failures;
    uint64_t readiness_runtime_hardware_tmr_failures;
    uint64_t readiness_runtime_identity_failures;
    uint64_t readiness_runtime_attestation_failures;
    uint64_t readiness_runtime_observation_digest_failures;
    uint32_t memory_safety_counters_fingerprint;
} llps_memory_safety_report_t;

/**
 * @brief Bound platform evidence record used by readiness checks.
 *
 * @details
 * Each material field is paired with its bitwise inverse and the complete
 * record is CRC-protected. The record binds observed host evidence, operator
 * supplied domain IDs, and runtime TMR layout fingerprints into a single
 * fail-closed readiness input.
 */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t flags_inverse;
    uint32_t observed_flags;
    uint32_t observed_flags_inverse;
    uint32_t edac_observation_fingerprint;
    uint32_t edac_observation_fingerprint_inverse;
    uint32_t edac_controller_count;
    uint32_t edac_controller_count_inverse;
    uint32_t edac_dimm_count;
    uint32_t edac_dimm_count_inverse;
    uint32_t edac_scrub_rate_count;
    uint32_t edac_scrub_rate_count_inverse;
    uint32_t edac_controller_counter_coverage;
    uint32_t edac_controller_counter_coverage_inverse;
    uint32_t edac_dimm_mode_coverage;
    uint32_t edac_dimm_mode_coverage_inverse;
    uint32_t edac_dimm_counter_coverage;
    uint32_t edac_dimm_counter_coverage_inverse;
    uint32_t edac_scrub_rate_coverage;
    uint32_t edac_scrub_rate_coverage_inverse;
    uint64_t edac_corrected_error_count;
    uint64_t edac_corrected_error_count_inverse;
    uint64_t edac_uncorrected_error_count;
    uint64_t edac_uncorrected_error_count_inverse;
    uint64_t edac_dimm_corrected_error_count;
    uint64_t edac_dimm_corrected_error_count_inverse;
    uint64_t edac_dimm_uncorrected_error_count;
    uint64_t edac_dimm_uncorrected_error_count_inverse;
    uint64_t edac_scrub_rate_sum;
    uint64_t edac_scrub_rate_sum_inverse;
    uint32_t platform_boot_fingerprint;
    uint32_t platform_boot_fingerprint_inverse;
    uint32_t platform_identity_fingerprint;
    uint32_t platform_identity_fingerprint_inverse;
    uint32_t executable_image_fingerprint;
    uint32_t executable_image_fingerprint_inverse;
    uint32_t process_memory_locked;
    uint32_t process_memory_locked_inverse;
    uint32_t tmr_memory_locked;
    uint32_t tmr_memory_locked_inverse;
    uint32_t tmr_memory_prefaulted;
    uint32_t tmr_memory_prefaulted_inverse;
    uint64_t tmr_memory_prefault_pages;
    uint64_t tmr_memory_prefault_pages_inverse;
    uint32_t tmr_memory_hardened;
    uint32_t tmr_memory_hardened_inverse;
    uint32_t tmr_startup_self_test_passed;
    uint32_t tmr_startup_self_test_passed_inverse;
    uint32_t tmr_startup_self_test_coverage;
    uint32_t tmr_startup_self_test_coverage_inverse;
    uint32_t tmr_startup_self_test_required_coverage;
    uint32_t tmr_startup_self_test_required_coverage_inverse;
    uint32_t platform_evidence_mode;
    uint32_t platform_evidence_mode_inverse;
    uint32_t software_evidence_schema_version;
    uint32_t software_evidence_schema_version_inverse;
    uint32_t software_evidence_self_test_passed;
    uint32_t software_evidence_self_test_passed_inverse;
    uint32_t software_evidence_self_test_coverage;
    uint32_t software_evidence_self_test_coverage_inverse;
    uint32_t software_evidence_self_test_required_coverage;
    uint32_t software_evidence_self_test_required_coverage_inverse;
    uint32_t software_ecc_controller_count;
    uint32_t software_ecc_controller_count_inverse;
    uint32_t software_dimm_bank_count;
    uint32_t software_dimm_bank_count_inverse;
    uint64_t software_ecc_scrub_rate;
    uint64_t software_ecc_scrub_rate_inverse;
    uint32_t software_dimm_generation;
    uint32_t software_dimm_generation_inverse;
    uint32_t software_dimm_scrub_generation;
    uint32_t software_dimm_scrub_generation_inverse;
    uint32_t software_dimm_fault_injection_coverage;
    uint32_t software_dimm_fault_injection_coverage_inverse;
    uint32_t software_fault_injection_mode;
    uint32_t software_fault_injection_mode_inverse;
    uint32_t software_dimm_observation_fingerprint;
    uint32_t software_dimm_observation_fingerprint_inverse;
    uint32_t software_numa_profile_fingerprint;
    uint32_t software_numa_profile_fingerprint_inverse;
    uint32_t physical_domain_observation_fingerprint;
    uint32_t physical_domain_observation_fingerprint_inverse;
    uint32_t physical_domain_topology_coverage;
    uint32_t physical_domain_topology_coverage_inverse;
    uint32_t physical_domain_observed_count;
    uint32_t physical_domain_observed_count_inverse;
    uint64_t physical_domain_memtotal_kib;
    uint64_t physical_domain_memtotal_kib_inverse;
    uint64_t physical_domain_distance_entries;
    uint64_t physical_domain_distance_entries_inverse;
    uint64_t physical_domain_distance_sum;
    uint64_t physical_domain_distance_sum_inverse;
    uint32_t physical_domain_distance_pair_coverage;
    uint32_t physical_domain_distance_pair_coverage_inverse;
    uint64_t physical_domain_distance_01;
    uint64_t physical_domain_distance_01_inverse;
    uint64_t physical_domain_distance_02;
    uint64_t physical_domain_distance_02_inverse;
    uint64_t physical_domain_distance_12;
    uint64_t physical_domain_distance_12_inverse;
    uint32_t tmr_memory_domain_observation_fingerprint;
    uint32_t tmr_memory_domain_observation_fingerprint_inverse;
    uint32_t tmr_memory_resident;
    uint32_t tmr_memory_resident_inverse;
    uint64_t tmr_memory_resident_pages;
    uint64_t tmr_memory_resident_pages_inverse;
    uint32_t tmr_memory_residency_fingerprint;
    uint32_t tmr_memory_residency_fingerprint_inverse;
    uint32_t tmr_memory_physical_frames_distinct;
    uint32_t tmr_memory_physical_frames_distinct_inverse;
    uint32_t tmr_memory_physical_frames_spaced;
    uint32_t tmr_memory_physical_frames_spaced_inverse;
    uint64_t tmr_memory_physical_frame_pages;
    uint64_t tmr_memory_physical_frame_pages_inverse;
    uint64_t tmr_memory_physical_frame_probe_failures;
    uint64_t tmr_memory_physical_frame_probe_failures_inverse;
    uint64_t tmr_memory_physical_frame_min_distance;
    uint64_t tmr_memory_physical_frame_min_distance_inverse;
    uint64_t tmr_memory_physical_frame_required_distance;
    uint64_t tmr_memory_physical_frame_required_distance_inverse;
    uint64_t tmr_memory_physical_frame_distance_01;
    uint64_t tmr_memory_physical_frame_distance_01_inverse;
    uint64_t tmr_memory_physical_frame_distance_02;
    uint64_t tmr_memory_physical_frame_distance_02_inverse;
    uint64_t tmr_memory_physical_frame_distance_12;
    uint64_t tmr_memory_physical_frame_distance_12_inverse;
    uint32_t tmr_memory_physical_frame_pair_coverage;
    uint32_t tmr_memory_physical_frame_pair_coverage_inverse;
    uint32_t tmr_memory_physical_frame_fingerprint;
    uint32_t tmr_memory_physical_frame_fingerprint_inverse;
    uint64_t tmr_memory_domain_pages_checked;
    uint64_t tmr_memory_domain_pages_checked_inverse;
    uint64_t tmr_memory_domain_mismatch_count;
    uint64_t tmr_memory_domain_mismatch_count_inverse;
    uint64_t tmr_memory_domain_probe_failures;
    uint64_t tmr_memory_domain_probe_failures_inverse;
    uint32_t tmr_memory_domain_region_coverage;
    uint32_t tmr_memory_domain_region_coverage_inverse;
    uint32_t tmr_memory_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t tmr_memory_observed_domain_ids_inverse[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t attested_flags;
    uint32_t attested_flags_inverse;
    uint32_t attestation_fingerprint;
    uint32_t attestation_fingerprint_inverse;
    uint64_t evidence_id;
    uint64_t evidence_id_inverse;
    uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t physical_memory_domain_ids_inverse[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t hardware_tmr_domain_ids_inverse[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t hardware_tmr_voter_domain_id;
    uint32_t hardware_tmr_voter_domain_id_inverse;
    uint32_t tmr_layout_fingerprint;
    uint32_t tmr_layout_fingerprint_inverse;
    uint32_t observation_digest;
    uint32_t observation_digest_inverse;
    uint32_t evidence_mac_enabled;
    uint32_t evidence_mac_enabled_inverse;
    uint32_t evidence_mac_key_fingerprint;
    uint32_t evidence_mac_key_fingerprint_inverse;
    uint8_t evidence_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint8_t evidence_mac_inverse[LLPS_PLATFORM_EVIDENCE_MAC_BYTES];
    uint32_t crc;
    uint32_t crc_inverse;
} llps_platform_safety_evidence_t;

/**
 * @brief Human-readable readiness decision and supporting counters.
 *
 * @details
 * The booleans expose which readiness requirements passed. The missing bitmask
 * explains the fail-closed reason when ::gate_passed is false.
 */
typedef struct {
    llps_memory_safety_report_t memory;
    bool software_tmr_ready;
    bool platform_evidence_valid;
    bool ecc_memory_ready;
    bool ecc_counters_clean;
    bool edac_controller_counter_coverage;
    bool edac_dimm_mode_coverage;
    bool edac_dimm_counter_coverage;
    bool edac_scrub_rate_coverage;
    bool physical_memory_separation_ready;
    bool independent_hardware_tmr_ready;
    bool physical_memory_domains_distinct;
    bool hardware_tmr_domains_distinct;
    bool hardware_tmr_voter_domain_independent;
    bool hardware_tmr_domains_independent;
    bool platform_evidence_layout_bound;
    bool platform_evidence_edac_bound;
    bool platform_evidence_physical_domain_bound;
    bool platform_evidence_tmr_memory_domain_bound;
    bool platform_attestation_bound;
    bool platform_boot_bound;
    bool platform_identity_bound;
    bool executable_image_bound;
    bool software_evidence_self_test_ready;
    bool evidence_mac_valid;
    bool payload_ecc_ready;
    bool configured_evidence_request_bound;
    bool configured_platform_observation_digest_bound;
    bool gate_passed;
    uint32_t platform_evidence_boot_fingerprint;
    uint32_t platform_evidence_identity_fingerprint;
    uint32_t executable_image_fingerprint;
    uint32_t platform_evidence_observation_digest;
    uint32_t platform_evidence_mode;
    uint32_t software_evidence_schema_version;
    uint32_t software_evidence_self_test_coverage;
    uint32_t software_evidence_self_test_required_coverage;
    uint32_t software_ecc_controller_count;
    uint32_t software_dimm_bank_count;
    uint64_t software_ecc_scrub_rate;
    uint32_t software_dimm_generation;
    uint32_t software_dimm_scrub_generation;
    uint32_t software_dimm_fault_injection_coverage;
    uint32_t software_fault_injection_mode;
    uint32_t software_dimm_observation_fingerprint;
    uint32_t software_numa_profile_fingerprint;
    uint32_t evidence_mac_key_fingerprint;
    uint32_t hardware_tmr_voter_domain_id;
    uint32_t physical_domain_topology_coverage;
    uint32_t physical_domain_observed_count;
    uint64_t physical_domain_memtotal_kib;
    uint64_t physical_domain_distance_entries;
    uint64_t physical_domain_distance_sum;
    uint32_t physical_domain_distance_pair_coverage;
    uint64_t physical_domain_distance_01;
    uint64_t physical_domain_distance_02;
    uint64_t physical_domain_distance_12;
    uint32_t edac_controller_count;
    uint32_t edac_dimm_count;
    uint32_t edac_scrub_rate_count;
    uint64_t edac_corrected_error_count;
    uint64_t edac_uncorrected_error_count;
    uint64_t edac_dimm_corrected_error_count;
    uint64_t edac_dimm_uncorrected_error_count;
    uint64_t edac_scrub_rate_sum;
    uint32_t missing_requirements;
} llps_readiness_report_t;

/**
 * @brief Load a normal runtime configuration from disk.
 */
llps_yml_status_t llps_yml_load_config_ex(const char *path,
                                          llps_yml_config_t *out_cfg,
                                          uint32_t *error_line_ref);

/**
 * @brief Load a configuration allowing attestation-only evidence generation.
 */
llps_yml_status_t llps_yml_load_config_for_attestation_ex(
    const char *path,
    llps_yml_config_t *out_cfg,
    uint32_t *error_line_ref);

/**
 * @brief Convert a YAML parser status code to a stable diagnostic string.
 */
const char *llps_yml_status_string(llps_yml_status_t st);

/**
 * @brief Initialize LLPS runtime state from a validated configuration.
 *
 * @param cfg Configuration loaded by the YAML parser.
 * @return ::LLPS_OK on success, otherwise a public LLPS error code.
 */
llps_status_t llps_init(const llps_yml_config_t *cfg);

/**
 * @brief Initialize enough LLPS state for diagnostics and readiness probes.
 *
 * @details This path avoids opening the proxy listener but prepares protected
 * runtime metadata so evidence and report APIs can run in isolation.
 */
llps_status_t llps_init_for_diagnostics(const llps_yml_config_t *cfg);

/**
 * @brief Copy the current memory and TMR safety report.
 *
 * @param out_report Destination report.
 * @return ::LLPS_OK on success.
 */
llps_status_t llps_get_memory_safety_report(
    llps_memory_safety_report_t *out_report);

/**
 * @brief Build platform safety evidence using default unknown domain IDs.
 */
llps_status_t llps_make_platform_safety_evidence(
    uint32_t flags,
    uint64_t evidence_id,
    llps_platform_safety_evidence_t *out_evidence);

/**
 * @brief Build platform safety evidence from explicit operator domain IDs.
 *
 * @details This records external evidence identifiers; it does not independently
 * prove hardware separation.
 */
llps_status_t llps_make_platform_safety_evidence_ex(
    uint32_t flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t *out_evidence);

/**
 * @brief Compute the fingerprint LLPS expects for a platform attestation.
 */
llps_status_t llps_compute_platform_attestation_fingerprint(
    uint32_t flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    uint32_t *out_fingerprint);

/**
 * @brief Collect observed host evidence and bind it into an evidence record.
 *
 * @details On Linux this may inspect EDAC, NUMA, process memory, executable,
 * boot, and platform identity sources. Callers that run inside an LLAM worker
 * should prefer the background readiness worker instead of calling this on a
 * latency-sensitive pump path.
 */
llps_status_t llps_collect_platform_safety_evidence(
    uint32_t requested_flags,
    uint64_t evidence_id,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t hardware_tmr_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t hardware_tmr_voter_domain_id,
    llps_platform_safety_evidence_t *out_evidence);

/**
 * @brief Explain whether a platform evidence record passes readiness policy.
 */
llps_status_t llps_get_readiness_report(
    const llps_platform_safety_evidence_t *evidence,
    llps_readiness_report_t *out_report);

/**
 * @brief Return success only when all configured readiness requirements pass.
 */
llps_status_t llps_require_readiness(
    const llps_platform_safety_evidence_t *evidence);

/**
 * @brief Open, bind, listen, and set the listen socket nonblocking.
 *
 * @details
 * On success, @p listen_fd_ref receives a valid listening socket. On failure,
 * any partially opened socket is closed and @p listen_fd_ref is set to
 * ::LLPS_INVALID_FD.
 *
 * @param cfg Listener configuration.
 * @param listen_fd_ref Destination socket owner.
 */
llps_status_t llps_open_listen_socket(const llps_yml_config_t *cfg,
                                      int *listen_fd_ref);

/**
 * @brief Close a listening socket and clear its owner slot.
 *
 * @details It is safe to call this with an already-invalid descriptor.
 */
llps_status_t llps_close_listen_socket(int *listen_fd_ref);

/**
 * @brief Run the server loop using a listening socket supplied through @p arg.
 *
 * @details
 * @p arg must point to an int containing a valid listening socket.
 *
 * On successful entry:
 * - llps_run_server() takes ownership of that socket.
 * - it stores LLPS_INVALID_FD through the provided pointer.
 * - it closes the socket before returning.
 *
 * Ownership model:
 * - Before successful spawn: caller owns listen fd.
 * - After server task entry: server task owns listen fd.
 * - If server task never takes ownership: caller-side defensive cleanup may
 *   close the still-valid fd.
 */
void llps_run_server(void *arg);

/** @brief Gracefully trigger shutdown of all active sessions. */
void llps_shutdown_all_sessions(void);

/** @brief Request the server to stop accepting connections and shut down. */
void llps_request_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* LLPS_H */
