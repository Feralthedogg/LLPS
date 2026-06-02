/**
 * @file src/app/main.c
 * @brief Command-line entry point and LLAM runtime bootstrap for LLPS.
 *
 * @details
 * The executable layer translates operator configuration into explicit LLPS
 * and LLAM runtime settings.
 */

#include "llam/runtime.h"

#include "llps.h"
#include "llps_config.h"
#include "llps_internal.h"
#include "llps_ip_audit.h"
#include "llps_llam_contract.h"
#include "llps_log.h"
#include "llps_software_evidence.h"
#include "yml_parser.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void handle_signal(int sig) {
    (void)sig;
    llps_request_shutdown();
}

static void llps_dump_llam_runtime_state(const char * const reason) {
    LLPS_EXPECT(reason != NULL, (void)0);
    (void)fprintf(stderr,
                  "LLAM runtime diagnostic dump: %s\n",
                  (reason != NULL) ? reason : "unknown");
    llam_dump_runtime_state(STDERR_FILENO);
}

static void llps_shutdown_llam_runtime(const char * const reason) {
    LLPS_EXPECT(reason != NULL, (void)0);
    llam_runtime_shutdown();
}

static void llps_app_llam_contract_failure(const char * const operation) {
    (void)fprintf(stderr,
                  "LLAM contract failure: %s\n",
                  (operation != NULL) ? operation : "unknown");
    llps_dump_llam_runtime_state(operation);
}

static void llps_log_llam_runtime_contract(
    const llam_runtime_stats_t * const stats) {
    if ((stats == NULL) || !llps_log_enabled()) {
        return;
    }

    llps_log_begin();
    (void)fprintf(stdout,
                  "llam_runtime_contract\n"
                  "  single_worker=1\n"
                  "  single_node=1\n"
                  "  deterministic=1\n"
                  "  profile=io-latency\n"
                  "  active_workers=%u\n"
                  "  online_workers=%u\n"
                  "  online_workers_floor=%u\n"
                  "  online_workers_min=%u\n"
                  "  online_workers_max=%u\n"
                  "  active_nodes=%u\n"
                  "  dynamic_workers=%u\n"
                  "  worker_rings=%u\n"
                  "  worker_rings_multishot=%u\n"
                  "  lockfree_normq=%u\n"
                  "  sqpoll=%u",
                  (unsigned)stats->active_workers,
                  (unsigned)stats->online_workers,
                  (unsigned)stats->online_workers_floor,
                  (unsigned)stats->online_workers_min,
                  (unsigned)stats->online_workers_max,
                  (unsigned)stats->active_nodes,
                  (unsigned)stats->dynamic_workers,
                  (unsigned)stats->worker_rings,
                  (unsigned)stats->worker_rings_multishot,
                  (unsigned)stats->lockfree_normq,
                  (unsigned)stats->sqpoll);
    llps_log_end();
}

static llam_task_t *llps_spawn_checked(llam_task_fn fn,
                                       void * const arg,
                                       const llam_spawn_opts_t * const opts,
                                       const char * const operation) {
    llam_task_t *task = NULL;

    if ((fn == NULL) || (opts == NULL) || (operation == NULL)) {
        (void)fprintf(stderr,
                      "Invalid LLAM spawn operation arguments: %s\n",
                      (operation != NULL) ? operation : "unknown");
        LLPS_EXPECT(false, llps_app_llam_contract_failure(operation));
        return NULL;
    }

    task = llam_spawn_ex(fn, arg, opts, LLAM_SPAWN_OPTS_CURRENT_SIZE);

    if (task == NULL) {
        (void)fprintf(stderr,
                      "Failed LLAM spawn operation: %s\n",
                      operation);
        LLPS_EXPECT(false, llps_app_llam_contract_failure(operation));
    }

    return task;
}

static bool llps_run_llam_runtime_checked(void) {
    if (llam_run() == 0) {
        return true;
    }

    (void)fprintf(stderr, "LLAM runtime returned an error\n");
    LLPS_EXPECT(false, llps_app_llam_contract_failure("runtime_run_failed"));
    return false;
}

static int llps_prepare_llam_spawn_opts(llam_spawn_opts_t * const opts,
                                        const uint32_t task_class,
                                        const uint32_t flags) {
    if (opts == NULL) {
        (void)fprintf(stderr, "Invalid LLAM spawn options destination\n");
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("spawn_opts_args"));
        return -1;
    }

    if (llam_spawn_opts_init(opts, LLAM_SPAWN_OPTS_CURRENT_SIZE) != 0) {
        (void)fprintf(stderr, "Failed to initialize LLAM spawn options\n");
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("spawn_opts_init"));
        return -1;
    }

    opts->task_class = task_class;
    opts->stack_class = LLAM_STACK_CLASS_DEFAULT;
    opts->flags |= flags;
    return 0;
}

static int llps_init_checked_llam_runtime(void) {
    llam_runtime_opts_t opts;
    llam_runtime_stats_t stats;

    if (llam_runtime_opts_init(&opts, LLAM_RUNTIME_OPTS_CURRENT_SIZE) != 0) {
        (void)fprintf(stderr, "Failed to initialize LLAM runtime options\n");
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("runtime_opts_init"));
        return -1;
    }

    opts.deterministic = 1u;
    opts.experimental_flags = 0u;
    opts.profile = LLAM_RUNTIME_PROFILE_IO_LATENCY;

    if (llam_runtime_init_ex(&opts, LLAM_RUNTIME_OPTS_CURRENT_SIZE) != 0) {
        (void)fprintf(stderr, "Failed to initialize LLAM runtime\n");
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("runtime_init"));
        return -1;
    }

    (void)memset(&stats, 0, sizeof(stats));
    if (llam_runtime_collect_stats_ex(&stats,
                                      LLAM_RUNTIME_STATS_CURRENT_SIZE) != 0) {
        (void)fprintf(stderr, "Failed to collect LLAM runtime stats\n");
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("collect_stats_failed"));
        llps_shutdown_llam_runtime("collect_stats_failed");
        return -1;
    }

    if (!llps_llam_runtime_stats_satisfy_single_worker_contract(&stats)) {
        (void)fprintf(stderr,
                      "LLPS requires a single deterministic LLAM worker/node "
                      "(active=%u online=%u floor=%u min=%u max=%u "
                      "nodes=%u dynamic=%u worker_rings=%u multishot=%u "
                      "lockfree_normq=%u sqpoll=%u)\n",
                      (unsigned)stats.active_workers,
                      (unsigned)stats.online_workers,
                      (unsigned)stats.online_workers_floor,
                      (unsigned)stats.online_workers_min,
                      (unsigned)stats.online_workers_max,
                      (unsigned)stats.active_nodes,
                      (unsigned)stats.dynamic_workers,
                      (unsigned)stats.worker_rings,
                      (unsigned)stats.worker_rings_multishot,
                      (unsigned)stats.lockfree_normq,
                      (unsigned)stats.sqpoll);
        LLPS_EXPECT(false,
                    llps_app_llam_contract_failure("runtime_policy_invalid"));
        llps_shutdown_llam_runtime("runtime_policy_invalid");
        return -1;
    }

    llps_log_llam_runtime_contract(&stats);
    return 0;
}

static void llps_set_default_config(llps_yml_config_t *cfg) {
    if (cfg != NULL) {
        (void)memset(cfg, 0, sizeof(*cfg));
        cfg->max_clients = LLPS_MAX_CLIENTS;
        cfg->buffer_size = LLPS_BUFFER_SIZE;

        (void)strncpy(cfg->listen_host, LLPS_LISTEN_HOST, sizeof(cfg->listen_host) - 1);
        cfg->listen_host[sizeof(cfg->listen_host) - 1] = '\0';
        cfg->listen_port = LLPS_LISTEN_PORT_U16;

        (void)strncpy(cfg->target_ip, LLPS_TARGET_IP, sizeof(cfg->target_ip) - 1);
        cfg->target_ip[sizeof(cfg->target_ip) - 1] = '\0';
        cfg->target_port = LLPS_TARGET_PORT_U16;

        cfg->listen_backlog = LLPS_LISTEN_BACKLOG;
        cfg->accept_batch_max = LLPS_ACCEPT_BATCH_MAX;
        cfg->session_idle_timeout_ms =
            LLPS_SESSION_IDLE_TIMEOUT_MS_DEFAULT;
        cfg->max_sessions_per_client_ip = 0u;
        cfg->max_new_sessions_per_client_ip_per_window = 0u;
        cfg->client_ip_rate_window_ms =
            LLPS_CLIENT_IP_RATE_WINDOW_MS_DEFAULT;
        cfg->client_preface_timeout_ms =
            LLPS_CLIENT_PREFACE_TIMEOUT_MS_DEFAULT;
        cfg->protocol_handshake_gate_enabled =
            LLPS_PROTOCOL_HANDSHAKE_GATE_DEFAULT;
        cfg->ip_audit_enabled = 0u;
        cfg->ip_audit_path[0] = '\0';
        cfg->audit_mac_enabled = 0u;
        cfg->audit_mac_key_path[0] = '\0';
        cfg->require_readiness = 0u;
        cfg->platform_safety_flags = 0u;
        cfg->platform_safety_evidence_id = 0u;
        cfg->platform_attestation_fingerprint = 0u;
        cfg->platform_observation_digest = 0u;
        cfg->platform_evidence_mode = LLPS_PLATFORM_EVIDENCE_MODE_REAL;
        for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            cfg->platform_physical_memory_domains[i] = 0u;
            cfg->platform_hardware_tmr_domains[i] = 0u;
        }
        cfg->platform_hardware_tmr_voter_domain = 0u;
        cfg->software_ecc_enabled = 0u;
        cfg->software_ecc_controller_count = 0u;
        cfg->software_ecc_dimm_count = 0u;
        cfg->software_ecc_scrub_rate = 0u;
        cfg->software_ecc_controller_corrected_error_count = 0u;
        cfg->software_ecc_controller_uncorrected_error_count = 0u;
        cfg->software_ecc_dimm_corrected_error_count = 0u;
        cfg->software_ecc_dimm_uncorrected_error_count = 0u;
        cfg->software_numa_enabled = 0u;
        cfg->software_numa_memtotal_kib = 0u;
        cfg->software_numa_local_distance = 0u;
        cfg->software_numa_remote_distance = 0u;
        cfg->software_fault_injection_mode =
            LLPS_SOFTWARE_FAULT_INJECTION_FULL;
        cfg->evidence_mac_enabled = 0u;
        cfg->evidence_mac_key_path[0] = '\0';
    }
}

static int llps_enforce_configured_readiness_gate(const llps_yml_config_t * const cfg) {
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    llps_status_t st = LLPS_OK;

    if (cfg == NULL) {
        return -1;
    }

    if (cfg->require_readiness == 0u) {
        return 0;
    }

    st = llps_collect_platform_safety_evidence(cfg->platform_safety_flags,
                                               cfg->platform_safety_evidence_id,
                                               cfg->platform_physical_memory_domains,
                                               cfg->platform_hardware_tmr_domains,
                                               cfg->platform_hardware_tmr_voter_domain,
                                               &evidence);
    if (st != LLPS_OK) {
        (void)fprintf(stderr,
                      "readiness evidence is malformed "
                      "(status %d)\n",
                      (int)st);
        return -1;
    }

    st = llps_get_readiness_report(&evidence, &report);
    if (st != LLPS_OK) {
        (void)fprintf(stderr,
                      "readiness check failed to run "
                      "(status %d)\n",
                      (int)st);
        return -1;
    }

    if (!report.gate_passed) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(missing mask 0x%08x)\n",
                      (unsigned)report.missing_requirements);
        return -1;
    }

    if (cfg->platform_observation_digest != evidence.observation_digest) {
        (void)fprintf(stderr,
                      "readiness gate rejected startup "
                      "(observation digest mismatch)\n");
        return -1;
    }

    return 0;
}

static unsigned llps_bool_as_u32(const bool value) {
    return value ? 1u : 0u;
}

#define LLPS_PRINT_BOOL_FIELD(label, value) \
    (void)printf(label ": %u\n", llps_bool_as_u32((value)))
#define LLPS_PRINT_U32_FIELD(label, value) \
    (void)printf(label ": %u\n", (unsigned)(value))
#define LLPS_PRINT_HEX_FIELD(label, value) \
    (void)printf(label ": 0x%08x\n", (unsigned)(value))
#define LLPS_PRINT_U64_FIELD(label, value) \
    (void)printf(label ": %llu\n", (unsigned long long)(value))
#define LLPS_PRINT_STR_FIELD(label, value) \
    (void)printf(label ": %s\n", (value))

static void llps_print_memory_core_flags(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_BOOL_FIELD("memory_runtime_cfg_tmr_valid",
                          report->runtime_cfg_tmr_valid);
    LLPS_PRINT_BOOL_FIELD("memory_control_flag_tmr_valid",
                          report->control_flag_tmr_valid);
    LLPS_PRINT_BOOL_FIELD("memory_free_list_tmr_valid",
                          report->free_list_tmr_valid);
    LLPS_PRINT_BOOL_FIELD("memory_shutdown_requested",
                          report->shutdown_requested);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_layout_valid", report->tmr_layout_valid);
    LLPS_PRINT_BOOL_FIELD("memory_process_memory_locked",
                          report->process_memory_locked);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_locked",
                          report->tmr_memory_locked);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_prefaulted",
                          report->tmr_memory_prefaulted);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_domains_bound",
                          report->tmr_memory_domains_bound);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_observed_domains_valid",
                          report->tmr_memory_observed_domains_valid);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_resident",
                          report->tmr_memory_resident);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_physical_frames_distinct",
                          report->tmr_memory_physical_frames_distinct);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_physical_frames_spaced",
                          report->tmr_memory_physical_frames_spaced);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_observed_domain_0",
                         report->tmr_memory_observed_domain_ids[0]);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_observed_domain_1",
                         report->tmr_memory_observed_domain_ids[1]);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_observed_domain_2",
                         report->tmr_memory_observed_domain_ids[2]);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_hardened",
                          report->tmr_memory_hardened);
}

static void llps_print_memory_startup_flags(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_BOOL_FIELD("memory_tmr_startup_self_test_passed",
                          report->tmr_startup_self_test_passed);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_startup_self_test_coverage_valid",
                          report->tmr_startup_self_test_coverage_valid);
    LLPS_PRINT_U32_FIELD("memory_tmr_startup_self_test_coverage",
                         report->tmr_startup_self_test_coverage);
    LLPS_PRINT_HEX_FIELD("memory_tmr_startup_self_test_coverage_hex",
                         report->tmr_startup_self_test_coverage);
    LLPS_PRINT_U32_FIELD("memory_tmr_startup_self_test_required_coverage",
                         report->tmr_startup_self_test_required_coverage);
    LLPS_PRINT_HEX_FIELD("memory_tmr_startup_self_test_required_coverage_hex",
                         report->tmr_startup_self_test_required_coverage);
    LLPS_PRINT_BOOL_FIELD("memory_readiness_runtime_monitor_enabled",
                          report->readiness_runtime_monitor_enabled);
    LLPS_PRINT_BOOL_FIELD("memory_runtime_safety_latches_valid",
                          report->runtime_safety_latches_valid);
    LLPS_PRINT_BOOL_FIELD("memory_safety_counters_valid",
                          report->memory_safety_counters_valid);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_memory_prefault_pages_valid",
                          report->tmr_memory_prefault_pages_valid);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_bank_guard_valid_0",
                          report->tmr_bank_guard_valid[0]);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_bank_guard_valid_1",
                          report->tmr_bank_guard_valid[1]);
    LLPS_PRINT_BOOL_FIELD("memory_tmr_bank_guard_valid_2",
                          report->tmr_bank_guard_valid[2]);
    LLPS_PRINT_U64_FIELD("memory_tmr_bank_distance_01",
                         report->tmr_bank_distance_01);
    LLPS_PRINT_U64_FIELD("memory_tmr_bank_distance_02",
                         report->tmr_bank_distance_02);
    LLPS_PRINT_U64_FIELD("memory_tmr_bank_distance_12",
                         report->tmr_bank_distance_12);
    LLPS_PRINT_U64_FIELD("memory_tmr_metadata_min_bank_distance",
                         report->tmr_metadata_min_bank_distance);
}

static void llps_print_memory_region_counters(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_U64_FIELD("memory_tmr_single_bank_repairs",
                         report->tmr_single_bank_repairs);
    LLPS_PRINT_U64_FIELD("memory_tmr_majority_failures",
                         report->tmr_majority_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_region_guard_faults",
                         report->tmr_region_guard_faults);
    LLPS_PRINT_U64_FIELD("memory_tmr_layout_failures",
                         report->tmr_layout_failures);
    LLPS_PRINT_U64_FIELD("memory_process_memory_lock_failures",
                         report->process_memory_lock_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_lock_failures",
                         report->tmr_memory_lock_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_prefault_pages",
                         report->tmr_memory_prefault_pages);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_prefault_failures",
                         report->tmr_memory_prefault_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_resident_pages",
                         report->tmr_memory_resident_pages);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_residency_failures",
                         report->tmr_memory_residency_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_faults",
                         report->tmr_memory_physical_frame_faults);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_residency_fingerprint",
                         report->tmr_memory_residency_fingerprint);
    LLPS_PRINT_HEX_FIELD("memory_tmr_memory_residency_fingerprint_hex",
                         report->tmr_memory_residency_fingerprint);
}

static void llps_print_memory_physical_frames(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_pages",
                         report->tmr_memory_physical_frame_pages);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_probe_failures",
                         report->tmr_memory_physical_frame_probe_failures);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_min_distance",
                         report->tmr_memory_physical_frame_min_distance);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_required_distance",
                         report->tmr_memory_physical_frame_required_distance);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_distance_01",
                         report->tmr_memory_physical_frame_distance_01);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_distance_02",
                         report->tmr_memory_physical_frame_distance_02);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_physical_frame_distance_12",
                         report->tmr_memory_physical_frame_distance_12);
    LLPS_PRINT_HEX_FIELD("memory_tmr_memory_physical_frame_pair_coverage",
                         report->tmr_memory_physical_frame_pair_coverage);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_physical_frame_fingerprint",
                         report->tmr_memory_physical_frame_fingerprint);
    LLPS_PRINT_HEX_FIELD("memory_tmr_memory_physical_frame_fingerprint_hex",
                         report->tmr_memory_physical_frame_fingerprint);
}

static void llps_print_memory_domain_counters(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_domain_bind_failures",
                         report->tmr_memory_domain_bind_failures);
    LLPS_PRINT_U32_FIELD("memory_tmr_memory_domain_observation_fingerprint",
                         report->tmr_memory_domain_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("memory_tmr_memory_domain_observation_fingerprint_hex",
                         report->tmr_memory_domain_observation_fingerprint);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_domain_pages_checked",
                         report->tmr_memory_domain_pages_checked);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_domain_mismatch_count",
                         report->tmr_memory_domain_mismatch_count);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_domain_probe_failures",
                         report->tmr_memory_domain_probe_failures);
    LLPS_PRINT_HEX_FIELD("memory_tmr_memory_domain_region_coverage",
                         report->tmr_memory_domain_region_coverage);
    LLPS_PRINT_U64_FIELD("memory_tmr_memory_harden_failures",
                         report->tmr_memory_harden_failures);
    LLPS_PRINT_U64_FIELD("memory_contract_violations",
                         report->contract_violations);
    LLPS_PRINT_U64_FIELD("memory_free_list_single_bank_repairs",
                         report->free_list_single_bank_repairs);
    LLPS_PRINT_U64_FIELD("memory_free_list_majority_failures",
                         report->free_list_majority_failures);
    LLPS_PRINT_U64_FIELD("memory_runtime_cfg_single_bank_repairs",
                         report->runtime_cfg_single_bank_repairs);
    LLPS_PRINT_U64_FIELD("memory_runtime_cfg_majority_failures",
                         report->runtime_cfg_majority_failures);
    LLPS_PRINT_U64_FIELD("memory_control_flag_single_bank_repairs",
                         report->control_flag_single_bank_repairs);
    LLPS_PRINT_U64_FIELD("memory_control_flag_majority_failures",
                         report->control_flag_majority_failures);
    LLPS_PRINT_U64_FIELD("memory_secded_single_bit_repairs",
                         report->secded_single_bit_repairs);
    LLPS_PRINT_U64_FIELD("memory_secded_double_bit_failures",
                         report->secded_double_bit_failures);
}

static void llps_print_memory_runtime_counters(
    const llps_memory_safety_report_t * const report) {
    LLPS_PRINT_U64_FIELD("memory_tmr_scrub_passes", report->tmr_scrub_passes);
    LLPS_PRINT_U64_FIELD("memory_tmr_scrub_sessions_checked",
                         report->tmr_scrub_sessions_checked);
    LLPS_PRINT_U64_FIELD("memory_tmr_scrub_fail_closed_sessions",
                         report->tmr_scrub_fail_closed_sessions);
    LLPS_PRINT_U64_FIELD("memory_payload_ecc_scrub_passes",
                         report->payload_ecc_scrub_passes);
    LLPS_PRINT_U64_FIELD("memory_payload_ecc_scrub_sessions_checked",
                         report->payload_ecc_scrub_sessions_checked);
    LLPS_PRINT_U64_FIELD("memory_payload_ecc_scrub_fail_closed_sessions",
                         report->payload_ecc_scrub_fail_closed_sessions);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_monitor_passes",
                         report->readiness_runtime_monitor_passes);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_software_evidence_patrol_passes",
                         report->readiness_runtime_software_evidence_patrol_passes);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_ecc_topology_patrol_passes",
                         report->readiness_runtime_synthetic_ecc_topology_patrol_passes);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_ecc_topology_patrol_failures",
                         report->readiness_runtime_synthetic_ecc_topology_patrol_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_fault_patrol_passes",
                         report->readiness_runtime_synthetic_fault_patrol_passes);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_fault_patrol_failures",
                         report->readiness_runtime_synthetic_fault_patrol_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_numa_patrol_passes",
                         report->readiness_runtime_synthetic_numa_patrol_passes);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_synthetic_numa_patrol_failures",
                         report->readiness_runtime_synthetic_numa_patrol_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_monitor_failures",
                         report->readiness_runtime_monitor_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_cfg_failures",
                         report->readiness_runtime_cfg_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_software_tmr_failures",
                         report->readiness_runtime_software_tmr_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_ecc_failures",
                         report->readiness_runtime_ecc_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_physical_domain_failures",
                         report->readiness_runtime_physical_domain_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_tmr_memory_domain_failures",
                         report->readiness_runtime_tmr_memory_domain_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_hardware_tmr_failures",
                         report->readiness_runtime_hardware_tmr_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_identity_failures",
                         report->readiness_runtime_identity_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_attestation_failures",
                         report->readiness_runtime_attestation_failures);
    LLPS_PRINT_U64_FIELD("memory_readiness_runtime_observation_digest_failures",
                         report->readiness_runtime_observation_digest_failures);
    LLPS_PRINT_U32_FIELD("memory_safety_counters_fingerprint",
                         report->memory_safety_counters_fingerprint);
    LLPS_PRINT_HEX_FIELD("memory_safety_counters_fingerprint_hex",
                         report->memory_safety_counters_fingerprint);
}

static void llps_print_memory_safety_report(
    const llps_memory_safety_report_t * const report) {
    if (report == NULL) {
        return;
    }
    llps_print_memory_core_flags(report);
    llps_print_memory_startup_flags(report);
    llps_print_memory_region_counters(report);
    llps_print_memory_physical_frames(report);
    llps_print_memory_domain_counters(report);
    llps_print_memory_runtime_counters(report);
}

static void llps_print_evidence_header(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_HEX_FIELD("evidence_magic", evidence->magic);
    LLPS_PRINT_U32_FIELD("evidence_version", evidence->version);
    LLPS_PRINT_U32_FIELD("evidence_flags", evidence->flags);
    LLPS_PRINT_HEX_FIELD("evidence_flags_hex", evidence->flags);
    LLPS_PRINT_U32_FIELD("evidence_observed_flags", evidence->observed_flags);
    LLPS_PRINT_U32_FIELD("evidence_attested_flags", evidence->attested_flags);
    LLPS_PRINT_U32_FIELD("evidence_edac_observation_fingerprint",
                         evidence->edac_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_edac_observation_fingerprint_hex",
                         evidence->edac_observation_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_edac_controller_count",
                         evidence->edac_controller_count);
    LLPS_PRINT_U32_FIELD("evidence_edac_dimm_count",
                         evidence->edac_dimm_count);
    LLPS_PRINT_U32_FIELD("evidence_edac_scrub_rate_count",
                         evidence->edac_scrub_rate_count);
    LLPS_PRINT_U32_FIELD("evidence_edac_controller_counter_coverage",
                         evidence->edac_controller_counter_coverage);
    LLPS_PRINT_U32_FIELD("evidence_edac_dimm_mode_coverage",
                         evidence->edac_dimm_mode_coverage);
    LLPS_PRINT_U32_FIELD("evidence_edac_dimm_counter_coverage",
                         evidence->edac_dimm_counter_coverage);
    LLPS_PRINT_U32_FIELD("evidence_edac_scrub_rate_coverage",
                         evidence->edac_scrub_rate_coverage);
    LLPS_PRINT_U64_FIELD("evidence_edac_corrected_error_count",
                         evidence->edac_corrected_error_count);
    LLPS_PRINT_U64_FIELD("evidence_edac_uncorrected_error_count",
                         evidence->edac_uncorrected_error_count);
    LLPS_PRINT_U64_FIELD("evidence_edac_dimm_corrected_error_count",
                         evidence->edac_dimm_corrected_error_count);
    LLPS_PRINT_U64_FIELD("evidence_edac_dimm_uncorrected_error_count",
                         evidence->edac_dimm_uncorrected_error_count);
    LLPS_PRINT_U64_FIELD("evidence_edac_scrub_rate_sum",
                         evidence->edac_scrub_rate_sum);
}

static void llps_print_evidence_identity_fingerprints(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_platform_boot_fingerprint",
                         evidence->platform_boot_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_platform_boot_fingerprint_hex",
                         evidence->platform_boot_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_platform_identity_fingerprint",
                         evidence->platform_identity_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_platform_identity_fingerprint_hex",
                         evidence->platform_identity_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_executable_image_fingerprint",
                         evidence->executable_image_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_executable_image_fingerprint_hex",
                         evidence->executable_image_fingerprint);
}

static void llps_print_evidence_memory_startup(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_process_memory_locked",
                         evidence->process_memory_locked);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_locked",
                         evidence->tmr_memory_locked);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_prefaulted",
                         evidence->tmr_memory_prefaulted);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_prefault_pages",
                         evidence->tmr_memory_prefault_pages);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_hardened",
                         evidence->tmr_memory_hardened);
    LLPS_PRINT_U32_FIELD("evidence_tmr_startup_self_test_passed",
                         evidence->tmr_startup_self_test_passed);
    LLPS_PRINT_U32_FIELD("evidence_tmr_startup_self_test_coverage",
                         evidence->tmr_startup_self_test_coverage);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_startup_self_test_coverage_hex",
                         evidence->tmr_startup_self_test_coverage);
    LLPS_PRINT_U32_FIELD("evidence_tmr_startup_self_test_required_coverage",
                         evidence->tmr_startup_self_test_required_coverage);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_startup_self_test_required_coverage_hex",
                         evidence->tmr_startup_self_test_required_coverage);
}

static void llps_print_evidence_software(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_platform_evidence_mode",
                         evidence->platform_evidence_mode);
    LLPS_PRINT_U32_FIELD("evidence_software_schema_version",
                         evidence->software_evidence_schema_version);
    LLPS_PRINT_U32_FIELD("evidence_software_self_test_passed",
                         evidence->software_evidence_self_test_passed);
    LLPS_PRINT_HEX_FIELD("evidence_software_self_test_coverage",
                         evidence->software_evidence_self_test_coverage);
    LLPS_PRINT_HEX_FIELD("evidence_software_self_test_required_coverage",
                         evidence->software_evidence_self_test_required_coverage);
    LLPS_PRINT_U32_FIELD("evidence_software_ecc_controller_count",
                         evidence->software_ecc_controller_count);
    LLPS_PRINT_U32_FIELD("evidence_software_dimm_bank_count",
                         evidence->software_dimm_bank_count);
    LLPS_PRINT_U64_FIELD("evidence_software_ecc_scrub_rate",
                         evidence->software_ecc_scrub_rate);
    LLPS_PRINT_U32_FIELD("evidence_software_dimm_generation",
                         evidence->software_dimm_generation);
    LLPS_PRINT_U32_FIELD("evidence_software_dimm_scrub_generation",
                         evidence->software_dimm_scrub_generation);
    LLPS_PRINT_HEX_FIELD("evidence_software_dimm_fault_injection_coverage",
                         evidence->software_dimm_fault_injection_coverage);
    LLPS_PRINT_U32_FIELD("evidence_software_fault_injection_mode",
                         evidence->software_fault_injection_mode);
    LLPS_PRINT_STR_FIELD("evidence_software_fault_injection_mode_text",
                         llps_software_fault_injection_mode_text(
                             evidence->software_fault_injection_mode));
    LLPS_PRINT_U32_FIELD("evidence_software_dimm_observation_fingerprint",
                         evidence->software_dimm_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_software_dimm_observation_fingerprint_hex",
                         evidence->software_dimm_observation_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_software_numa_profile_fingerprint",
                         evidence->software_numa_profile_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_software_numa_profile_fingerprint_hex",
                         evidence->software_numa_profile_fingerprint);
}

static void llps_print_evidence_physical_domain(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_physical_domain_observation_fingerprint",
                         evidence->physical_domain_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_physical_domain_observation_fingerprint_hex",
                         evidence->physical_domain_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_physical_domain_topology_coverage",
                         evidence->physical_domain_topology_coverage);
    LLPS_PRINT_U32_FIELD("evidence_physical_domain_observed_count",
                         evidence->physical_domain_observed_count);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_memtotal_kib",
                         evidence->physical_domain_memtotal_kib);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_distance_entries",
                         evidence->physical_domain_distance_entries);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_distance_sum",
                         evidence->physical_domain_distance_sum);
    LLPS_PRINT_HEX_FIELD("evidence_physical_domain_distance_pair_coverage",
                         evidence->physical_domain_distance_pair_coverage);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_distance_01",
                         evidence->physical_domain_distance_01);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_distance_02",
                         evidence->physical_domain_distance_02);
    LLPS_PRINT_U64_FIELD("evidence_physical_domain_distance_12",
                         evidence->physical_domain_distance_12);
}

static void llps_print_evidence_tmr_memory(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_domain_observation_fingerprint",
                         evidence->tmr_memory_domain_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_memory_domain_observation_fingerprint_hex",
                         evidence->tmr_memory_domain_observation_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_resident",
                         evidence->tmr_memory_resident);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_resident_pages",
                         evidence->tmr_memory_resident_pages);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_residency_fingerprint",
                         evidence->tmr_memory_residency_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_memory_residency_fingerprint_hex",
                         evidence->tmr_memory_residency_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_physical_frames_distinct",
                         evidence->tmr_memory_physical_frames_distinct);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_physical_frames_spaced",
                         evidence->tmr_memory_physical_frames_spaced);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_pages",
                         evidence->tmr_memory_physical_frame_pages);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_probe_failures",
                         evidence->tmr_memory_physical_frame_probe_failures);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_min_distance",
                         evidence->tmr_memory_physical_frame_min_distance);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_required_distance",
                         evidence->tmr_memory_physical_frame_required_distance);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_distance_01",
                         evidence->tmr_memory_physical_frame_distance_01);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_distance_02",
                         evidence->tmr_memory_physical_frame_distance_02);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_physical_frame_distance_12",
                         evidence->tmr_memory_physical_frame_distance_12);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_memory_physical_frame_pair_coverage",
                         evidence->tmr_memory_physical_frame_pair_coverage);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_physical_frame_fingerprint",
                         evidence->tmr_memory_physical_frame_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_memory_physical_frame_fingerprint_hex",
                         evidence->tmr_memory_physical_frame_fingerprint);
}

static void llps_print_evidence_tmr_memory_domain(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_domain_pages_checked",
                         evidence->tmr_memory_domain_pages_checked);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_domain_mismatch_count",
                         evidence->tmr_memory_domain_mismatch_count);
    LLPS_PRINT_U64_FIELD("evidence_tmr_memory_domain_probe_failures",
                         evidence->tmr_memory_domain_probe_failures);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_memory_domain_region_coverage",
                         evidence->tmr_memory_domain_region_coverage);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_observed_domain_0",
                         evidence->tmr_memory_observed_domain_ids[0]);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_observed_domain_1",
                         evidence->tmr_memory_observed_domain_ids[1]);
    LLPS_PRINT_U32_FIELD("evidence_tmr_memory_observed_domain_2",
                         evidence->tmr_memory_observed_domain_ids[2]);
}

static void llps_print_evidence_domain_ids(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U64_FIELD("evidence_id", evidence->evidence_id);
    LLPS_PRINT_U32_FIELD("evidence_physical_memory_domain_0",
                         evidence->physical_memory_domain_ids[0]);
    LLPS_PRINT_U32_FIELD("evidence_physical_memory_domain_1",
                         evidence->physical_memory_domain_ids[1]);
    LLPS_PRINT_U32_FIELD("evidence_physical_memory_domain_2",
                         evidence->physical_memory_domain_ids[2]);
    LLPS_PRINT_U32_FIELD("evidence_hardware_tmr_domain_0",
                         evidence->hardware_tmr_domain_ids[0]);
    LLPS_PRINT_U32_FIELD("evidence_hardware_tmr_domain_1",
                         evidence->hardware_tmr_domain_ids[1]);
    LLPS_PRINT_U32_FIELD("evidence_hardware_tmr_domain_2",
                         evidence->hardware_tmr_domain_ids[2]);
    LLPS_PRINT_U32_FIELD("evidence_hardware_tmr_voter_domain",
                         evidence->hardware_tmr_voter_domain_id);
}

static void llps_print_evidence_trailer(
    const llps_platform_safety_evidence_t * const evidence) {
    LLPS_PRINT_U32_FIELD("evidence_attestation_fingerprint",
                         evidence->attestation_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_attestation_fingerprint_hex",
                         evidence->attestation_fingerprint);
    llps_print_evidence_domain_ids(evidence);
    LLPS_PRINT_U32_FIELD("evidence_tmr_layout_fingerprint",
                         evidence->tmr_layout_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_tmr_layout_fingerprint_hex",
                         evidence->tmr_layout_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_observation_digest",
                         evidence->observation_digest);
    LLPS_PRINT_HEX_FIELD("evidence_observation_digest_hex",
                         evidence->observation_digest);
    LLPS_PRINT_U32_FIELD("evidence_mac_enabled", evidence->evidence_mac_enabled);
    LLPS_PRINT_U32_FIELD("evidence_mac_key_fingerprint",
                         evidence->evidence_mac_key_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_mac_key_fingerprint_hex",
                         evidence->evidence_mac_key_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_crc", evidence->crc);
    LLPS_PRINT_HEX_FIELD("evidence_crc_hex", evidence->crc);
    LLPS_PRINT_U32_FIELD("evidence_crc_inverse", evidence->crc_inverse);
    LLPS_PRINT_HEX_FIELD("evidence_crc_inverse_hex", evidence->crc_inverse);
}

static void llps_print_evidence_report(
    const llps_platform_safety_evidence_t * const evidence) {
    if (evidence == NULL) {
        return;
    }
    llps_print_evidence_header(evidence);
    llps_print_evidence_identity_fingerprints(evidence);
    llps_print_evidence_memory_startup(evidence);
    llps_print_evidence_software(evidence);
    llps_print_evidence_physical_domain(evidence);
    llps_print_evidence_tmr_memory(evidence);
    llps_print_evidence_tmr_memory_domain(evidence);
    llps_print_evidence_trailer(evidence);
}

typedef struct {
    llps_platform_safety_evidence_t evidence;
    llps_readiness_report_t report;
    const llps_platform_safety_evidence_t *evidence_ref;
} llps_readiness_diagnostics_t;

static void llps_print_readiness_config_core(
    const llps_yml_config_t * const cfg) {
    LLPS_PRINT_U32_FIELD("readiness_report_version", 3u);
    LLPS_PRINT_U32_FIELD("configured_require_readiness",
                         cfg->require_readiness);
    LLPS_PRINT_U32_FIELD("configured_platform_safety_flags",
                         cfg->platform_safety_flags);
    LLPS_PRINT_HEX_FIELD("configured_platform_safety_flags_hex",
                         cfg->platform_safety_flags);
    LLPS_PRINT_U32_FIELD("configured_payload_ecc_enabled",
                         cfg->payload_ecc_enabled);
    LLPS_PRINT_U64_FIELD("configured_platform_safety_evidence_id",
                         cfg->platform_safety_evidence_id);
    LLPS_PRINT_U32_FIELD("configured_platform_attestation_fingerprint",
                         cfg->platform_attestation_fingerprint);
    LLPS_PRINT_HEX_FIELD("configured_platform_attestation_fingerprint_hex",
                         cfg->platform_attestation_fingerprint);
    LLPS_PRINT_U32_FIELD("configured_platform_observation_digest",
                         cfg->platform_observation_digest);
    LLPS_PRINT_HEX_FIELD("configured_platform_observation_digest_hex",
                         cfg->platform_observation_digest);
    LLPS_PRINT_U32_FIELD("configured_platform_evidence_mode",
                         cfg->platform_evidence_mode);
    LLPS_PRINT_STR_FIELD("configured_platform_evidence_mode_text",
                         llps_platform_evidence_mode_text(
                             cfg->platform_evidence_mode));
    LLPS_PRINT_STR_FIELD("configured_platform_evidence_scope",
                         llps_platform_evidence_scope_text(
                             cfg->platform_evidence_mode));
    LLPS_PRINT_BOOL_FIELD("configured_synthetic_evidence_active",
                          llps_platform_evidence_mode_uses_software(
                              cfg->platform_evidence_mode));
    LLPS_PRINT_BOOL_FIELD("configured_software_platform_model_active",
                          llps_platform_evidence_mode_uses_software(
                              cfg->platform_evidence_mode));
}

static void llps_print_readiness_config_scopes(
    const llps_yml_config_t * const cfg) {
    LLPS_PRINT_STR_FIELD("configured_ecc_evidence_scope",
                         llps_ecc_evidence_scope_text(
                             cfg->platform_evidence_mode,
                             cfg->software_ecc_enabled != 0u));
    LLPS_PRINT_STR_FIELD("configured_physical_memory_evidence_scope",
                         llps_physical_memory_evidence_scope_text(
                             cfg->platform_evidence_mode,
                             cfg->software_numa_enabled != 0u));
    LLPS_PRINT_STR_FIELD("configured_independent_tmr_evidence_scope",
                         llps_independent_tmr_evidence_scope_text(
                             cfg->platform_evidence_mode));
    LLPS_PRINT_U32_FIELD("configured_physical_memory_domain_0",
                         cfg->platform_physical_memory_domains[0]);
    LLPS_PRINT_U32_FIELD("configured_physical_memory_domain_1",
                         cfg->platform_physical_memory_domains[1]);
    LLPS_PRINT_U32_FIELD("configured_physical_memory_domain_2",
                         cfg->platform_physical_memory_domains[2]);
    LLPS_PRINT_U32_FIELD("configured_hardware_tmr_domain_0",
                         cfg->platform_hardware_tmr_domains[0]);
    LLPS_PRINT_U32_FIELD("configured_hardware_tmr_domain_1",
                         cfg->platform_hardware_tmr_domains[1]);
    LLPS_PRINT_U32_FIELD("configured_hardware_tmr_domain_2",
                         cfg->platform_hardware_tmr_domains[2]);
    LLPS_PRINT_U32_FIELD("configured_hardware_tmr_voter_domain",
                         cfg->platform_hardware_tmr_voter_domain);
}

static void llps_print_readiness_config_software(
    const llps_yml_config_t * const cfg) {
    LLPS_PRINT_U32_FIELD("configured_software_ecc_enabled",
                         cfg->software_ecc_enabled);
    LLPS_PRINT_U32_FIELD("configured_software_ecc_controller_count",
                         cfg->software_ecc_controller_count);
    LLPS_PRINT_U32_FIELD("configured_software_ecc_dimm_count",
                         cfg->software_ecc_dimm_count);
    LLPS_PRINT_U64_FIELD("configured_software_ecc_scrub_rate",
                         cfg->software_ecc_scrub_rate);
    LLPS_PRINT_U64_FIELD("configured_software_ecc_controller_corrected_error_count",
                         cfg->software_ecc_controller_corrected_error_count);
    LLPS_PRINT_U64_FIELD("configured_software_ecc_controller_uncorrected_error_count",
                         cfg->software_ecc_controller_uncorrected_error_count);
    LLPS_PRINT_U64_FIELD("configured_software_ecc_dimm_corrected_error_count",
                         cfg->software_ecc_dimm_corrected_error_count);
    LLPS_PRINT_U64_FIELD("configured_software_ecc_dimm_uncorrected_error_count",
                         cfg->software_ecc_dimm_uncorrected_error_count);
    LLPS_PRINT_U32_FIELD("configured_software_numa_enabled",
                         cfg->software_numa_enabled);
    LLPS_PRINT_U64_FIELD("configured_software_numa_memtotal_kib",
                         cfg->software_numa_memtotal_kib);
    LLPS_PRINT_U64_FIELD("configured_software_numa_local_distance",
                         cfg->software_numa_local_distance);
    LLPS_PRINT_U64_FIELD("configured_software_numa_remote_distance",
                         cfg->software_numa_remote_distance);
    LLPS_PRINT_U32_FIELD("configured_software_fault_injection_mode",
                         cfg->software_fault_injection_mode);
    LLPS_PRINT_STR_FIELD("configured_software_fault_injection_mode_text",
                         llps_software_fault_injection_mode_text(
                             cfg->software_fault_injection_mode));
}

static void llps_print_readiness_config_trailer(
    const llps_yml_config_t * const cfg,
    const llps_status_t status) {
    LLPS_PRINT_U32_FIELD("configured_audit_mac_enabled",
                         cfg->audit_mac_enabled);
    LLPS_PRINT_STR_FIELD("configured_audit_mac_key_path",
                         cfg->audit_mac_key_path);
    LLPS_PRINT_U32_FIELD("configured_evidence_mac_enabled",
                         cfg->evidence_mac_enabled);
    LLPS_PRINT_STR_FIELD("configured_evidence_mac_key_path",
                         cfg->evidence_mac_key_path);
    (void)printf("diagnostic_init_status: %d\n", (int)status);
}

static void llps_print_readiness_config(
    const llps_yml_config_t * const cfg,
    const llps_status_t status) {
    llps_print_readiness_config_core(cfg);
    llps_print_readiness_config_scopes(cfg);
    llps_print_readiness_config_software(cfg);
    llps_print_readiness_config_trailer(cfg, status);
}

static bool llps_readiness_collect_diagnostics(
    const llps_yml_config_t * const cfg,
    llps_readiness_diagnostics_t * const diagnostics) {
    llps_status_t status = LLPS_OK;

    if ((cfg == NULL) || (diagnostics == NULL)) {
        return false;
    }
    (void)memset(diagnostics, 0, sizeof(*diagnostics));
    status = llps_collect_platform_safety_evidence(
        cfg->platform_safety_flags,
        cfg->platform_safety_evidence_id,
        cfg->platform_physical_memory_domains,
        cfg->platform_hardware_tmr_domains,
        cfg->platform_hardware_tmr_voter_domain,
        &diagnostics->evidence);
    (void)printf("evidence_collection_status: %d\n", (int)status);
    if (status == LLPS_OK) {
        diagnostics->evidence_ref = &diagnostics->evidence;
        llps_print_evidence_report(diagnostics->evidence_ref);
    }
    status = llps_get_readiness_report(diagnostics->evidence_ref,
                                       &diagnostics->report);
    (void)printf("report_status: %d\n", (int)status);
    return status == LLPS_OK;
}

static uint32_t llps_readiness_effective_missing(
    const llps_readiness_report_t * const report) {
    if (report == NULL) {
        return UINT32_MAX;
    }
    return report->missing_requirements |
           (report->configured_evidence_request_bound ?
            0u :
            LLPS_READINESS_MISSING_ATTESTATION_BINDING) |
           (report->configured_platform_observation_digest_bound ?
            0u :
            LLPS_READINESS_MISSING_OBSERVATION_DIGEST_BINDING);
}

static bool llps_readiness_effective_gate_passed(
    const llps_readiness_report_t * const report) {
    return (report != NULL) &&
           report->gate_passed &&
           report->configured_evidence_request_bound &&
           report->configured_platform_observation_digest_bound;
}

static void llps_print_readiness_gate_and_ecc(
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_BOOL_FIELD("gate_passed",
                          llps_readiness_effective_gate_passed(report));
    LLPS_PRINT_HEX_FIELD("missing_requirements",
                         llps_readiness_effective_missing(report));
    LLPS_PRINT_BOOL_FIELD("software_tmr_ready", report->software_tmr_ready);
    LLPS_PRINT_BOOL_FIELD("platform_evidence_valid",
                          report->platform_evidence_valid);
    LLPS_PRINT_BOOL_FIELD("ecc_memory_ready", report->ecc_memory_ready);
    LLPS_PRINT_BOOL_FIELD("ecc_counters_clean", report->ecc_counters_clean);
    LLPS_PRINT_U32_FIELD("edac_controller_count",
                         report->edac_controller_count);
    LLPS_PRINT_U32_FIELD("edac_dimm_count", report->edac_dimm_count);
    LLPS_PRINT_U32_FIELD("edac_scrub_rate_count",
                         report->edac_scrub_rate_count);
    LLPS_PRINT_BOOL_FIELD("edac_controller_counter_coverage",
                          report->edac_controller_counter_coverage);
    LLPS_PRINT_BOOL_FIELD("edac_dimm_mode_coverage",
                          report->edac_dimm_mode_coverage);
    LLPS_PRINT_BOOL_FIELD("edac_dimm_counter_coverage",
                          report->edac_dimm_counter_coverage);
    LLPS_PRINT_BOOL_FIELD("edac_scrub_rate_coverage",
                          report->edac_scrub_rate_coverage);
    LLPS_PRINT_U64_FIELD("edac_corrected_error_count",
                         report->edac_corrected_error_count);
    LLPS_PRINT_U64_FIELD("edac_uncorrected_error_count",
                         report->edac_uncorrected_error_count);
    LLPS_PRINT_U64_FIELD("edac_dimm_corrected_error_count",
                         report->edac_dimm_corrected_error_count);
    LLPS_PRINT_U64_FIELD("edac_dimm_uncorrected_error_count",
                         report->edac_dimm_uncorrected_error_count);
    LLPS_PRINT_U64_FIELD("edac_scrub_rate_sum", report->edac_scrub_rate_sum);
}

static void llps_print_readiness_physical_domain(
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_BOOL_FIELD("physical_memory_separation_ready",
                          report->physical_memory_separation_ready);
    LLPS_PRINT_HEX_FIELD("physical_domain_topology_coverage",
                         report->physical_domain_topology_coverage);
    LLPS_PRINT_U32_FIELD("physical_domain_observed_count",
                         report->physical_domain_observed_count);
    LLPS_PRINT_U64_FIELD("physical_domain_memtotal_kib",
                         report->physical_domain_memtotal_kib);
    LLPS_PRINT_U64_FIELD("physical_domain_distance_entries",
                         report->physical_domain_distance_entries);
    LLPS_PRINT_U64_FIELD("physical_domain_distance_sum",
                         report->physical_domain_distance_sum);
    LLPS_PRINT_HEX_FIELD("physical_domain_distance_pair_coverage",
                         report->physical_domain_distance_pair_coverage);
    LLPS_PRINT_U64_FIELD("physical_domain_distance_01",
                         report->physical_domain_distance_01);
    LLPS_PRINT_U64_FIELD("physical_domain_distance_02",
                         report->physical_domain_distance_02);
    LLPS_PRINT_U64_FIELD("physical_domain_distance_12",
                         report->physical_domain_distance_12);
}

static void llps_print_readiness_tmr_and_binding(
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_BOOL_FIELD("independent_hardware_tmr_ready",
                          report->independent_hardware_tmr_ready);
    LLPS_PRINT_BOOL_FIELD("physical_memory_domains_distinct",
                          report->physical_memory_domains_distinct);
    LLPS_PRINT_BOOL_FIELD("hardware_tmr_domains_distinct",
                          report->hardware_tmr_domains_distinct);
    LLPS_PRINT_BOOL_FIELD("hardware_tmr_voter_domain_independent",
                          report->hardware_tmr_voter_domain_independent);
    LLPS_PRINT_U32_FIELD("hardware_tmr_voter_domain_id",
                         report->hardware_tmr_voter_domain_id);
    LLPS_PRINT_BOOL_FIELD("hardware_tmr_domains_independent",
                          report->hardware_tmr_domains_independent);
    LLPS_PRINT_BOOL_FIELD("platform_evidence_layout_bound",
                          report->platform_evidence_layout_bound);
    LLPS_PRINT_BOOL_FIELD("platform_evidence_edac_bound",
                          report->platform_evidence_edac_bound);
    LLPS_PRINT_BOOL_FIELD("platform_evidence_physical_domain_bound",
                          report->platform_evidence_physical_domain_bound);
    LLPS_PRINT_BOOL_FIELD("platform_evidence_tmr_memory_domain_bound",
                          report->platform_evidence_tmr_memory_domain_bound);
    LLPS_PRINT_BOOL_FIELD("platform_attestation_bound",
                          report->platform_attestation_bound);
    LLPS_PRINT_BOOL_FIELD("platform_boot_bound", report->platform_boot_bound);
    LLPS_PRINT_BOOL_FIELD("platform_identity_bound",
                          report->platform_identity_bound);
    LLPS_PRINT_BOOL_FIELD("executable_image_bound",
                          report->executable_image_bound);
    LLPS_PRINT_BOOL_FIELD("software_evidence_self_test_ready",
                          report->software_evidence_self_test_ready);
    LLPS_PRINT_BOOL_FIELD("evidence_mac_valid", report->evidence_mac_valid);
    LLPS_PRINT_BOOL_FIELD("payload_ecc_ready", report->payload_ecc_ready);
    LLPS_PRINT_BOOL_FIELD("configured_evidence_request_bound",
                          report->configured_evidence_request_bound);
}

static void llps_print_readiness_platform_identity(
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_U32_FIELD("platform_evidence_boot_fingerprint",
                         report->platform_evidence_boot_fingerprint);
    LLPS_PRINT_HEX_FIELD("platform_evidence_boot_fingerprint_hex",
                         report->platform_evidence_boot_fingerprint);
    LLPS_PRINT_U32_FIELD("platform_evidence_identity_fingerprint",
                         report->platform_evidence_identity_fingerprint);
    LLPS_PRINT_HEX_FIELD("platform_evidence_identity_fingerprint_hex",
                         report->platform_evidence_identity_fingerprint);
    LLPS_PRINT_U32_FIELD("executable_image_fingerprint",
                         report->executable_image_fingerprint);
    LLPS_PRINT_HEX_FIELD("executable_image_fingerprint_hex",
                         report->executable_image_fingerprint);
    LLPS_PRINT_U32_FIELD("platform_evidence_observation_digest",
                         report->platform_evidence_observation_digest);
    LLPS_PRINT_HEX_FIELD("platform_evidence_observation_digest_hex",
                         report->platform_evidence_observation_digest);
}

static void llps_print_readiness_platform_mode(
    const llps_yml_config_t * const cfg,
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_U32_FIELD("platform_evidence_mode",
                         report->platform_evidence_mode);
    LLPS_PRINT_STR_FIELD("platform_evidence_mode_text",
                         llps_platform_evidence_mode_text(
                             report->platform_evidence_mode));
    LLPS_PRINT_STR_FIELD("platform_evidence_scope",
                         llps_platform_evidence_scope_text(
                             report->platform_evidence_mode));
    LLPS_PRINT_BOOL_FIELD("synthetic_evidence_active",
                          llps_platform_evidence_mode_uses_software(
                              report->platform_evidence_mode));
    LLPS_PRINT_BOOL_FIELD("software_platform_model_active",
                          llps_platform_evidence_mode_uses_software(
                              report->platform_evidence_mode));
    LLPS_PRINT_STR_FIELD("ecc_evidence_scope",
                         llps_ecc_evidence_scope_text(
                             report->platform_evidence_mode,
                             cfg->software_ecc_enabled != 0u));
    LLPS_PRINT_STR_FIELD("physical_memory_evidence_scope",
                         llps_physical_memory_evidence_scope_text(
                             report->platform_evidence_mode,
                             cfg->software_numa_enabled != 0u));
    LLPS_PRINT_STR_FIELD("independent_tmr_evidence_scope",
                         llps_independent_tmr_evidence_scope_text(
                             report->platform_evidence_mode));
}

static void llps_print_readiness_software_model(
    const llps_readiness_report_t * const report) {
    LLPS_PRINT_U32_FIELD("software_evidence_schema_version",
                         report->software_evidence_schema_version);
    LLPS_PRINT_HEX_FIELD("software_evidence_self_test_coverage",
                         report->software_evidence_self_test_coverage);
    LLPS_PRINT_HEX_FIELD("software_evidence_self_test_required_coverage",
                         report->software_evidence_self_test_required_coverage);
    LLPS_PRINT_U32_FIELD("software_dimm_bank_count",
                         report->software_dimm_bank_count);
    LLPS_PRINT_U32_FIELD("software_ecc_controller_count",
                         report->software_ecc_controller_count);
    LLPS_PRINT_U64_FIELD("software_ecc_scrub_rate",
                         report->software_ecc_scrub_rate);
    LLPS_PRINT_U32_FIELD("software_dimm_generation",
                         report->software_dimm_generation);
    LLPS_PRINT_U32_FIELD("software_dimm_scrub_generation",
                         report->software_dimm_scrub_generation);
    LLPS_PRINT_HEX_FIELD("software_dimm_fault_injection_coverage",
                         report->software_dimm_fault_injection_coverage);
    LLPS_PRINT_U32_FIELD("software_fault_injection_mode",
                         report->software_fault_injection_mode);
    LLPS_PRINT_STR_FIELD("software_fault_injection_mode_text",
                         llps_software_fault_injection_mode_text(
                             report->software_fault_injection_mode));
    LLPS_PRINT_U32_FIELD("software_dimm_observation_fingerprint",
                         report->software_dimm_observation_fingerprint);
    LLPS_PRINT_HEX_FIELD("software_dimm_observation_fingerprint_hex",
                         report->software_dimm_observation_fingerprint);
    LLPS_PRINT_U32_FIELD("software_numa_profile_fingerprint",
                         report->software_numa_profile_fingerprint);
    LLPS_PRINT_HEX_FIELD("software_numa_profile_fingerprint_hex",
                         report->software_numa_profile_fingerprint);
    LLPS_PRINT_U32_FIELD("evidence_mac_key_fingerprint",
                         report->evidence_mac_key_fingerprint);
    LLPS_PRINT_HEX_FIELD("evidence_mac_key_fingerprint_hex",
                         report->evidence_mac_key_fingerprint);
    LLPS_PRINT_BOOL_FIELD("configured_platform_observation_digest_bound",
                          report->configured_platform_observation_digest_bound);
}

static void llps_print_readiness_result(
    const llps_yml_config_t * const cfg,
    const llps_readiness_report_t * const report) {
    llps_print_readiness_gate_and_ecc(report);
    llps_print_readiness_physical_domain(report);
    llps_print_readiness_tmr_and_binding(report);
    llps_print_readiness_platform_identity(report);
    llps_print_readiness_platform_mode(cfg, report);
    llps_print_readiness_software_model(report);
    llps_print_memory_safety_report(&report->memory);
}

static int llps_print_readiness_diagnostics(
    const llps_yml_config_t * const cfg) {
    llps_readiness_diagnostics_t diagnostics;

    if (!llps_readiness_collect_diagnostics(cfg, &diagnostics)) {
        return 1;
    }
    llps_print_readiness_result(cfg, &diagnostics.report);
    return 0;
}

static int llps_print_readiness_report(
    const llps_yml_config_t * const cfg) {
    int exit_code = 1;
    llps_status_t status = LLPS_OK;

    if (cfg == NULL) {
        return 1;
    }
    if (llps_init_checked_llam_runtime() != 0) {
        return 1;
    }
    status = llps_init_for_diagnostics(cfg);
    llps_print_readiness_config(cfg, status);
    if (status == LLPS_OK) {
        exit_code = llps_print_readiness_diagnostics(cfg);
    }
    llps_ip_audit_shutdown();
    llps_shutdown_llam_runtime("print_readiness_report_done");
    return exit_code;
}

typedef struct {
    const char *config_path;
    int print_attestation_fingerprint;
    int print_readiness_report;
    int help_requested;
} llps_cli_options_t;

#define LLPS_CLI_ARG_MAX (64)

static void llps_cli_options_init(llps_cli_options_t * const opts) {
    if (opts != NULL) {
        opts->config_path = NULL;
        opts->print_attestation_fingerprint = 0;
        opts->print_readiness_report = 0;
        opts->help_requested = 0;
    }
}

static int llps_print_usage(const char * const argv0) {
    (void)fprintf(stderr,
                  "Usage: %s [-c config.yml] "
                  "[--print-platform-attestation-fingerprint] "
                  "[--print-readiness-report]\n",
                  (argv0 != NULL) ? argv0 : "llps");
    return 0;
}

static bool llps_cli_arg_is_attestation_flag(const char * const arg) {
    return (arg != NULL) &&
           ((strcmp(arg, "--print-platform-attestation-fingerprint") == 0) ||
            (strcmp(arg, "--print-attestation-fingerprint") == 0));
}

static int llps_parse_config_arg(const int argc,
                                 const char *argv[],
                                 int * const index,
                                 llps_cli_options_t * const opts) {
    if ((index == NULL) || (opts == NULL) || ((*index + 1) >= argc)) {
        (void)fprintf(stderr, "Error: -c requires an argument\n");
        return 1;
    }
    opts->config_path = argv[*index + 1];
    ++(*index);
    return 0;
}

static int llps_parse_one_arg(const int argc,
                              const char *argv[],
                              int * const index,
                              llps_cli_options_t * const opts) {
    const char * const arg = ((argv != NULL) && (index != NULL)) ?
                             argv[*index] :
                             NULL;

    if ((arg == NULL) || (opts == NULL)) {
        return 1;
    }
    if (strcmp(arg, "-c") == 0) {
        return llps_parse_config_arg(argc, argv, index, opts);
    }
    if (llps_cli_arg_is_attestation_flag(arg)) {
        opts->print_attestation_fingerprint = 1;
        return 0;
    }
    if (strcmp(arg, "--print-readiness-report") == 0) {
        opts->print_readiness_report = 1;
        return 0;
    }
    if (strcmp(arg, "-h") == 0) {
        opts->help_requested = 1;
        return llps_print_usage(argv[0]);
    }
    (void)fprintf(stderr, "Unknown option: %s\n", arg);
    return 1;
}

static int llps_parse_cli_args(const int argc,
                               const char *argv[],
                               llps_cli_options_t * const opts) {
    if ((argv == NULL) || (opts == NULL) ||
        (argc <= 0) || (argc > LLPS_CLI_ARG_MAX)) {
        (void)fprintf(stderr, "Invalid command line\n");
        return 1;
    }
    llps_cli_options_init(opts);
    for (int i = 1; i < LLPS_CLI_ARG_MAX; ++i) {
        if (i >= argc) {
            break;
        }
        if (llps_parse_one_arg(argc, argv, &i, opts) != 0) {
            return 1;
        }
        if (opts->help_requested != 0) {
            return 0;
        }
    }
    return 0;
}

static int llps_validate_cli_options(
    const llps_cli_options_t * const opts) {
    if (opts == NULL) {
        return 1;
    }
    if ((opts->print_attestation_fingerprint != 0) &&
        (opts->config_path == NULL)) {
        (void)fprintf(stderr,
                      "Error: --print-platform-attestation-fingerprint "
                      "requires -c config.yml\n");
        return 1;
    }
    if ((opts->print_attestation_fingerprint != 0) &&
        (opts->print_readiness_report != 0)) {
        (void)fprintf(stderr,
                      "Error: attestation fingerprint and readiness report "
                      "modes are mutually exclusive\n");
        return 1;
    }
    return 0;
}

static llps_yml_status_t llps_load_selected_config(
    const llps_cli_options_t * const opts,
    llps_yml_config_t * const cfg,
    uint32_t * const error_line) {
    if (opts->print_attestation_fingerprint != 0) {
        return llps_yml_load_config_for_attestation_ex(opts->config_path,
                                                       cfg,
                                                       error_line);
    }
    return llps_yml_load_config_ex(opts->config_path, cfg, error_line);
}

static int llps_load_runtime_config(const llps_cli_options_t * const opts,
                                    llps_yml_config_t * const cfg) {
    uint32_t error_line = 0u;
    llps_yml_status_t st = LLPS_YML_OK;

    if ((opts == NULL) || (cfg == NULL)) {
        return 1;
    }
    if (opts->config_path == NULL) {
        llps_set_default_config(cfg);
        if (opts->print_readiness_report == 0) {
            (void)printf("Using default compiled configuration\n");
        }
        return 0;
    }
    st = llps_load_selected_config(opts, cfg, &error_line);
    if (st != LLPS_YML_OK) {
        (void)fprintf(stderr, "Failed to load config '%s': %s (Line %u)\n",
                      opts->config_path,
                      llps_yml_status_string(st),
                      (unsigned)error_line);
        fflush(stderr);
        return EXIT_FAILURE;
    }
    if ((opts->print_attestation_fingerprint == 0) &&
        (opts->print_readiness_report == 0)) {
        (void)printf("Loaded configuration from %s\n", opts->config_path);
        fflush(stdout);
    }
    return 0;
}

static int llps_print_attestation_fingerprint(
    const llps_yml_config_t * const cfg) {
    uint32_t fingerprint = 0u;
    const llps_status_t st = llps_compute_platform_attestation_fingerprint(
        cfg->platform_safety_flags,
        cfg->platform_safety_evidence_id,
        cfg->platform_physical_memory_domains,
        cfg->platform_hardware_tmr_domains,
        cfg->platform_hardware_tmr_voter_domain,
        &fingerprint);

    if (st != LLPS_OK) {
        (void)fprintf(stderr,
                      "Failed to compute platform attestation "
                      "fingerprint (status %d)\n",
                      (int)st);
        return 1;
    }
    LLPS_PRINT_U32_FIELD("platform_attestation_fingerprint", fingerprint);
    LLPS_PRINT_HEX_FIELD("platform_attestation_fingerprint_hex", fingerprint);
    return 0;
}

static void llps_install_signal_handlers(void) {
    struct sigaction sa;

#if defined(SIGPIPE)
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, NULL);
#endif

    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
}

static bool llps_init_proxy_runtime(const llps_yml_config_t * const cfg) {
    if (llps_init_checked_llam_runtime() != 0) {
        return false;
    }
    if (llps_init(cfg) != LLPS_OK) {
        (void)fprintf(stderr, "Failed to initialize LLPS state\n");
        llps_ip_audit_shutdown();
        llps_shutdown_llam_runtime("llps_init_failed");
        return false;
    }
    if (llps_enforce_configured_readiness_gate(cfg) != 0) {
        llps_ip_audit_shutdown();
        llps_shutdown_llam_runtime("readiness_gate_failed");
        return false;
    }
    return true;
}

static bool llps_open_proxy_listen_socket(
    const llps_yml_config_t * const cfg,
    int * const listen_fd) {
    if (llps_open_listen_socket(cfg, listen_fd) == LLPS_OK) {
        return true;
    }
    if (cfg != NULL) {
        (void)fprintf(stderr,
                      "Failed to bind listen socket on %s:%u\n",
                      cfg->listen_host,
                      (unsigned)cfg->listen_port);
    }
    return false;
}

static const char *llps_spawn_proxy_server_task(int * const listen_fd) {
    llam_spawn_opts_t server_opts;

    if (llps_prepare_llam_spawn_opts(&server_opts,
                                     LLAM_TASK_CLASS_LATENCY,
                                     LLAM_SPAWN_F_SYS_TASK |
                                     LLAM_SPAWN_F_LATENCY_CRITICAL) != 0) {
        return "server_spawn_opts_failed";
    }
    if (llps_spawn_checked(llps_run_server,
                           listen_fd,
                           &server_opts,
                           "server_spawn") == NULL) {
        return "server_spawn_failed";
    }
    return NULL;
}

static void llps_print_server_started(const llps_yml_config_t * const cfg) {
    (void)printf("LLPS runtime initialized; server listening on %s:%u (target: %s:%u, buf: %u)\n",
                 cfg->listen_host,
                 (unsigned)cfg->listen_port,
                 cfg->target_ip,
                 (unsigned)cfg->target_port,
                 (unsigned)cfg->buffer_size);
}

static int llps_run_proxy_server(const llps_yml_config_t * const cfg) {
    int exit_code = 1;
    static int listen_fd = LLPS_INVALID_FD;
    const char *spawn_failure = NULL;

    llps_install_signal_handlers();
    if (!llps_init_proxy_runtime(cfg)) {
        return 1;
    }
    if (!llps_open_proxy_listen_socket(cfg, &listen_fd)) {
        llps_ip_audit_shutdown();
        llps_shutdown_llam_runtime("listen_socket_open_failed");
        return 1;
    }
    spawn_failure = llps_spawn_proxy_server_task(&listen_fd);
    if (spawn_failure != NULL) {
        (void)llps_close_listen_socket(&listen_fd);
        llps_ip_audit_shutdown();
        llps_shutdown_llam_runtime(spawn_failure);
        return 1;
    }
    llps_print_server_started(cfg);

    if (llps_run_llam_runtime_checked()) {
        exit_code = 0;
    }

    /*
     * Defensive cleanup:
     * - If the server task took ownership, listen_fd is LLPS_INVALID_FD.
     * - If the task never actually ran, this closes the still-owned fd.
     */
    (void)llps_close_listen_socket(&listen_fd);

    llps_ip_audit_shutdown();
    llps_shutdown_llam_runtime("main_done");
    return exit_code;
}

int main(int argc, const char *argv[]) {
    llps_yml_config_t cfg;
    llps_cli_options_t opts;

    if (llps_parse_cli_args(argc, argv, &opts) != 0) {
        return 1;
    }
    if (opts.help_requested != 0) {
        return 0;
    }
    if (llps_validate_cli_options(&opts) != 0) {
        return 1;
    }
    if (llps_load_runtime_config(&opts, &cfg) != 0) {
        return EXIT_FAILURE;
    }
    if (opts.print_attestation_fingerprint != 0) {
        return llps_print_attestation_fingerprint(&cfg);
    }
    if (opts.print_readiness_report != 0) {
        return llps_print_readiness_report(&cfg);
    }
    return llps_run_proxy_server(&cfg);
}
