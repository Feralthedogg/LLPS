/**
 * @file src/readiness/llps_readiness_monitor_worker.c
 * @brief Runtime readiness gates and background evidence monitoring.
 *
 * @details
 * Readiness modules turn observed evidence into startup and runtime
 * pass/fail decisions.
 */

#include "llps_readiness_monitor_worker.h"

#if !defined(LLPS_TEST_HOOKS)

#include "llps_internal.h"
#include "llps_log.h"
#include "llps_readiness_config.h"
#include "llps_readiness_runtime_failures.h"

#include "llam/runtime.h"

#include <errno.h>
#include <stddef.h>

typedef struct {
    llam_channel_t *request_channel;
    bool collector_started;
    bool request_pending;
    bool worker_busy;
    bool result_valid;
    uint64_t request_generation;
    uint64_t result_generation;
    uint64_t consumed_generation;
    uint64_t request_time_ns;
    llps_yml_config_t request_cfg;
    llps_status_t result_status;
    uint32_t result_failure_mask;
} llps_readiness_runtime_monitor_worker_t;

typedef struct {
    llps_yml_config_t cfg;
    llps_status_t status;
    uint32_t failure_mask;
} llps_readiness_runtime_monitor_blocking_job_t;

static llps_readiness_runtime_monitor_worker_t g_readiness_runtime_monitor_worker;

static void llps_readiness_monitor_llam_contract_failure(
    const char * const operation,
    const uint32_t failure_mask) {
    const uint32_t bounded_mask =
        (failure_mask != 0u) ? failure_mask : LLPS_READINESS_RUNTIME_FAILURE_CFG;

    llps_logf("readiness_monitor_llam_contract_failure operation=%s "
              "failure_mask=0x%08x",
              (operation != NULL) ? operation : "unknown",
              (unsigned)bounded_mask);
    llps_readiness_runtime_monitor_count_failure_mask(bounded_mask);
}

static bool llps_readiness_monitor_channel_destroy_checked(
    llam_channel_t * const channel,
    const char * const operation) {
    if ((channel == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    if (llam_channel_destroy(channel) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    return true;
}

static llam_channel_t *llps_readiness_monitor_channel_create_checked(
    const size_t capacity,
    const char * const operation) {
    llam_channel_t *channel = NULL;

    if ((capacity == 0u) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return NULL;
    }

    channel = llam_channel_create(capacity);

    if (channel == NULL) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
    }

    return channel;
}

static bool llps_readiness_monitor_spawn_opts_init_checked(
    llam_spawn_opts_t * const opts,
    const char * const operation) {
    if ((opts == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    if (llam_spawn_opts_init(opts, LLAM_SPAWN_OPTS_CURRENT_SIZE) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    return true;
}

static llam_task_t *llps_readiness_monitor_spawn_checked(
    llam_task_fn fn,
    void * const arg,
    const llam_spawn_opts_t * const opts,
    const char * const operation) {
    llam_task_t *task = NULL;

    if ((fn == NULL) || (opts == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return NULL;
    }

    task = llam_spawn_ex(fn,
                         arg,
                         opts,
                         LLAM_SPAWN_OPTS_CURRENT_SIZE);

    if (task == NULL) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
    }

    return task;
}

static bool llps_readiness_monitor_detach_checked(
    llam_task_t * const task,
    const char * const operation) {
    if ((task == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    if (llam_detach(task) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    return true;
}

static bool llps_readiness_monitor_call_blocking_checked(
    llam_blocking_fn fn,
    void * const arg,
    void ** const out,
    const char * const operation,
    const uint32_t failure_mask) {
    if ((fn == NULL) || (out == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        failure_mask));
        return false;
    }

    *out = NULL;
    if (llam_call_blocking_result(fn, arg, out) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        failure_mask));
        return false;
    }

    return true;
}

static bool llps_readiness_monitor_channel_send_checked(
    llam_channel_t * const channel,
    void * const value,
    const char * const operation) {
    if ((channel == NULL) || (value == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG |
                        LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION));
        return false;
    }

    if (llam_channel_send(channel, value) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG |
                        LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION));
        return false;
    }

    return true;
}

static bool llps_readiness_monitor_channel_recv_checked(
    llam_channel_t * const channel,
    void ** const out,
    const char * const operation) {
    if ((channel == NULL) || (out == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG |
                        LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION));
        return false;
    }

    *out = NULL;
    errno = 0;
    if (llam_channel_recv_result(channel, out) != 0) {
        const int recv_errno = errno;

        if (recv_errno != EPIPE) {
            LLPS_EXPECT(false,
                        llps_readiness_monitor_llam_contract_failure(
                            operation,
                            LLPS_READINESS_RUNTIME_FAILURE_CFG |
                            LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION));
        }
        return false;
    }

    return true;
}

static bool llps_readiness_monitor_channel_close_checked(
    llam_channel_t * const channel,
    const char * const operation) {
    if ((channel == NULL) || (operation == NULL)) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    if (llam_channel_close(channel) != 0) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        operation,
                        LLPS_READINESS_RUNTIME_FAILURE_CFG));
        return false;
    }

    return true;
}

static void *llps_readiness_runtime_monitor_blocking_collect(void *arg) {
    llps_readiness_runtime_monitor_blocking_job_t * const job =
        (llps_readiness_runtime_monitor_blocking_job_t *)arg;

    if (job == NULL) {
        return NULL;
    }
    job->failure_mask = 0u;
    job->status =
        llps_check_configured_readiness_platform_snapshot(&job->cfg,
                                                          &job->failure_mask);
    return job;
}

static void llps_readiness_runtime_monitor_worker_note_bad_message(void) {
    g_readiness_runtime_monitor_worker.result_status = LLPS_E_RUNTIME;
    g_readiness_runtime_monitor_worker.result_failure_mask =
        LLPS_READINESS_RUNTIME_FAILURE_CFG;
    ++g_readiness_runtime_monitor_worker.result_generation;
    g_readiness_runtime_monitor_worker.result_valid = true;
}

static void llps_readiness_runtime_monitor_worker_take_request(
    llps_yml_config_t * const out_cfg,
    uint64_t * const out_generation) {
    if ((out_cfg != NULL) && (out_generation != NULL)) {
        *out_cfg = g_readiness_runtime_monitor_worker.request_cfg;
        *out_generation = g_readiness_runtime_monitor_worker.request_generation;
        g_readiness_runtime_monitor_worker.request_pending = false;
        g_readiness_runtime_monitor_worker.worker_busy = true;
    }
}

static void llps_readiness_runtime_monitor_worker_init_job(
    llps_readiness_runtime_monitor_blocking_job_t * const job,
    const llps_yml_config_t * const cfg) {
    if ((job != NULL) && (cfg != NULL)) {
        job->cfg = *cfg;
        job->status = LLPS_E_RUNTIME;
        job->failure_mask = 0u;
    }
}

static void llps_readiness_runtime_monitor_worker_note_bad_result(
    llps_readiness_runtime_monitor_blocking_job_t * const job,
    void * const result) {
    if (job == NULL) {
        return;
    }
    if (result != job) {
        LLPS_EXPECT(false,
                    llps_readiness_monitor_llam_contract_failure(
                        "readiness_blocking_collect_result",
                        LLPS_READINESS_RUNTIME_FAILURE_CFG |
                        LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION));
    }
    job->status = LLPS_E_RUNTIME;
    job->failure_mask =
        LLPS_READINESS_RUNTIME_FAILURE_CFG |
        LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION;
}

static void llps_readiness_runtime_monitor_worker_publish_result(
    const uint64_t generation,
    const llps_status_t status,
    const uint32_t failure_mask) {
    g_readiness_runtime_monitor_worker.result_status = status;
    g_readiness_runtime_monitor_worker.result_failure_mask = failure_mask;
    g_readiness_runtime_monitor_worker.result_generation = generation;
    g_readiness_runtime_monitor_worker.result_valid = true;
    g_readiness_runtime_monitor_worker.worker_busy = false;
}

static void llps_readiness_runtime_monitor_worker_task(void *arg) {
    (void)arg;

    for (uint64_t worker_cycle = 0u;
         worker_cycle < UINT64_MAX;
         ++worker_cycle) {
        llps_yml_config_t cfg_snapshot;
        llps_readiness_runtime_monitor_blocking_job_t job;
        void *message = NULL;
        void *result = NULL;
        uint64_t generation = 0u;

        if (!llps_readiness_monitor_channel_recv_checked(
                g_readiness_runtime_monitor_worker.request_channel,
                &message,
                "readiness_channel_recv")) {
            break;
        }
        if (message != &g_readiness_runtime_monitor_worker) {
            llps_readiness_runtime_monitor_worker_note_bad_message();
            continue;
        }

        llps_readiness_runtime_monitor_worker_take_request(&cfg_snapshot,
                                                           &generation);

        llps_readiness_runtime_monitor_worker_init_job(&job, &cfg_snapshot);
        if (!llps_readiness_monitor_call_blocking_checked(
                llps_readiness_runtime_monitor_blocking_collect,
                &job,
                &result,
                "readiness_blocking_collect",
                LLPS_READINESS_RUNTIME_FAILURE_CFG |
                LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION) ||
            (result != &job)) {
            llps_readiness_runtime_monitor_worker_note_bad_result(&job, result);
        }

        llps_readiness_runtime_monitor_worker_publish_result(
            generation,
            job.status,
            job.failure_mask);
    }

    g_readiness_runtime_monitor_worker.collector_started = false;
}

static bool llps_readiness_runtime_monitor_worker_destroy_stale_channel(void) {
    if (g_readiness_runtime_monitor_worker.request_channel == NULL) {
        return true;
    }
    if (!llps_readiness_monitor_channel_destroy_checked(
            g_readiness_runtime_monitor_worker.request_channel,
            "readiness_channel_destroy_stale")) {
        return false;
    }
    g_readiness_runtime_monitor_worker.request_channel = NULL;
    return true;
}

static void llps_readiness_runtime_monitor_worker_reset_state(void) {
    g_readiness_runtime_monitor_worker.request_pending = false;
    g_readiness_runtime_monitor_worker.worker_busy = false;
    g_readiness_runtime_monitor_worker.result_valid = false;
    g_readiness_runtime_monitor_worker.request_generation = 0u;
    g_readiness_runtime_monitor_worker.result_generation = 0u;
    g_readiness_runtime_monitor_worker.consumed_generation = 0u;
    g_readiness_runtime_monitor_worker.request_time_ns = 0u;
}

static bool llps_readiness_runtime_monitor_worker_destroy_after_start_failure(
    const char * const operation) {
    (void)llps_readiness_monitor_channel_destroy_checked(
        g_readiness_runtime_monitor_worker.request_channel,
        operation);
    g_readiness_runtime_monitor_worker.request_channel = NULL;
    return false;
}

static void llps_readiness_runtime_monitor_worker_configure_opts(
    llam_spawn_opts_t * const opts) {
    if (opts != NULL) {
        opts->task_class = LLAM_TASK_CLASS_BATCH;
        opts->stack_class = LLAM_STACK_CLASS_DEFAULT;
        opts->flags |= LLAM_SPAWN_F_SYS_TASK;
    }
}

bool llps_readiness_runtime_monitor_worker_start(void) {
    llam_spawn_opts_t opts;
    llam_task_t *collector_task = NULL;

    if (g_readiness_runtime_monitor_worker.collector_started) {
        return true;
    }
    if (!llps_readiness_runtime_monitor_worker_destroy_stale_channel()) {
        return false;
    }

    g_readiness_runtime_monitor_worker.request_channel =
        llps_readiness_monitor_channel_create_checked(
            1u,
            "readiness_channel_create");
    if (g_readiness_runtime_monitor_worker.request_channel == NULL) {
        return false;
    }
    llps_readiness_runtime_monitor_worker_reset_state();

    if (!llps_readiness_monitor_spawn_opts_init_checked(
            &opts,
            "readiness_spawn_opts_init")) {
        return llps_readiness_runtime_monitor_worker_destroy_after_start_failure(
            "readiness_channel_destroy_after_opts");
    }
    llps_readiness_runtime_monitor_worker_configure_opts(&opts);

    collector_task = llps_readiness_monitor_spawn_checked(
        llps_readiness_runtime_monitor_worker_task,
        NULL,
        &opts,
        "readiness_worker_spawn");
    if (collector_task == NULL) {
        return llps_readiness_runtime_monitor_worker_destroy_after_start_failure(
            "readiness_channel_destroy_after_spawn");
    }
    if (!llps_readiness_monitor_detach_checked(collector_task,
                                              "readiness_worker_detach")) {
        (void)llps_readiness_monitor_channel_close_checked(
            g_readiness_runtime_monitor_worker.request_channel,
            "readiness_channel_close_after_detach");
        return false;
    }

    g_readiness_runtime_monitor_worker.collector_started = true;
    return true;
}

void llps_readiness_runtime_monitor_worker_stop(void) {
    if (g_readiness_runtime_monitor_worker.request_channel != NULL) {
        (void)llps_readiness_monitor_channel_close_checked(
            g_readiness_runtime_monitor_worker.request_channel,
            "readiness_channel_close_stop");
    }
}

static bool llps_readiness_runtime_monitor_worker_submit(
    const llps_yml_config_t * const cfg,
    const uint64_t now_ns) {
    bool can_submit = false;

    if (cfg == NULL) {
        return false;
    }
    if (g_readiness_runtime_monitor_worker.request_channel == NULL) {
        return false;
    }
    can_submit = g_readiness_runtime_monitor_worker.collector_started &&
                 !g_readiness_runtime_monitor_worker.request_pending &&
                 !g_readiness_runtime_monitor_worker.worker_busy;
    if (can_submit) {
        ++g_readiness_runtime_monitor_worker.request_generation;
        if (g_readiness_runtime_monitor_worker.request_generation == 0u) {
            g_readiness_runtime_monitor_worker.request_generation = 1u;
        }
        g_readiness_runtime_monitor_worker.request_cfg = *cfg;
        g_readiness_runtime_monitor_worker.request_time_ns = now_ns;
        g_readiness_runtime_monitor_worker.request_pending = true;
        if (!llps_readiness_monitor_channel_send_checked(
                g_readiness_runtime_monitor_worker.request_channel,
                &g_readiness_runtime_monitor_worker,
                "readiness_channel_send")) {
            g_readiness_runtime_monitor_worker.request_pending = false;
            can_submit = false;
        }
    }

    return can_submit;
}

static bool llps_readiness_runtime_monitor_worker_take_result(
    llps_status_t * const out_status,
    uint32_t * const out_failure_mask,
    bool * const out_result_consumed) {
    if ((out_status == NULL) || (out_failure_mask == NULL)) {
        return false;
    }
    if (!g_readiness_runtime_monitor_worker.result_valid ||
        (g_readiness_runtime_monitor_worker.result_generation ==
         g_readiness_runtime_monitor_worker.consumed_generation)) {
        return false;
    }

    *out_status = g_readiness_runtime_monitor_worker.result_status;
    *out_failure_mask =
        g_readiness_runtime_monitor_worker.result_failure_mask;
    g_readiness_runtime_monitor_worker.consumed_generation =
        g_readiness_runtime_monitor_worker.result_generation;
    if (out_result_consumed != NULL) {
        *out_result_consumed = true;
    }
    return true;
}

static bool llps_readiness_runtime_monitor_worker_request_timed_out(
    const uint64_t now_ns,
    const uint64_t timeout_ns,
    const uint64_t request_time_ns) {
    return (request_time_ns != 0u) &&
           (now_ns >= request_time_ns) &&
           ((now_ns - request_time_ns) > timeout_ns);
}

llps_status_t llps_readiness_runtime_monitor_worker_poll(
    const llps_yml_config_t * const cfg,
    const uint64_t now_ns,
    const uint64_t timeout_ns,
    uint32_t * const out_failure_mask,
    bool * const out_result_consumed) {
    bool collector_started = false;
    bool pending_or_busy = false;
    llps_status_t result_status = LLPS_OK;
    uint32_t result_failure_mask = 0u;
    uint64_t request_time_ns = 0u;

    if (out_failure_mask == NULL) {
        return LLPS_E_NULL;
    }
    *out_failure_mask = 0u;
    if (out_result_consumed != NULL) {
        *out_result_consumed = false;
    }

    collector_started = g_readiness_runtime_monitor_worker.collector_started;
    pending_or_busy = g_readiness_runtime_monitor_worker.request_pending ||
                      g_readiness_runtime_monitor_worker.worker_busy;
    request_time_ns = g_readiness_runtime_monitor_worker.request_time_ns;
    const bool result_ready =
        llps_readiness_runtime_monitor_worker_take_result(
            &result_status,
            &result_failure_mask,
            out_result_consumed);

    if (!collector_started) {
        *out_failure_mask = LLPS_READINESS_RUNTIME_FAILURE_CFG;
        return LLPS_E_RUNTIME;
    }
    if (result_ready && (result_status != LLPS_OK)) {
        *out_failure_mask =
            (result_failure_mask != 0u) ?
            result_failure_mask :
            LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION;
        return result_status;
    }

    if (!pending_or_busy) {
        (void)llps_readiness_runtime_monitor_worker_submit(cfg, now_ns);
    } else if (llps_readiness_runtime_monitor_worker_request_timed_out(
                   now_ns,
                   timeout_ns,
                   request_time_ns)) {
        *out_failure_mask =
            LLPS_READINESS_RUNTIME_FAILURE_CFG |
            LLPS_READINESS_RUNTIME_FAILURE_ATTESTATION;
        return LLPS_E_RUNTIME;
    }

    return LLPS_OK;
}

#endif
