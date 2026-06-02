/**
 * @file src/internal/llps_log.h
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#ifndef LLPS_LOG_H
#define LLPS_LOG_H

#include <stdbool.h>
#include <stdio.h>

/** @brief Read a boolean-like environment flag with a deterministic default. */
bool llps_env_flag_enabled(const char *name, bool default_value);
/** @brief Return true when normal LLPS logging is enabled. */
bool llps_log_enabled(void);
/** @brief Return true when high-volume I/O logging is enabled. */
bool llps_io_log_enabled(void);
/** @brief Return true when endpoint audit event blocks are enabled. */
bool llps_audit_log_enabled(void);
/** @brief Return true when readiness evidence event blocks are enabled. */
bool llps_evidence_log_enabled(void);
/** @brief Begin a single log line emission. */
void llps_log_begin(void);
/** @brief Finish a single log line emission. */
void llps_log_end(void);

/** @brief Emit a formatted LLPS log line when normal logging is enabled. */
#define llps_logf(...) \
    do { \
        if (llps_log_enabled()) { \
            llps_log_begin(); \
            (void)fprintf(stdout, __VA_ARGS__); \
            llps_log_end(); \
        } \
    } while (0)

#endif /* LLPS_LOG_H */
