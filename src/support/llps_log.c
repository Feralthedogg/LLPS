/**
 * @file src/support/llps_log.c
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#include "llps_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool llps_env_flag_enabled(const char * const name, const bool default_value) {
    const char *value = NULL;

    if (name == NULL) {
        return default_value;
    }

    value = getenv(name);
    if (value == NULL) {
        return default_value;
    }

    if ((strcmp(value, "0") == 0) ||
        (strcmp(value, "false") == 0) ||
        (strcmp(value, "FALSE") == 0) ||
        (strcmp(value, "off") == 0) ||
        (strcmp(value, "OFF") == 0) ||
        (strcmp(value, "no") == 0) ||
        (strcmp(value, "NO") == 0)) {
        return false;
    }

    return true;
}

bool llps_log_enabled(void) {
    return llps_env_flag_enabled("LLPS_LOG", true);
}

bool llps_io_log_enabled(void) {
    return llps_env_flag_enabled("LLPS_LOG_IO", false);
}

bool llps_audit_log_enabled(void) {
    return llps_env_flag_enabled("LLPS_LOG_AUDIT", true);
}

bool llps_evidence_log_enabled(void) {
    return llps_env_flag_enabled("LLPS_LOG_EVIDENCE", true);
}

void llps_log_begin(void) {
    (void)fprintf(stdout, "[llps] ");
}

void llps_log_end(void) {
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
}
