/**
 * @file src/internal/yml_parser.h
 * @brief Configuration parsing and validation for LLPS runtime options.
 *
 * @details
 * Configuration code owns text input normalization before values cross into
 * the runtime state.
 */

#ifndef YML_PARSER_H
#define YML_PARSER_H

#include "llps.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif /* YML_PARSER_H */
