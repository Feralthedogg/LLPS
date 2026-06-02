/**
 * @file src/internal/llps_config_validate.h
 * @brief Configuration parsing and validation for LLPS runtime options.
 *
 * @details
 * Configuration code owns text input normalization before values cross into
 * the runtime state.
 */

#ifndef LLPS_CONFIG_VALIDATE_H
#define LLPS_CONFIG_VALIDATE_H

#include "llps.h"

#include <stdbool.h>

/** @brief Validate normalized runtime configuration values and bounds. */
bool llps_runtime_cfg_values_are_valid(const llps_yml_config_t *cfg);

#endif /* LLPS_CONFIG_VALIDATE_H */
