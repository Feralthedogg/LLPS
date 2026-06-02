/**
 * @file src/internal/llps_guard.h
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#ifndef LLPS_GUARD_H
#define LLPS_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/** @brief Convert a boolean to the guarded 0/1 word representation. */
uint32_t llps_guarded_bool_word(bool value);
/** @brief Convert a boolean to a plain 0/1 word. */
uint32_t llps_bool_to_u32(bool value);
/** @brief Store a boolean and its inverse guard together. */
void llps_guarded_bool_set(bool *value_ref,
                           uint32_t *inverse_ref,
                           bool value);
/** @brief Validate a boolean and inverse guard pair. */
bool llps_guarded_bool_is_valid(bool value, uint32_t inverse);
/** @brief Read a guarded boolean, returning false when the guard is invalid. */
bool llps_guarded_bool_read(bool value, uint32_t inverse);

#endif /* LLPS_GUARD_H */
