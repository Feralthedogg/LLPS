/**
 * @file src/support/llps_guard.c
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#include "llps_guard.h"

#include <stddef.h>
#include <stdint.h>

uint32_t llps_guarded_bool_word(const bool value) {
    return value ? UINT32_MAX : 0u;
}

uint32_t llps_bool_to_u32(const bool value) {
    return value ? 1u : 0u;
}

void llps_guarded_bool_set(bool * const value_ref,
                           uint32_t * const inverse_ref,
                           const bool value) {
    if ((value_ref != NULL) && (inverse_ref != NULL)) {
        const uint32_t word = llps_guarded_bool_word(value);

        *value_ref = value;
        *inverse_ref = ~word;
    }
}

bool llps_guarded_bool_is_valid(const bool value, const uint32_t inverse) {
    return inverse == ~llps_guarded_bool_word(value);
}

bool llps_guarded_bool_read(const bool value, const uint32_t inverse) {
    return llps_guarded_bool_is_valid(value, inverse) && value;
}
