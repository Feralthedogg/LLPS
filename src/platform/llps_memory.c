/**
 * @file src/platform/llps_memory.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_memory.h"

#include <stdint.h>

void llps_secure_bzero(void * const ptr, const size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    if (p != NULL) {
        for (size_t i = 0u; i < len; ++i) {
            p[i] = 0u;
        }
    }
}
