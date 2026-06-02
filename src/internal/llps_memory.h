/**
 * @file src/internal/llps_memory.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_MEMORY_H
#define LLPS_MEMORY_H

#include <stddef.h>

/** @brief Zero a memory range using a compiler-resistant byte scrub loop. */
void llps_secure_bzero(void *ptr, size_t len);

#endif /* LLPS_MEMORY_H */
