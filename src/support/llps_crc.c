/**
 * @file src/support/llps_crc.c
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#include "llps_crc.h"

#include <stdint.h>

uint32_t llps_crc32_update_byte(uint32_t crc, const uint8_t byte) {
    crc ^= (uint32_t)byte;

    for (uint32_t bit = 0u; bit < 8u; ++bit) {
        const uint32_t mask = 0u - (crc & 1u);
        crc = (crc >> 1u) ^ (0xEDB88320u & mask);
    }

    return crc;
}

uint32_t llps_crc32_update_u32(uint32_t crc, const uint32_t value) {
    for (uint32_t shift = 0u; shift < 32u; shift += 8u) {
        crc = llps_crc32_update_byte(
            crc,
            (uint8_t)((value >> shift) & 0xFFu));
    }

    return crc;
}

uint32_t llps_crc32_update_u64(uint32_t crc, const uint64_t value) {
    for (uint32_t shift = 0u; shift < 64u; shift += 8u) {
        crc = llps_crc32_update_byte(
            crc,
            (uint8_t)((value >> shift) & 0xFFu));
    }

    return crc;
}

uint32_t llps_crc32_update_size(uint32_t crc, const size_t value) {
    return llps_crc32_update_u64(crc, (uint64_t)value);
}

uint32_t llps_crc32_update_ptr(uint32_t crc, const void * const ptr) {
    return llps_crc32_update_u64(crc, (uint64_t)(uintptr_t)ptr);
}

uint32_t llps_crc32_update_cstr_bounded(uint32_t crc,
                                        const char * const text,
                                        const size_t cap) {
    if (text == NULL) {
        return llps_crc32_update_u32(crc, 0u);
    }

    for (size_t i = 0u; i < cap; ++i) {
        const uint8_t byte = (uint8_t)(unsigned char)text[i];

        crc = llps_crc32_update_byte(crc, byte);
        if (byte == 0u) {
            break;
        }
    }

    return crc;
}

uint32_t llps_nonzero_fingerprint(const uint32_t fingerprint) {
    return (fingerprint != 0u) ? fingerprint : UINT32_MAX;
}
