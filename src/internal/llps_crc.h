/**
 * @file src/internal/llps_crc.h
 * @brief Shared low-level support helpers for LLPS modules.
 *
 * @details
 * Support modules provide small deterministic helpers shared by multiple
 * LLPS layers.
 */

#ifndef LLPS_CRC_H
#define LLPS_CRC_H

#include <stddef.h>
#include <stdint.h>

/** @brief Initial CRC value used for LLPS protected records. */
#define LLPS_SESSION_CRC_INIT              (0xFFFFFFFFu)
/** @brief Final XOR value used for LLPS protected records. */
#define LLPS_SESSION_CRC_XOROUT            (0xFFFFFFFFu)

/** @brief Fold one byte into an in-progress CRC32 value. */
uint32_t llps_crc32_update_byte(uint32_t crc, uint8_t byte);
/** @brief Fold one little-endian 32-bit value into an in-progress CRC32. */
uint32_t llps_crc32_update_u32(uint32_t crc, uint32_t value);
/** @brief Fold one little-endian 64-bit value into an in-progress CRC32. */
uint32_t llps_crc32_update_u64(uint32_t crc, uint64_t value);
/** @brief Fold a size_t value into an in-progress CRC32. */
uint32_t llps_crc32_update_size(uint32_t crc, size_t value);
/** @brief Fold a pointer value into an in-progress CRC32. */
uint32_t llps_crc32_update_ptr(uint32_t crc, const void *ptr);
/** @brief Fold a bounded NUL-terminated string into an in-progress CRC32. */
uint32_t llps_crc32_update_cstr_bounded(uint32_t crc,
                                        const char *text,
                                        size_t cap);
/** @brief Replace a zero fingerprint with a stable nonzero sentinel. */
uint32_t llps_nonzero_fingerprint(uint32_t fingerprint);

#endif /* LLPS_CRC_H */
