/**
 * @file src/internal/llps_secded.h
 * @brief Single-error correction, double-error detection helpers.
 *
 * @details
 * SECDED protects individual fixed-width metadata words. It complements CRC
 * and TMR: SECDED repairs a one-bit word fault locally, CRC detects broader
 * corruption, and TMR supplies majority repair across separated banks.
 */

#ifndef LLPS_SECDED_H
#define LLPS_SECDED_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    LLPS_SECDED_OK = 0,
    LLPS_SECDED_CORRECTED,
    LLPS_SECDED_UNCORRECTABLE
} llps_secded_status_t;

/** @brief Build an 8-bit SECDED code for the low @p data_bits bits. */
uint8_t llps_secded_encode_u64(uint64_t data, uint32_t data_bits);
/** @brief Validate that @p ecc matches @p data. */
bool llps_secded_is_valid_u64(uint64_t data,
                              uint32_t data_bits,
                              uint8_t ecc);
/** @brief Repair one-bit data/ECC faults, or detect an uncorrectable fault. */
llps_secded_status_t llps_secded_repair_u64(uint64_t *data,
                                            uint32_t data_bits,
                                            uint8_t *ecc);

uint8_t llps_secded_encode_u32(uint32_t data);
bool llps_secded_is_valid_u32(uint32_t data, uint8_t ecc);
llps_secded_status_t llps_secded_repair_u32(uint32_t *data, uint8_t *ecc);

uint8_t llps_secded_encode_u16(uint16_t data);
bool llps_secded_is_valid_u16(uint16_t data, uint8_t ecc);
llps_secded_status_t llps_secded_repair_u16(uint16_t *data, uint8_t *ecc);

#endif /* LLPS_SECDED_H */
