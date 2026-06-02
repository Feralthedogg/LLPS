/**
 * @file src/support/llps_secded.c
 * @brief Single-error correction, double-error detection helpers.
 *
 * @details
 * Implements a compact extended Hamming code for 1..64 data bits. The low
 * seven bits store Hamming parity, and bit 7 stores overall parity.
 */

#include "llps_secded.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define LLPS_SECDED_OVERALL_BIT ((uint8_t)0x80u)
#define LLPS_SECDED_MAX_DATA_BITS (64u)
#define LLPS_SECDED_U64_PARITY_BITS (7u)

static bool llps_secded_is_power_of_two(const uint32_t value) {
    return (value != 0u) && ((value & (value - 1u)) == 0u);
}

static uint8_t llps_secded_parity_u64(uint64_t value) {
    value ^= value >> 32u;
    value ^= value >> 16u;
    value ^= value >> 8u;
    value ^= value >> 4u;
    value &= UINT64_C(0x0f);

    return (uint8_t)((UINT64_C(0x6996) >> value) & UINT64_C(1));
}

static uint32_t llps_secded_parity_bits_for_data_bits(
    const uint32_t data_bits) {
    uint32_t parity_bits = 1u;

    for (parity_bits = 1u;
         (parity_bits < 8u) &&
         (((uint32_t)1u << parity_bits) <
          (data_bits + parity_bits + 1u));
         ++parity_bits) {
    }

    return parity_bits;
}

static uint64_t llps_secded_data_mask(const uint32_t data_bits) {
    if (data_bits >= LLPS_SECDED_MAX_DATA_BITS) {
        return UINT64_MAX;
    }

    return (UINT64_C(1) << data_bits) - UINT64_C(1);
}

static uint8_t llps_secded_encode_u64_full(const uint64_t data) {
    static const uint64_t parity_masks[LLPS_SECDED_U64_PARITY_BITS] = {
        UINT64_C(0xab55555556aaad5b),
        UINT64_C(0xcd9999999b33366d),
        UINT64_C(0xf1e1e1e1e3c3c78e),
        UINT64_C(0x01fe01fe03fc07f0),
        UINT64_C(0x01fffe0003fff800),
        UINT64_C(0x01fffffffc000000),
        UINT64_C(0xfe00000000000000)
    };
    uint8_t hamming = 0u;
    uint8_t overall = 0u;

    for (uint32_t i = 0u; i < LLPS_SECDED_U64_PARITY_BITS; ++i) {
        hamming |= (uint8_t)(llps_secded_parity_u64(data & parity_masks[i])
                             << i);
    }

    overall = (uint8_t)(llps_secded_parity_u64(data) ^
                        llps_secded_parity_u64(hamming));
    return (uint8_t)(hamming | (uint8_t)(overall << 7u));
}

static uint32_t llps_secded_data_index_for_position(
    const uint32_t code_position,
    const uint32_t data_bits) {
    uint32_t data_index = 0u;
    const uint32_t parity_bits =
        llps_secded_parity_bits_for_data_bits(data_bits);
    const uint32_t total_positions = data_bits + parity_bits;

    for (uint32_t pos = 1u; pos <= total_positions; ++pos) {
        if (llps_secded_is_power_of_two(pos)) {
            continue;
        }

        if (pos == code_position) {
            return data_index;
        }
        ++data_index;
    }

    return UINT32_MAX;
}

uint8_t llps_secded_encode_u64(const uint64_t data,
                               const uint32_t data_bits) {
    const uint32_t bounded_bits =
        (data_bits > LLPS_SECDED_MAX_DATA_BITS) ?
        LLPS_SECDED_MAX_DATA_BITS :
        data_bits;
    const uint32_t parity_bits =
        llps_secded_parity_bits_for_data_bits(bounded_bits);
    const uint32_t total_positions = bounded_bits + parity_bits;
    const uint64_t masked_data = data & llps_secded_data_mask(bounded_bits);
    uint8_t hamming = 0u;
    uint8_t overall = 0u;

    if (bounded_bits == LLPS_SECDED_MAX_DATA_BITS) {
        return llps_secded_encode_u64_full(data);
    }

    for (uint32_t parity_index = 0u;
         parity_index < parity_bits;
         ++parity_index) {
        const uint32_t parity_position = (uint32_t)1u << parity_index;
        uint8_t parity = 0u;
        uint32_t data_index = 0u;

        for (uint32_t pos = 1u; pos <= total_positions; ++pos) {
            if (llps_secded_is_power_of_two(pos)) {
                continue;
            }

            if ((pos & parity_position) != 0u) {
                parity ^= (uint8_t)((masked_data >> data_index) &
                                    UINT64_C(1));
            }
            ++data_index;
        }

        hamming |= (uint8_t)(parity << parity_index);
    }

    overall = (uint8_t)(llps_secded_parity_u64(masked_data) ^
                        llps_secded_parity_u64(hamming));
    return (uint8_t)(hamming | (uint8_t)(overall << 7u));
}

bool llps_secded_is_valid_u64(const uint64_t data,
                              const uint32_t data_bits,
                              const uint8_t ecc) {
    return ecc == llps_secded_encode_u64(data, data_bits);
}

static llps_secded_status_t llps_secded_apply_repair_u64(
    uint64_t * const data,
    uint8_t * const ecc,
    const uint32_t bounded_bits,
    const uint32_t total_positions,
    const uint8_t expected_ecc,
    const uint8_t syndrome,
    const uint8_t overall_error,
    const uint64_t masked_data) {
    if ((syndrome == 0u) && (overall_error == 0u)) {
        return LLPS_SECDED_OK;
    }
    if ((syndrome == 0u) && (overall_error != 0u)) {
        *ecc = expected_ecc;
        return LLPS_SECDED_CORRECTED;
    }
    if ((syndrome != 0u) && (overall_error == 0u)) {
        return LLPS_SECDED_UNCORRECTABLE;
    }
    if (syndrome > total_positions) {
        return LLPS_SECDED_UNCORRECTABLE;
    }
    if (llps_secded_is_power_of_two(syndrome)) {
        *ecc = expected_ecc;
        return LLPS_SECDED_CORRECTED;
    }

    const uint32_t data_index =
        llps_secded_data_index_for_position(syndrome, bounded_bits);
    if (data_index >= bounded_bits) {
        return LLPS_SECDED_UNCORRECTABLE;
    }

    *data = masked_data ^ (UINT64_C(1) << data_index);
    *ecc = llps_secded_encode_u64(*data, bounded_bits);
    return LLPS_SECDED_CORRECTED;
}

llps_secded_status_t llps_secded_repair_u64(uint64_t * const data,
                                            const uint32_t data_bits,
                                            uint8_t * const ecc) {
    const uint32_t bounded_bits =
        (data_bits > LLPS_SECDED_MAX_DATA_BITS) ?
        LLPS_SECDED_MAX_DATA_BITS :
        data_bits;
    const uint32_t parity_bits =
        llps_secded_parity_bits_for_data_bits(bounded_bits);
    const uint32_t total_positions = bounded_bits + parity_bits;
    const uint8_t parity_mask =
        (uint8_t)(((uint32_t)1u << parity_bits) - 1u);
    uint8_t expected_ecc = 0u;
    uint8_t received_hamming = 0u;
    uint8_t received_overall = 0u;
    uint8_t syndrome = 0u;
    uint8_t overall_error = 0u;
    uint64_t masked_data = 0u;

    if ((data == NULL) || (ecc == NULL) || (bounded_bits == 0u)) {
        return LLPS_SECDED_UNCORRECTABLE;
    }

    *data &= llps_secded_data_mask(bounded_bits);
    masked_data = *data;
    expected_ecc = llps_secded_encode_u64(masked_data, bounded_bits);
    received_hamming = (uint8_t)(*ecc & parity_mask);
    received_overall =
        (uint8_t)(((*ecc & LLPS_SECDED_OVERALL_BIT) != 0u) ? 1u : 0u);
    syndrome = (uint8_t)((expected_ecc ^ received_hamming) & parity_mask);
    overall_error =
        (uint8_t)(llps_secded_parity_u64(masked_data) ^
                  llps_secded_parity_u64(received_hamming) ^
                  received_overall);

    return llps_secded_apply_repair_u64(data,
                                        ecc,
                                        bounded_bits,
                                        total_positions,
                                        expected_ecc,
                                        syndrome,
                                        overall_error,
                                        masked_data);
}

uint8_t llps_secded_encode_u32(const uint32_t data) {
    return llps_secded_encode_u64((uint64_t)data, 32u);
}

bool llps_secded_is_valid_u32(const uint32_t data, const uint8_t ecc) {
    return llps_secded_is_valid_u64((uint64_t)data, 32u, ecc);
}

llps_secded_status_t llps_secded_repair_u32(uint32_t * const data,
                                            uint8_t * const ecc) {
    uint64_t wide = 0u;
    llps_secded_status_t status = LLPS_SECDED_UNCORRECTABLE;

    if (data == NULL) {
        return LLPS_SECDED_UNCORRECTABLE;
    }

    wide = (uint64_t)(*data);
    status = llps_secded_repair_u64(&wide, 32u, ecc);
    *data = (uint32_t)wide;
    return status;
}

uint8_t llps_secded_encode_u16(const uint16_t data) {
    return llps_secded_encode_u64((uint64_t)data, 16u);
}

bool llps_secded_is_valid_u16(const uint16_t data, const uint8_t ecc) {
    return llps_secded_is_valid_u64((uint64_t)data, 16u, ecc);
}

llps_secded_status_t llps_secded_repair_u16(uint16_t * const data,
                                            uint8_t * const ecc) {
    uint64_t wide = 0u;
    llps_secded_status_t status = LLPS_SECDED_UNCORRECTABLE;

    if (data == NULL) {
        return LLPS_SECDED_UNCORRECTABLE;
    }

    wide = (uint64_t)(*data);
    status = llps_secded_repair_u64(&wide, 16u, ecc);
    *data = (uint16_t)wide;
    return status;
}
