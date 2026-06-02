/**
 * @file src/internal/llps_control_flag.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_CONTROL_FLAG_H
#define LLPS_CONTROL_FLAG_H

#include <stdbool.h>
#include <stdint.h>

/** @brief One replicated bank for the process-wide shutdown request flag. */
typedef struct {
    uint32_t magic_start; /**< Bank-specific start canary. */
    uint32_t bank_id; /**< TMR bank index. */
    uint32_t shutdown_requested; /**< Encoded shutdown request boolean. */
    uint32_t shutdown_requested_inverse; /**< Inverse shutdown guard. */
    uint32_t crc; /**< CRC over the bank payload. */
    uint32_t crc_inverse; /**< Bitwise inverse of crc. */
    uint32_t magic_end; /**< Bank-specific end canary. */
} llps_control_flag_bank_t;

extern llps_control_flag_bank_t g_control_flag_bank0;
extern llps_control_flag_bank_t g_control_flag_bank1;
extern llps_control_flag_bank_t g_control_flag_bank2;

/** @brief Return true when an encoded shutdown flag is 0 or 1. */
bool llps_control_flag_value_is_valid(uint32_t value);
/** @brief Compute the CRC for one shutdown-flag TMR bank. */
uint32_t llps_control_flag_bank_compute_crc(
    const llps_control_flag_bank_t *bank);
/** @brief Validate canaries, inverse fields, and CRC for one bank. */
bool llps_control_flag_bank_is_valid(const llps_control_flag_bank_t *bank,
                                     uint32_t expected_bank_id);
/** @brief Populate one shutdown-flag bank from a canonical boolean value. */
void llps_control_flag_bank_from_value(llps_control_flag_bank_t *bank,
                                       uint32_t bank_id,
                                       bool shutdown_requested);
/** @brief Write the same shutdown request into all TMR banks. */
void llps_control_flag_write_all(bool shutdown_requested);
/** @brief Vote shutdown request banks and repair a single bad bank. */
bool llps_control_flag_reconcile(bool *out_shutdown_requested);
/** @brief Read the reconciled shutdown request, failing closed to true. */
bool llps_control_shutdown_is_requested(void);
/** @brief Set the shutdown request across all banks. */
void llps_control_request_shutdown(void);
/** @brief Clear the shutdown request across all banks. */
void llps_control_clear_shutdown(void);
/** @brief Exercise single-bank repair and fail-closed startup paths. */
bool llps_control_flag_tmr_startup_self_test(uint32_t *coverage);

#endif /* LLPS_CONTROL_FLAG_H */
