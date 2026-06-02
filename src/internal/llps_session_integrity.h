/**
 * @file src/internal/llps_session_integrity.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_SESSION_INTEGRITY_H
#define LLPS_SESSION_INTEGRITY_H

#include "llps_internal.h"

#include <stdbool.h>
#include <stdint.h>

/** @brief Encode the inverse word expected for a session state. */
uint32_t llps_state_inverse_value(llps_state_t state);
/** @brief Return true when a session state enum value is recognized. */
bool llps_state_is_valid(llps_state_t state);
/** @brief Return the active/free canary expected for a state. */
uint32_t llps_magic_for_state(llps_state_t state);
/** @brief Encode a signed descriptor into CRC-friendly unsigned form. */
uint32_t llps_encode_fd(int fd);
/** @brief Decode a descriptor encoded by ::llps_encode_fd. */
int llps_decode_fd(uint32_t fd);
/** @brief Return true when a close-reason enum value is recognized. */
bool llps_close_reason_is_valid(uint32_t reason);
/** @brief Return a stable audit token for a close reason. */
const char *llps_close_reason_text(uint32_t reason);
/** @brief Validate the state and state-inverse pair of a session. */
bool llps_session_state_pair_is_valid(const llps_session_t *sess);
/** @brief Compute the local session metadata CRC. */
uint32_t llps_session_compute_crc(const llps_session_t *sess);
/** @brief Validate local canaries, inverse fields, and CRC. */
bool llps_session_local_integrity_is_valid(const llps_session_t *sess);
/** @brief Recompute SECDED codes for local session metadata words. */
void llps_session_refresh_secded(llps_session_t *sess);
/** @brief Validate local session SECDED codes without mutating the session. */
bool llps_session_secded_is_valid(const llps_session_t *sess);
/** @brief Repair one-bit local session metadata faults where possible. */
bool llps_session_repair_secded(llps_session_t *sess);
/** @brief Clear pump arguments to an invalid but deterministic state. */
void llps_reset_pump_args(llps_pump_args_t *pump);
/** @brief Set session state and its inverse field together. */
void llps_session_set_state_fields(llps_session_t *sess, llps_state_t state);
/** @brief Return true when a pump direction enum value is recognized. */
bool llps_direction_is_valid(llps_direction_t dir);
/** @brief Return a stable diagnostic string for a pump direction. */
const char *llps_direction_text(llps_direction_t dir);

#endif /* LLPS_SESSION_INTEGRITY_H */
