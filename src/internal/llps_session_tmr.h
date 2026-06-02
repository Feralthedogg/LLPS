/**
 * @file src/internal/llps_session_tmr.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_SESSION_TMR_H
#define LLPS_SESSION_TMR_H

#include "llps_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t session_id;
    llps_state_t state;
    uint64_t last_activity_ns;
    uint64_t request_no;
    int client_fd;
    int backend_fd;
    uint32_t close_reason;
    char client_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint16_t client_port;
    uint32_t c2s_payload_ecc_len;
    uint32_t s2c_payload_ecc_len;
    uint32_t session_crc;
} llps_session_tmr_snapshot_t;

typedef struct {
    uint32_t magic_start;
    uint32_t bank_id;
    uint32_t session_id;
    uint8_t session_id_secded;
    uint32_t session_id_inverse;
    uint8_t session_id_inverse_secded;
    uint32_t state;
    uint8_t state_secded;
    uint32_t state_inverse;
    uint8_t state_inverse_secded;
    uint64_t last_activity_ns;
    uint8_t last_activity_ns_secded;
    uint64_t last_activity_ns_inverse;
    uint8_t last_activity_ns_inverse_secded;
    uint64_t request_no;
    uint8_t request_no_secded;
    uint64_t request_no_inverse;
    uint8_t request_no_inverse_secded;
    uint32_t close_reason;
    uint8_t close_reason_secded;
    uint32_t close_reason_inverse;
    uint8_t close_reason_inverse_secded;
    uint32_t client_fd;
    uint8_t client_fd_secded;
    uint32_t client_fd_inverse;
    uint8_t client_fd_inverse_secded;
    uint32_t backend_fd;
    uint8_t backend_fd_secded;
    uint32_t backend_fd_inverse;
    uint8_t backend_fd_inverse_secded;
    uint8_t client_ip[LLPS_CLIENT_IP_TEXT_LEN];
    uint8_t client_ip_inverse[LLPS_CLIENT_IP_TEXT_LEN];
    uint32_t client_port;
    uint8_t client_port_secded;
    uint32_t client_port_inverse;
    uint8_t client_port_inverse_secded;
    uint32_t c2s_payload_ecc_len;
    uint8_t c2s_payload_ecc_len_secded;
    uint32_t c2s_payload_ecc_len_inverse;
    uint8_t c2s_payload_ecc_len_inverse_secded;
    uint32_t s2c_payload_ecc_len;
    uint8_t s2c_payload_ecc_len_secded;
    uint32_t s2c_payload_ecc_len_inverse;
    uint8_t s2c_payload_ecc_len_inverse_secded;
    uint32_t session_crc;
    uint8_t session_crc_secded;
    uint32_t session_crc_inverse;
    uint8_t session_crc_inverse_secded;
    uint32_t record_crc;
    uint32_t record_crc_inverse;
    uint32_t magic_end;
    uint8_t separation_pad[LLPS_SESSION_TMR_PAD_BYTES];
} llps_session_tmr_record_t;

typedef struct {
    uint32_t magic_start;
    uint32_t bank_id;
    uint32_t bank_id_inverse;
    uint32_t magic_start_inverse;
    uint8_t pre_guard_pad[LLPS_SESSION_TMR_REGION_PAD_BYTES];
    llps_session_tmr_record_t records[LLPS_MAX_CLIENTS];
    uint8_t post_guard_pad[LLPS_SESSION_TMR_REGION_PAD_BYTES];
    uint32_t magic_end_inverse;
    uint32_t bank_id_tail;
    uint32_t bank_id_tail_inverse;
    uint32_t magic_end;
} llps_session_tmr_region_t;

extern llps_session_tmr_region_t g_session_tmr_region0;
extern llps_session_tmr_region_t g_session_tmr_region1;
extern llps_session_tmr_region_t g_session_tmr_region2;

/** @brief Compute the deterministic guard byte for a TMR region pad. */
uint8_t llps_session_tmr_guard_byte(uint32_t bank_id,
                                    size_t offset,
                                    bool post_guard);
/** @brief Initialize one session TMR region and its guard pads. */
void llps_session_tmr_init_region(uint32_t bank_id);
/** @brief Validate one session TMR region's canaries and guard pads. */
bool llps_session_tmr_region_guard_is_valid(uint32_t bank_id);
/** @brief Return a raw session TMR record pointer without guard validation. */
llps_session_tmr_record_t *llps_session_tmr_record_raw_ref(
    uint32_t bank_id,
    uint32_t session_id);
/** @brief Return a writable session TMR record after region validation. */
llps_session_tmr_record_t *llps_session_tmr_record_ref(uint32_t bank_id,
                                                       uint32_t session_id);
/** @brief Return a read-only session TMR record after region validation. */
const llps_session_tmr_record_t *llps_session_tmr_record_cref(
    uint32_t bank_id,
    uint32_t session_id);
/** @brief Compute the CRC for one session TMR record. */
uint32_t llps_session_tmr_record_compute_crc(
    const llps_session_tmr_record_t *rec);
/** @brief Compare two session TMR snapshots for exact equality. */
bool llps_session_tmr_snapshot_equal(const llps_session_tmr_snapshot_t *lhs,
                                     const llps_session_tmr_snapshot_t *rhs);
/** @brief Validate one session TMR record against its expected bank and slot. */
bool llps_session_tmr_record_is_valid(const llps_session_tmr_record_t *rec,
                                      uint32_t expected_bank_id,
                                      uint32_t expected_session_id);
/** @brief Copy a validated record into a canonical session snapshot. */
void llps_session_tmr_record_to_snapshot(
    const llps_session_tmr_record_t *rec,
    llps_session_tmr_snapshot_t *out_snapshot);
/** @brief Populate one record from a canonical session snapshot. */
void llps_session_tmr_record_from_snapshot(
    llps_session_tmr_record_t *rec,
    uint32_t bank_id,
    const llps_session_tmr_snapshot_t *snapshot);
/** @brief Write a canonical session snapshot into all TMR banks. */
void llps_session_tmr_write_all(const llps_session_tmr_snapshot_t *snapshot);
/** @brief Vote session TMR banks and repair a single divergent record. */
bool llps_session_tmr_vote(uint32_t session_id,
                           uint32_t max_clients,
                           llps_session_tmr_snapshot_t *out_snapshot);
/** @brief Exercise session TMR repair and fail-closed startup paths. */
bool llps_session_tmr_startup_self_test(uint32_t max_clients,
                                        uint32_t *coverage);

#endif /* LLPS_SESSION_TMR_H */
