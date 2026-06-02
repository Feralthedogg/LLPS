/**
 * @file src/session/llps_session_integrity.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_session_integrity.h"

#include "llps_config.h"
#include "llps_crc.h"
#include "llps_safety_counters.h"
#include "llps_secded.h"

#include <stdbool.h>
#include <stdint.h>

uint32_t llps_state_inverse_value(const llps_state_t state) {
    return ~((uint32_t)state);
}

bool llps_state_is_valid(const llps_state_t state) {
    return (state == ST_FREE) || (state == ST_ACTIVE);
}

uint32_t llps_magic_for_state(const llps_state_t state) {
    if (state == ST_ACTIVE) {
        return LLPS_SESSION_MAGIC_ACTIVE;
    }

    return LLPS_SESSION_MAGIC_FREE;
}

uint32_t llps_encode_fd(const int fd) {
    return (uint32_t)(int32_t)fd;
}

int llps_decode_fd(const uint32_t fd) {
    return (int)(int32_t)fd;
}

bool llps_close_reason_is_valid(const uint32_t reason) {
    return reason < (uint32_t)LLPS_CLOSE_REASON_COUNT;
}

const char *llps_close_reason_text(const uint32_t reason) {
    switch ((llps_close_reason_t)reason) {
    case LLPS_CLOSE_REASON_NORMAL:
        return "closed";
    case LLPS_CLOSE_REASON_IDLE_TIMEOUT:
        return "idle_timeout";
    case LLPS_CLOSE_REASON_PAYLOAD_ECC:
        return "payload_ecc";
    case LLPS_CLOSE_REASON_METADATA_FAULT:
        return "metadata_fault";
    case LLPS_CLOSE_REASON_CONTRACT_VIOLATION:
        return "contract_violation";
    case LLPS_CLOSE_REASON_CLIENT_PREFACE_TIMEOUT:
        return "client_preface_timeout";
    case LLPS_CLOSE_REASON_PROTOCOL_HANDSHAKE:
        return "protocol_handshake_invalid";
    default:
        return "unknown";
    }
}

bool llps_session_state_pair_is_valid(const llps_session_t * const sess) {
    if (sess == NULL) {
        return false;
    }

    return llps_state_is_valid(sess->state) &&
           (sess->state_inverse == llps_state_inverse_value(sess->state));
}

static uint32_t llps_session_crc_metadata(
    uint32_t crc,
    const llps_session_t * const sess) {
    crc = llps_crc32_update_u32(crc, sess->magic_start);
    crc = llps_crc32_update_u32(crc, sess->session_id);
    crc = llps_crc32_update_byte(crc, sess->session_id_secded);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->state);
    crc = llps_crc32_update_byte(crc, sess->state_secded);
    crc = llps_crc32_update_u32(crc, sess->state_inverse);
    crc = llps_crc32_update_byte(crc, sess->state_inverse_secded);
    crc = llps_crc32_update_u64(crc, sess->last_activity_ns);
    crc = llps_crc32_update_byte(crc, sess->last_activity_ns_secded);
    crc = llps_crc32_update_u64(crc, sess->request_no);
    crc = llps_crc32_update_byte(crc, sess->request_no_secded);
    crc = llps_crc32_update_u64(crc, sess->request_no_inverse);
    crc = llps_crc32_update_byte(crc, sess->request_no_inverse_secded);
    crc = llps_crc32_update_u32(crc, sess->close_reason);
    crc = llps_crc32_update_byte(crc, sess->close_reason_secded);
    crc = llps_crc32_update_u32(crc, sess->close_reason_inverse);
    crc = llps_crc32_update_byte(crc,
                                 sess->close_reason_inverse_secded);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->client_fd);
    crc = llps_crc32_update_byte(crc, sess->client_fd_secded);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->backend_fd);
    crc = llps_crc32_update_byte(crc, sess->backend_fd_secded);
    crc = llps_crc32_update_cstr_bounded(crc,
                                         sess->client_ip,
                                         sizeof(sess->client_ip));
    crc = llps_crc32_update_u32(crc, sess->client_port);
    crc = llps_crc32_update_byte(crc, sess->client_port_secded);
    crc = llps_crc32_update_u32(crc, sess->client_port_inverse);
    crc = llps_crc32_update_byte(crc, sess->client_port_inverse_secded);
    crc = llps_crc32_update_u32(crc, sess->c2s_payload_ecc_len);
    crc = llps_crc32_update_byte(crc, sess->c2s_payload_ecc_len_secded);
    crc = llps_crc32_update_u32(crc, sess->c2s_payload_ecc_len_inverse);
    crc = llps_crc32_update_byte(crc,
                                 sess->c2s_payload_ecc_len_inverse_secded);
    crc = llps_crc32_update_u32(crc, sess->s2c_payload_ecc_len);
    crc = llps_crc32_update_byte(crc, sess->s2c_payload_ecc_len_secded);
    crc = llps_crc32_update_u32(crc, sess->s2c_payload_ecc_len_inverse);
    crc = llps_crc32_update_byte(crc,
                                 sess->s2c_payload_ecc_len_inverse_secded);
    return crc;
}

static uint32_t llps_session_crc_pumps(
    uint32_t crc,
    const llps_session_t * const sess) {
    crc = llps_crc32_update_ptr(crc, sess->pump_c2s.session);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_c2s.src_fd);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_c2s.dst_fd);
    crc = llps_crc32_update_ptr(crc, sess->pump_c2s.buf);
    crc = llps_crc32_update_size(crc, sess->pump_c2s.buf_len);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_c2s.direction);

    crc = llps_crc32_update_ptr(crc, sess->pump_s2c.session);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_s2c.src_fd);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_s2c.dst_fd);
    crc = llps_crc32_update_ptr(crc, sess->pump_s2c.buf);
    crc = llps_crc32_update_size(crc, sess->pump_s2c.buf_len);
    crc = llps_crc32_update_u32(crc, (uint32_t)sess->pump_s2c.direction);
    return crc;
}

uint32_t llps_session_compute_crc(const llps_session_t * const sess) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (sess == NULL) {
        return 0u;
    }

    crc = llps_session_crc_metadata(crc, sess);
    crc = llps_session_crc_pumps(crc, sess);
    crc = llps_crc32_update_u32(crc, sess->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

void llps_session_refresh_secded(llps_session_t * const sess) {
    if (sess != NULL) {
        sess->session_id_secded = llps_secded_encode_u32(sess->session_id);
        sess->state_secded = llps_secded_encode_u32((uint32_t)sess->state);
        sess->state_inverse_secded =
            llps_secded_encode_u32(sess->state_inverse);
        sess->last_activity_ns_secded =
            llps_secded_encode_u64(sess->last_activity_ns, 64u);
        sess->request_no_secded =
            llps_secded_encode_u64(sess->request_no, 64u);
        sess->request_no_inverse_secded =
            llps_secded_encode_u64(sess->request_no_inverse, 64u);
        sess->close_reason_secded =
            llps_secded_encode_u32(sess->close_reason);
        sess->close_reason_inverse_secded =
            llps_secded_encode_u32(sess->close_reason_inverse);
        sess->client_fd_secded =
            llps_secded_encode_u32((uint32_t)sess->client_fd);
        sess->backend_fd_secded =
            llps_secded_encode_u32((uint32_t)sess->backend_fd);
        sess->client_port_secded =
            llps_secded_encode_u16(sess->client_port);
        sess->client_port_inverse_secded =
            llps_secded_encode_u32(sess->client_port_inverse);
        sess->c2s_payload_ecc_len_secded =
            llps_secded_encode_u32(sess->c2s_payload_ecc_len);
        sess->c2s_payload_ecc_len_inverse_secded =
            llps_secded_encode_u32(sess->c2s_payload_ecc_len_inverse);
        sess->s2c_payload_ecc_len_secded =
            llps_secded_encode_u32(sess->s2c_payload_ecc_len);
        sess->s2c_payload_ecc_len_inverse_secded =
            llps_secded_encode_u32(sess->s2c_payload_ecc_len_inverse);
    }
}

bool llps_session_secded_is_valid(const llps_session_t * const sess) {
    if (sess == NULL) {
        return false;
    }

    return llps_secded_is_valid_u32(sess->session_id,
                                    sess->session_id_secded) &&
           llps_secded_is_valid_u32((uint32_t)sess->state,
                                    sess->state_secded) &&
           llps_secded_is_valid_u32(sess->state_inverse,
                                    sess->state_inverse_secded) &&
           llps_secded_is_valid_u64(sess->last_activity_ns,
                                    64u,
                                    sess->last_activity_ns_secded) &&
           llps_secded_is_valid_u64(sess->request_no,
                                    64u,
                                    sess->request_no_secded) &&
           llps_secded_is_valid_u64(sess->request_no_inverse,
                                    64u,
                                    sess->request_no_inverse_secded) &&
           llps_secded_is_valid_u32(sess->close_reason,
                                    sess->close_reason_secded) &&
           llps_secded_is_valid_u32(sess->close_reason_inverse,
                                    sess->close_reason_inverse_secded) &&
           llps_secded_is_valid_u32((uint32_t)sess->client_fd,
                                    sess->client_fd_secded) &&
           llps_secded_is_valid_u32((uint32_t)sess->backend_fd,
                                    sess->backend_fd_secded) &&
           llps_secded_is_valid_u16(sess->client_port,
                                    sess->client_port_secded) &&
           llps_secded_is_valid_u32(sess->client_port_inverse,
                                    sess->client_port_inverse_secded) &&
           llps_secded_is_valid_u32(sess->c2s_payload_ecc_len,
                                    sess->c2s_payload_ecc_len_secded) &&
           llps_secded_is_valid_u32(
               sess->c2s_payload_ecc_len_inverse,
               sess->c2s_payload_ecc_len_inverse_secded) &&
           llps_secded_is_valid_u32(sess->s2c_payload_ecc_len,
                                    sess->s2c_payload_ecc_len_secded) &&
           llps_secded_is_valid_u32(
               sess->s2c_payload_ecc_len_inverse,
               sess->s2c_payload_ecc_len_inverse_secded);
}

static bool llps_session_repair_status_ok(
    const llps_secded_status_t status) {
    if (status == LLPS_SECDED_CORRECTED) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(secded_single_bit_repairs);
        return true;
    }

    if (status == LLPS_SECDED_UNCORRECTABLE) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(secded_double_bit_failures);
        LLPS_MEMORY_SAFETY_COUNTER_INC(readiness_runtime_ecc_failures);
        return false;
    }

    return true;
}

static bool llps_session_repair_identity_secded(llps_session_t * const sess) {
    uint32_t word32 = 0u;
    bool ok = true;

    if (sess == NULL) {
        return false;
    }

    word32 = sess->session_id;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->session_id_secded)) && ok;
    sess->session_id = word32;

    word32 = (uint32_t)sess->state;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->state_secded)) && ok;
    sess->state = (llps_state_t)word32;

    word32 = sess->state_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->state_inverse_secded)) && ok;
    sess->state_inverse = word32;

    return ok;
}

static bool llps_session_repair_activity_secded(llps_session_t * const sess) {
    uint64_t word64 = 0u;
    uint32_t word32 = 0u;
    bool ok = true;

    if (sess == NULL) {
        return false;
    }

    word64 = sess->last_activity_ns;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u64(&word64, 64u, &sess->last_activity_ns_secded)) &&
        ok;
    sess->last_activity_ns = word64;

    word64 = sess->request_no;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u64(&word64, 64u, &sess->request_no_secded)) && ok;
    sess->request_no = word64;

    word64 = sess->request_no_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u64(&word64,
                               64u,
                               &sess->request_no_inverse_secded)) && ok;
    sess->request_no_inverse = word64;

    word32 = sess->close_reason;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->close_reason_secded)) && ok;
    sess->close_reason = word32;

    word32 = sess->close_reason_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32,
                               &sess->close_reason_inverse_secded)) && ok;
    sess->close_reason_inverse = word32;

    return ok;
}

static bool llps_session_repair_fd_port_secded(llps_session_t * const sess) {
    uint32_t word32 = 0u;
    uint16_t word16 = 0u;
    bool ok = true;

    if (sess == NULL) {
        return false;
    }

    word32 = (uint32_t)sess->client_fd;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->client_fd_secded)) && ok;
    sess->client_fd = llps_decode_fd(word32);

    word32 = (uint32_t)sess->backend_fd;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->backend_fd_secded)) && ok;
    sess->backend_fd = llps_decode_fd(word32);

    word16 = sess->client_port;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u16(&word16, &sess->client_port_secded)) && ok;
    sess->client_port = word16;

    word32 = sess->client_port_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(&word32, &sess->client_port_inverse_secded)) &&
        ok;
    sess->client_port_inverse = word32;

    return ok;
}

static bool llps_session_repair_payload_secded(llps_session_t * const sess) {
    uint32_t word32 = 0u;
    bool ok = true;

    if (sess == NULL) {
        return false;
    }

    word32 = sess->c2s_payload_ecc_len;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(
            &word32,
            &sess->c2s_payload_ecc_len_secded)) && ok;
    sess->c2s_payload_ecc_len = word32;

    word32 = sess->c2s_payload_ecc_len_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(
            &word32,
            &sess->c2s_payload_ecc_len_inverse_secded)) && ok;
    sess->c2s_payload_ecc_len_inverse = word32;

    word32 = sess->s2c_payload_ecc_len;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(
            &word32,
            &sess->s2c_payload_ecc_len_secded)) && ok;
    sess->s2c_payload_ecc_len = word32;

    word32 = sess->s2c_payload_ecc_len_inverse;
    ok = llps_session_repair_status_ok(
        llps_secded_repair_u32(
            &word32,
            &sess->s2c_payload_ecc_len_inverse_secded)) && ok;
    sess->s2c_payload_ecc_len_inverse = word32;

    return ok;
}

bool llps_session_repair_secded(llps_session_t * const sess) {
    bool ok = true;

    if (sess == NULL) {
        return false;
    }

    ok = llps_session_repair_identity_secded(sess) && ok;
    ok = llps_session_repair_activity_secded(sess) && ok;
    ok = llps_session_repair_fd_port_secded(sess) && ok;
    ok = llps_session_repair_payload_secded(sess) && ok;
    return ok;
}

bool llps_session_local_integrity_is_valid(
    const llps_session_t * const sess) {
    uint32_t expected_magic = 0u;

    if ((sess == NULL) ||
        !llps_session_secded_is_valid(sess) ||
        !llps_session_state_pair_is_valid(sess)) {
        return false;
    }

    expected_magic = llps_magic_for_state(sess->state);
    if ((sess->magic_start != expected_magic) ||
        (sess->magic_end != expected_magic) ||
        (sess->request_no_inverse != ~sess->request_no) ||
        !llps_close_reason_is_valid(sess->close_reason) ||
        (sess->close_reason_inverse != ~sess->close_reason) ||
        (sess->client_port_inverse != ~((uint32_t)sess->client_port)) ||
        (sess->c2s_payload_ecc_len > LLPS_BUFFER_SIZE) ||
        (sess->s2c_payload_ecc_len > LLPS_BUFFER_SIZE) ||
        (sess->c2s_payload_ecc_len_inverse !=
         ~sess->c2s_payload_ecc_len) ||
        (sess->s2c_payload_ecc_len_inverse !=
         ~sess->s2c_payload_ecc_len)) {
        return false;
    }

    return (sess->integrity_crc_inverse == ~sess->integrity_crc) &&
           (sess->integrity_crc == llps_session_compute_crc(sess));
}

void llps_reset_pump_args(llps_pump_args_t * const pump) {
    if (pump != NULL) {
        pump->session = NULL;
        pump->src_fd = LLPS_INVALID_FD;
        pump->dst_fd = LLPS_INVALID_FD;
        pump->buf = NULL;
        pump->buf_len = 0u;
        pump->direction = LLPS_DIR_C2S;
    }
}

void llps_session_set_state_fields(llps_session_t * const sess,
                                   const llps_state_t state) {
    if (sess != NULL) {
        const uint32_t magic = llps_magic_for_state(state);
        sess->magic_start = magic;
        sess->state = state;
        sess->state_inverse = llps_state_inverse_value(state);
        sess->magic_end = magic;
    }
}

bool llps_direction_is_valid(const llps_direction_t dir) {
    return (dir == LLPS_DIR_C2S) || (dir == LLPS_DIR_S2C);
}

const char *llps_direction_text(const llps_direction_t dir) {
    if (dir == LLPS_DIR_C2S) {
        return "c2s";
    }

    if (dir == LLPS_DIR_S2C) {
        return "s2c";
    }

    return "unknown";
}
