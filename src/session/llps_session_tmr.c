/**
 * @file src/session/llps_session_tmr.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_session_tmr.h"

#include "llps_crc.h"
#include "llps_safety_counters.h"
#include "llps_secded.h"
#include "llps_session_integrity.h"
#include "llps_tmr_vote.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK0)
LLPS_USED
llps_session_tmr_region_t g_session_tmr_region0;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK1)
LLPS_USED
llps_session_tmr_region_t g_session_tmr_region1;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK2)
LLPS_USED
llps_session_tmr_region_t g_session_tmr_region2;

static llps_session_tmr_region_t *llps_session_tmr_region_ref(
    const uint32_t bank_id) {
    static llps_session_tmr_region_t *
        const regions[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_session_tmr_region0,
        &g_session_tmr_region1,
        &g_session_tmr_region2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? regions[bank_id] : NULL;
}

static const llps_session_tmr_region_t *llps_session_tmr_region_cref(
    const uint32_t bank_id) {
    static const llps_session_tmr_region_t *
        const regions[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_session_tmr_region0,
        &g_session_tmr_region1,
        &g_session_tmr_region2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? regions[bank_id] : NULL;
}

static uint32_t llps_session_tmr_region_head_magic_for_bank(
    const uint32_t bank_id) {
    return LLPS_SESSION_TMR_REGION_MAGIC_HEAD ^ (0x01010101u * (bank_id + 1u));
}

static uint32_t llps_session_tmr_region_tail_magic_for_bank(
    const uint32_t bank_id) {
    return LLPS_SESSION_TMR_REGION_MAGIC_TAIL ^ (0x10101010u * (bank_id + 1u));
}

uint8_t llps_session_tmr_guard_byte(const uint32_t bank_id,
                                    const size_t offset,
                                    const bool post_guard) {
    uint32_t value = (uint32_t)offset;

    value ^= (value >> 8u);
    value ^= (value >> 16u);
    value ^= (bank_id + 1u) * 0x3Du;
    value ^= post_guard ? LLPS_SESSION_TMR_GUARD_POST_SALT :
                          LLPS_SESSION_TMR_GUARD_PRE_SALT;

    return (uint8_t)(value & 0xFFu);
}

static void llps_session_tmr_fill_guard_pad(uint8_t * const pad,
                                            const size_t len,
                                            const uint32_t bank_id,
                                            const bool post_guard) {
    if (pad != NULL) {
        for (size_t i = 0u; i < len; ++i) {
            pad[i] = llps_session_tmr_guard_byte(bank_id, i, post_guard);
        }
    }
}

static bool llps_session_tmr_guard_pad_is_valid(const uint8_t * const pad,
                                                const size_t len,
                                                const uint32_t bank_id,
                                                const bool post_guard) {
    if (pad == NULL) {
        return false;
    }

    for (size_t i = 0u; i < len; ++i) {
        if (pad[i] != llps_session_tmr_guard_byte(bank_id, i, post_guard)) {
            return false;
        }
    }

    return true;
}

void llps_session_tmr_init_region(const uint32_t bank_id) {
    llps_session_tmr_region_t * const region =
        llps_session_tmr_region_ref(bank_id);
    const uint32_t head_magic =
        llps_session_tmr_region_head_magic_for_bank(bank_id);
    const uint32_t tail_magic =
        llps_session_tmr_region_tail_magic_for_bank(bank_id);

    if (region == NULL) {
        LLPS_EXPECT(false, return);
    }

    region->magic_start = head_magic;
    region->bank_id = bank_id;
    region->bank_id_inverse = ~bank_id;
    region->magic_start_inverse = ~head_magic;
    llps_session_tmr_fill_guard_pad(region->pre_guard_pad,
                                    sizeof(region->pre_guard_pad),
                                    bank_id,
                                    false);
    llps_session_tmr_fill_guard_pad(region->post_guard_pad,
                                    sizeof(region->post_guard_pad),
                                    bank_id,
                                    true);
    region->magic_end_inverse = ~tail_magic;
    region->bank_id_tail = bank_id;
    region->bank_id_tail_inverse = ~bank_id;
    region->magic_end = tail_magic;
}

static void llps_session_tmr_restore_region_guard(const uint32_t bank_id) {
    llps_session_tmr_init_region(bank_id);
    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_region_guard_faults);
}

bool llps_session_tmr_region_guard_is_valid(const uint32_t bank_id) {
    const llps_session_tmr_region_t * const region =
        llps_session_tmr_region_cref(bank_id);
    const uint32_t head_magic =
        llps_session_tmr_region_head_magic_for_bank(bank_id);
    const uint32_t tail_magic =
        llps_session_tmr_region_tail_magic_for_bank(bank_id);

    if (region == NULL) {
        return false;
    }

    return (region->magic_start == head_magic) &&
           (region->magic_start_inverse == ~head_magic) &&
           (region->bank_id == bank_id) &&
           (region->bank_id_inverse == ~bank_id) &&
           llps_session_tmr_guard_pad_is_valid(region->pre_guard_pad,
                                               sizeof(region->pre_guard_pad),
                                               bank_id,
                                               false) &&
           llps_session_tmr_guard_pad_is_valid(region->post_guard_pad,
                                               sizeof(region->post_guard_pad),
                                               bank_id,
                                               true) &&
           (region->magic_end == tail_magic) &&
           (region->magic_end_inverse == ~tail_magic) &&
           (region->bank_id_tail == bank_id) &&
           (region->bank_id_tail_inverse == ~bank_id);
}

llps_session_tmr_record_t *llps_session_tmr_record_raw_ref(
    const uint32_t bank_id,
    const uint32_t session_id) {
    llps_session_tmr_region_t * const region =
        llps_session_tmr_region_ref(bank_id);

    if ((region == NULL) || (session_id >= LLPS_MAX_CLIENTS)) {
        return NULL;
    }

    return &region->records[session_id];
}

llps_session_tmr_record_t *llps_session_tmr_record_ref(
    const uint32_t bank_id,
    const uint32_t session_id) {
    llps_session_tmr_region_t * const region =
        llps_session_tmr_region_ref(bank_id);

    if (session_id >= LLPS_MAX_CLIENTS) {
        return NULL;
    }

    if ((region == NULL) ||
        !llps_session_tmr_region_guard_is_valid(bank_id)) {
        return NULL;
    }

    return &region->records[session_id];
}

const llps_session_tmr_record_t *llps_session_tmr_record_cref(
    const uint32_t bank_id,
    const uint32_t session_id) {
    const llps_session_tmr_region_t * const region =
        llps_session_tmr_region_cref(bank_id);

    if (session_id >= LLPS_MAX_CLIENTS) {
        return NULL;
    }

    if ((region == NULL) ||
        !llps_session_tmr_region_guard_is_valid(bank_id)) {
        return NULL;
    }

    return &region->records[session_id];
}

static uint32_t llps_session_tmr_magic_for_bank(const uint32_t bank_id) {
    return LLPS_SESSION_TMR_RECORD_MAGIC ^ (0x11111111u * (bank_id + 1u));
}

static uint32_t llps_session_tmr_record_crc_identity(
    uint32_t crc,
    const llps_session_tmr_record_t * const rec) {
    crc = llps_crc32_update_u32(crc, rec->magic_start);
    crc = llps_crc32_update_u32(crc, rec->bank_id);
    crc = llps_crc32_update_u32(crc, rec->session_id);
    crc = llps_crc32_update_byte(crc, rec->session_id_secded);
    crc = llps_crc32_update_u32(crc, rec->session_id_inverse);
    crc = llps_crc32_update_byte(crc, rec->session_id_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->state);
    crc = llps_crc32_update_byte(crc, rec->state_secded);
    crc = llps_crc32_update_u32(crc, rec->state_inverse);
    crc = llps_crc32_update_byte(crc, rec->state_inverse_secded);
    crc = llps_crc32_update_u64(crc, rec->last_activity_ns);
    crc = llps_crc32_update_byte(crc, rec->last_activity_ns_secded);
    crc = llps_crc32_update_u64(crc, rec->last_activity_ns_inverse);
    crc = llps_crc32_update_byte(crc, rec->last_activity_ns_inverse_secded);
    return crc;
}

static uint32_t llps_session_tmr_record_crc_request(
    uint32_t crc,
    const llps_session_tmr_record_t * const rec) {
    crc = llps_crc32_update_u64(crc, rec->request_no);
    crc = llps_crc32_update_byte(crc, rec->request_no_secded);
    crc = llps_crc32_update_u64(crc, rec->request_no_inverse);
    crc = llps_crc32_update_byte(crc, rec->request_no_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->close_reason);
    crc = llps_crc32_update_byte(crc, rec->close_reason_secded);
    crc = llps_crc32_update_u32(crc, rec->close_reason_inverse);
    crc = llps_crc32_update_byte(crc, rec->close_reason_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->client_fd);
    crc = llps_crc32_update_byte(crc, rec->client_fd_secded);
    crc = llps_crc32_update_u32(crc, rec->client_fd_inverse);
    crc = llps_crc32_update_byte(crc, rec->client_fd_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->backend_fd);
    crc = llps_crc32_update_byte(crc, rec->backend_fd_secded);
    crc = llps_crc32_update_u32(crc, rec->backend_fd_inverse);
    crc = llps_crc32_update_byte(crc, rec->backend_fd_inverse_secded);
    return crc;
}

static uint32_t llps_session_tmr_record_crc_client(
    uint32_t crc,
    const llps_session_tmr_record_t * const rec) {
    for (size_t i = 0u; i < sizeof(rec->client_ip); ++i) {
        crc = llps_crc32_update_byte(crc, rec->client_ip[i]);
    }
    for (size_t i = 0u; i < sizeof(rec->client_ip_inverse); ++i) {
        crc = llps_crc32_update_byte(crc, rec->client_ip_inverse[i]);
    }
    crc = llps_crc32_update_u32(crc, rec->client_port);
    crc = llps_crc32_update_byte(crc, rec->client_port_secded);
    crc = llps_crc32_update_u32(crc, rec->client_port_inverse);
    crc = llps_crc32_update_byte(crc, rec->client_port_inverse_secded);
    return crc;
}

static uint32_t llps_session_tmr_record_crc_payload(
    uint32_t crc,
    const llps_session_tmr_record_t * const rec) {
    crc = llps_crc32_update_u32(crc, rec->c2s_payload_ecc_len);
    crc = llps_crc32_update_byte(crc, rec->c2s_payload_ecc_len_secded);
    crc = llps_crc32_update_u32(crc, rec->c2s_payload_ecc_len_inverse);
    crc = llps_crc32_update_byte(
        crc,
        rec->c2s_payload_ecc_len_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->s2c_payload_ecc_len);
    crc = llps_crc32_update_byte(crc, rec->s2c_payload_ecc_len_secded);
    crc = llps_crc32_update_u32(crc, rec->s2c_payload_ecc_len_inverse);
    crc = llps_crc32_update_byte(
        crc,
        rec->s2c_payload_ecc_len_inverse_secded);
    crc = llps_crc32_update_u32(crc, rec->session_crc);
    crc = llps_crc32_update_byte(crc, rec->session_crc_secded);
    crc = llps_crc32_update_u32(crc, rec->session_crc_inverse);
    crc = llps_crc32_update_byte(crc, rec->session_crc_inverse_secded);
    return crc;
}

uint32_t llps_session_tmr_record_compute_crc(
    const llps_session_tmr_record_t * const rec) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (rec == NULL) {
        return 0u;
    }

    crc = llps_session_tmr_record_crc_identity(crc, rec);
    crc = llps_session_tmr_record_crc_request(crc, rec);
    crc = llps_session_tmr_record_crc_client(crc, rec);
    crc = llps_session_tmr_record_crc_payload(crc, rec);
    crc = llps_crc32_update_u32(crc, rec->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

bool llps_session_tmr_snapshot_equal(
    const llps_session_tmr_snapshot_t * const lhs,
    const llps_session_tmr_snapshot_t * const rhs) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    return (lhs->session_id == rhs->session_id) &&
           (lhs->state == rhs->state) &&
           (lhs->last_activity_ns == rhs->last_activity_ns) &&
           (lhs->request_no == rhs->request_no) &&
           (lhs->client_fd == rhs->client_fd) &&
           (lhs->backend_fd == rhs->backend_fd) &&
           (lhs->close_reason == rhs->close_reason) &&
           (lhs->client_port == rhs->client_port) &&
           (lhs->c2s_payload_ecc_len == rhs->c2s_payload_ecc_len) &&
           (lhs->s2c_payload_ecc_len == rhs->s2c_payload_ecc_len) &&
           (memcmp(lhs->client_ip,
                   rhs->client_ip,
                   sizeof(lhs->client_ip)) == 0) &&
           (lhs->session_crc == rhs->session_crc);
}

static void llps_session_tmr_record_refresh_secded(
    llps_session_tmr_record_t * const rec) {
    if (rec != NULL) {
        rec->session_id_secded = llps_secded_encode_u32(rec->session_id);
        rec->session_id_inverse_secded =
            llps_secded_encode_u32(rec->session_id_inverse);
        rec->state_secded = llps_secded_encode_u32(rec->state);
        rec->state_inverse_secded =
            llps_secded_encode_u32(rec->state_inverse);
        rec->last_activity_ns_secded =
            llps_secded_encode_u64(rec->last_activity_ns, 64u);
        rec->last_activity_ns_inverse_secded =
            llps_secded_encode_u64(rec->last_activity_ns_inverse, 64u);
        rec->request_no_secded =
            llps_secded_encode_u64(rec->request_no, 64u);
        rec->request_no_inverse_secded =
            llps_secded_encode_u64(rec->request_no_inverse, 64u);
        rec->close_reason_secded =
            llps_secded_encode_u32(rec->close_reason);
        rec->close_reason_inverse_secded =
            llps_secded_encode_u32(rec->close_reason_inverse);
        rec->client_fd_secded = llps_secded_encode_u32(rec->client_fd);
        rec->client_fd_inverse_secded =
            llps_secded_encode_u32(rec->client_fd_inverse);
        rec->backend_fd_secded = llps_secded_encode_u32(rec->backend_fd);
        rec->backend_fd_inverse_secded =
            llps_secded_encode_u32(rec->backend_fd_inverse);
        rec->client_port_secded = llps_secded_encode_u32(rec->client_port);
        rec->client_port_inverse_secded =
            llps_secded_encode_u32(rec->client_port_inverse);
        rec->c2s_payload_ecc_len_secded =
            llps_secded_encode_u32(rec->c2s_payload_ecc_len);
        rec->c2s_payload_ecc_len_inverse_secded =
            llps_secded_encode_u32(rec->c2s_payload_ecc_len_inverse);
        rec->s2c_payload_ecc_len_secded =
            llps_secded_encode_u32(rec->s2c_payload_ecc_len);
        rec->s2c_payload_ecc_len_inverse_secded =
            llps_secded_encode_u32(rec->s2c_payload_ecc_len_inverse);
        rec->session_crc_secded = llps_secded_encode_u32(rec->session_crc);
        rec->session_crc_inverse_secded =
            llps_secded_encode_u32(rec->session_crc_inverse);
    }
}

static bool llps_session_tmr_record_secded_is_valid(
    const llps_session_tmr_record_t * const rec) {
    if (rec == NULL) {
        return false;
    }

    return llps_secded_is_valid_u32(rec->session_id,
                                    rec->session_id_secded) &&
           llps_secded_is_valid_u32(rec->session_id_inverse,
                                    rec->session_id_inverse_secded) &&
           llps_secded_is_valid_u32(rec->state, rec->state_secded) &&
           llps_secded_is_valid_u32(rec->state_inverse,
                                    rec->state_inverse_secded) &&
           llps_secded_is_valid_u64(rec->last_activity_ns,
                                    64u,
                                    rec->last_activity_ns_secded) &&
           llps_secded_is_valid_u64(rec->last_activity_ns_inverse,
                                    64u,
                                    rec->last_activity_ns_inverse_secded) &&
           llps_secded_is_valid_u64(rec->request_no,
                                    64u,
                                    rec->request_no_secded) &&
           llps_secded_is_valid_u64(rec->request_no_inverse,
                                    64u,
                                    rec->request_no_inverse_secded) &&
           llps_secded_is_valid_u32(rec->close_reason,
                                    rec->close_reason_secded) &&
           llps_secded_is_valid_u32(rec->close_reason_inverse,
                                    rec->close_reason_inverse_secded) &&
           llps_secded_is_valid_u32(rec->client_fd,
                                    rec->client_fd_secded) &&
           llps_secded_is_valid_u32(rec->client_fd_inverse,
                                    rec->client_fd_inverse_secded) &&
           llps_secded_is_valid_u32(rec->backend_fd,
                                    rec->backend_fd_secded) &&
           llps_secded_is_valid_u32(rec->backend_fd_inverse,
                                    rec->backend_fd_inverse_secded) &&
           llps_secded_is_valid_u32(rec->client_port,
                                    rec->client_port_secded) &&
           llps_secded_is_valid_u32(rec->client_port_inverse,
                                    rec->client_port_inverse_secded) &&
           llps_secded_is_valid_u32(rec->c2s_payload_ecc_len,
                                    rec->c2s_payload_ecc_len_secded) &&
           llps_secded_is_valid_u32(
               rec->c2s_payload_ecc_len_inverse,
               rec->c2s_payload_ecc_len_inverse_secded) &&
           llps_secded_is_valid_u32(rec->s2c_payload_ecc_len,
                                    rec->s2c_payload_ecc_len_secded) &&
           llps_secded_is_valid_u32(
               rec->s2c_payload_ecc_len_inverse,
               rec->s2c_payload_ecc_len_inverse_secded) &&
           llps_secded_is_valid_u32(rec->session_crc,
                                    rec->session_crc_secded) &&
           llps_secded_is_valid_u32(rec->session_crc_inverse,
                                    rec->session_crc_inverse_secded);
}

static bool llps_session_tmr_repair_status_ok(
    const llps_secded_status_t status,
    bool * const corrected) {
    if (status == LLPS_SECDED_CORRECTED) {
        if (corrected != NULL) {
            *corrected = true;
        }
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

static bool llps_session_tmr_record_repair_identity_secded(
    llps_session_tmr_record_t * const rec,
    bool * const corrected) {
    bool ok = true;

    if (rec == NULL) {
        return false;
    }

    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->session_id,
                               &rec->session_id_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->session_id_inverse,
                               &rec->session_id_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->state, &rec->state_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->state_inverse,
                               &rec->state_inverse_secded),
        corrected) && ok;
    return ok;
}

static bool llps_session_tmr_record_repair_activity_secded(
    llps_session_tmr_record_t * const rec,
    bool * const corrected) {
    bool ok = true;

    if (rec == NULL) {
        return false;
    }

    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u64(&rec->last_activity_ns,
                               64u,
                               &rec->last_activity_ns_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u64(&rec->last_activity_ns_inverse,
                               64u,
                               &rec->last_activity_ns_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u64(&rec->request_no,
                               64u,
                               &rec->request_no_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u64(&rec->request_no_inverse,
                               64u,
                               &rec->request_no_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->close_reason,
                               &rec->close_reason_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->close_reason_inverse,
                               &rec->close_reason_inverse_secded),
        corrected) && ok;
    return ok;
}

static bool llps_session_tmr_record_repair_fd_port_secded(
    llps_session_tmr_record_t * const rec,
    bool * const corrected) {
    bool ok = true;

    if (rec == NULL) {
        return false;
    }

    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->client_fd,
                               &rec->client_fd_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->client_fd_inverse,
                               &rec->client_fd_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->backend_fd,
                               &rec->backend_fd_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->backend_fd_inverse,
                               &rec->backend_fd_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->client_port,
                               &rec->client_port_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->client_port_inverse,
                               &rec->client_port_inverse_secded),
        corrected) && ok;
    return ok;
}

static bool llps_session_tmr_record_repair_payload_crc_secded(
    llps_session_tmr_record_t * const rec,
    bool * const corrected) {
    bool ok = true;

    if (rec == NULL) {
        return false;
    }

    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(
            &rec->c2s_payload_ecc_len,
            &rec->c2s_payload_ecc_len_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(
            &rec->c2s_payload_ecc_len_inverse,
            &rec->c2s_payload_ecc_len_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(
            &rec->s2c_payload_ecc_len,
            &rec->s2c_payload_ecc_len_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(
            &rec->s2c_payload_ecc_len_inverse,
            &rec->s2c_payload_ecc_len_inverse_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->session_crc,
                               &rec->session_crc_secded),
        corrected) && ok;
    ok = llps_session_tmr_repair_status_ok(
        llps_secded_repair_u32(&rec->session_crc_inverse,
                               &rec->session_crc_inverse_secded),
        corrected) && ok;
    return ok;
}

static bool llps_session_tmr_record_repair_secded(
    llps_session_tmr_record_t * const rec) {
    bool ok = true;
    bool corrected = false;

    if (rec == NULL) {
        return false;
    }

    ok = llps_session_tmr_record_repair_identity_secded(rec, &corrected) && ok;
    ok = llps_session_tmr_record_repair_activity_secded(rec, &corrected) && ok;
    ok = llps_session_tmr_record_repair_fd_port_secded(rec, &corrected) && ok;
    ok = llps_session_tmr_record_repair_payload_crc_secded(rec, &corrected) && ok;

    if (ok && corrected) {
        rec->record_crc = llps_session_tmr_record_compute_crc(rec);
        rec->record_crc_inverse = ~rec->record_crc;
    }

    return ok;
}

bool llps_session_tmr_record_is_valid(
    const llps_session_tmr_record_t * const rec,
    const uint32_t expected_bank_id,
    const uint32_t expected_session_id) {
    const uint32_t expected_magic =
        llps_session_tmr_magic_for_bank(expected_bank_id);

    if (rec == NULL) {
        return false;
    }

    if ((rec->magic_start != expected_magic) ||
        (rec->magic_end != expected_magic) ||
        (rec->bank_id != expected_bank_id) ||
        (rec->session_id != expected_session_id)) {
        return false;
    }

    if (!llps_session_tmr_record_secded_is_valid(rec)) {
        return false;
    }

    if ((rec->session_id_inverse != ~rec->session_id) ||
        (rec->state_inverse != ~rec->state) ||
        (rec->last_activity_ns_inverse != ~rec->last_activity_ns) ||
        (rec->request_no_inverse != ~rec->request_no) ||
        !llps_close_reason_is_valid(rec->close_reason) ||
        (rec->close_reason_inverse != ~rec->close_reason) ||
        (rec->client_fd_inverse != ~rec->client_fd) ||
        (rec->backend_fd_inverse != ~rec->backend_fd) ||
        (rec->client_port_inverse != ~rec->client_port) ||
        (rec->c2s_payload_ecc_len > LLPS_BUFFER_SIZE) ||
        (rec->s2c_payload_ecc_len > LLPS_BUFFER_SIZE) ||
        (rec->c2s_payload_ecc_len_inverse !=
         ~rec->c2s_payload_ecc_len) ||
        (rec->s2c_payload_ecc_len_inverse !=
         ~rec->s2c_payload_ecc_len) ||
        (rec->session_crc_inverse != ~rec->session_crc)) {
        return false;
    }

    for (size_t i = 0u; i < sizeof(rec->client_ip); ++i) {
        if (rec->client_ip_inverse[i] !=
            (uint8_t)(~rec->client_ip[i])) {
            return false;
        }
    }

    if (!llps_state_is_valid((llps_state_t)rec->state)) {
        return false;
    }

    return (rec->record_crc_inverse == ~rec->record_crc) &&
           (rec->record_crc == llps_session_tmr_record_compute_crc(rec));
}

void llps_session_tmr_record_to_snapshot(
    const llps_session_tmr_record_t * const rec,
    llps_session_tmr_snapshot_t * const out_snapshot) {
    if ((rec != NULL) && (out_snapshot != NULL)) {
        out_snapshot->session_id = rec->session_id;
        out_snapshot->state = (llps_state_t)rec->state;
        out_snapshot->last_activity_ns = rec->last_activity_ns;
        out_snapshot->request_no = rec->request_no;
        out_snapshot->client_fd = llps_decode_fd(rec->client_fd);
        out_snapshot->backend_fd = llps_decode_fd(rec->backend_fd);
        out_snapshot->close_reason = rec->close_reason;
        for (size_t i = 0u; i < sizeof(out_snapshot->client_ip); ++i) {
            out_snapshot->client_ip[i] = (char)rec->client_ip[i];
        }
        out_snapshot->client_port = (uint16_t)rec->client_port;
        out_snapshot->c2s_payload_ecc_len = rec->c2s_payload_ecc_len;
        out_snapshot->s2c_payload_ecc_len = rec->s2c_payload_ecc_len;
        out_snapshot->session_crc = rec->session_crc;
    }
}

void llps_session_tmr_record_from_snapshot(
    llps_session_tmr_record_t * const rec,
    const uint32_t bank_id,
    const llps_session_tmr_snapshot_t * const snapshot) {
    const uint32_t magic = llps_session_tmr_magic_for_bank(bank_id);

    if ((rec != NULL) && (snapshot != NULL)) {
        rec->magic_start = magic;
        rec->bank_id = bank_id;
        rec->session_id = snapshot->session_id;
        rec->session_id_inverse = ~snapshot->session_id;
        rec->state = (uint32_t)snapshot->state;
        rec->state_inverse = ~rec->state;
        rec->last_activity_ns = snapshot->last_activity_ns;
        rec->last_activity_ns_inverse = ~snapshot->last_activity_ns;
        rec->request_no = snapshot->request_no;
        rec->request_no_inverse = ~snapshot->request_no;
        rec->close_reason = snapshot->close_reason;
        rec->close_reason_inverse = ~snapshot->close_reason;
        rec->client_fd = llps_encode_fd(snapshot->client_fd);
        rec->client_fd_inverse = ~rec->client_fd;
        rec->backend_fd = llps_encode_fd(snapshot->backend_fd);
        rec->backend_fd_inverse = ~rec->backend_fd;
        for (size_t i = 0u; i < sizeof(rec->client_ip); ++i) {
            rec->client_ip[i] = (uint8_t)(unsigned char)snapshot->client_ip[i];
            rec->client_ip_inverse[i] = (uint8_t)(~rec->client_ip[i]);
        }
        rec->client_port = (uint32_t)snapshot->client_port;
        rec->client_port_inverse = ~rec->client_port;
        rec->c2s_payload_ecc_len = snapshot->c2s_payload_ecc_len;
        rec->c2s_payload_ecc_len_inverse = ~snapshot->c2s_payload_ecc_len;
        rec->s2c_payload_ecc_len = snapshot->s2c_payload_ecc_len;
        rec->s2c_payload_ecc_len_inverse = ~snapshot->s2c_payload_ecc_len;
        rec->session_crc = snapshot->session_crc;
        rec->session_crc_inverse = ~snapshot->session_crc;
        rec->magic_end = magic;
        (void)memset(rec->separation_pad, 0, sizeof(rec->separation_pad));
        llps_session_tmr_record_refresh_secded(rec);
        rec->record_crc = llps_session_tmr_record_compute_crc(rec);
        rec->record_crc_inverse = ~rec->record_crc;
    }
}

static void llps_session_tmr_write_bank(
    const uint32_t bank_id,
    const llps_session_tmr_snapshot_t * const snapshot) {
    llps_session_tmr_record_t *rec = NULL;

    if (snapshot == NULL) {
        LLPS_EXPECT(false, return);
    }

    rec = llps_session_tmr_record_ref(bank_id, snapshot->session_id);

    if (rec == NULL) {
        llps_session_tmr_restore_region_guard(bank_id);
        rec = llps_session_tmr_record_raw_ref(bank_id, snapshot->session_id);
    }

    if (rec == NULL) {
        LLPS_EXPECT(false, return);
    }

    llps_session_tmr_record_from_snapshot(rec, bank_id, snapshot);
}

void llps_session_tmr_write_all(
    const llps_session_tmr_snapshot_t * const snapshot) {
    if (snapshot == NULL) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_session_tmr_write_bank(bank_id, snapshot);
    }
}

static void llps_session_tmr_repair_divergent_banks(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_session_tmr_snapshot_t snapshots[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_session_tmr_snapshot_t * const majority) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        if (!valid[bank_id] ||
            !llps_session_tmr_snapshot_equal(&snapshots[bank_id], majority)) {
            llps_session_tmr_write_bank(bank_id, majority);
            LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_single_bank_repairs);
        }
    }
}

bool llps_session_tmr_vote(const uint32_t session_id,
                           const uint32_t max_clients,
                           llps_session_tmr_snapshot_t * const out_snapshot) {
    bool valid[LLPS_SESSION_TMR_BANK_COUNT] = { false, false, false };
    llps_session_tmr_snapshot_t snapshots[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t valid_count = 0u;
    uint32_t majority_index = UINT32_MAX;
    llps_session_tmr_snapshot_t majority;

    if ((out_snapshot == NULL) || (max_clients > LLPS_MAX_CLIENTS)) {
        return false;
    }

    if (session_id >= max_clients) {
        return false;
    }

    (void)memset(snapshots, 0, sizeof(snapshots));
    (void)memset(&majority, 0, sizeof(majority));

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_session_tmr_record_t * const rec =
            llps_session_tmr_record_ref(bank_id, session_id);

        valid[bank_id] =
            llps_session_tmr_record_repair_secded(rec) &&
            llps_session_tmr_record_is_valid(rec, bank_id, session_id);
        if (valid[bank_id]) {
            llps_session_tmr_record_to_snapshot(rec, &snapshots[bank_id]);
            ++valid_count;
        }
    }

    if (valid_count < 2u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_majority_failures);
        return false;
    }

    if (!llps_tmr_vote_find_matching_pair(
            valid,
            llps_session_tmr_snapshot_equal(&snapshots[0u], &snapshots[1u]),
            llps_session_tmr_snapshot_equal(&snapshots[0u], &snapshots[2u]),
            llps_session_tmr_snapshot_equal(&snapshots[1u], &snapshots[2u]),
            &majority_index)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_majority_failures);
        return false;
    }
    majority = snapshots[majority_index];

    llps_session_tmr_repair_divergent_banks(valid, snapshots, &majority);
    *out_snapshot = majority;
    return true;
}

static bool llps_session_tmr_save_records(
    const uint32_t session_id,
    llps_session_tmr_record_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((saved == NULL) || (session_id >= LLPS_MAX_CLIENTS)) {
        return false;
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_session_tmr_record_t * const rec =
            llps_session_tmr_record_raw_ref(bank_id, session_id);
        if (rec == NULL) {
            return false;
        }
        saved[bank_id] = *rec;
    }

    return true;
}

static void llps_session_tmr_restore_records(
    const uint32_t session_id,
    const llps_session_tmr_record_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((saved == NULL) || (session_id >= LLPS_MAX_CLIENTS)) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_session_tmr_record_t * const rec =
            llps_session_tmr_record_raw_ref(bank_id, session_id);
        if (rec == NULL) {
            LLPS_EXPECT(false, return);
        }
        *rec = saved[bank_id];
    }
}

static bool llps_session_tmr_self_test_record_refs(
    const uint32_t session_id,
    llps_session_tmr_record_t ** const rec0,
    llps_session_tmr_record_t ** const rec1,
    llps_session_tmr_record_t ** const rec2) {
    if ((rec0 == NULL) || (rec1 == NULL) || (rec2 == NULL)) {
        return false;
    }

    *rec0 = llps_session_tmr_record_raw_ref(0u, session_id);
    *rec1 = llps_session_tmr_record_raw_ref(1u, session_id);
    *rec2 = llps_session_tmr_record_raw_ref(2u, session_id);
    if ((*rec0 == NULL) || (*rec1 == NULL) || (*rec2 == NULL)) {
        LLPS_EXPECT(false, return false);
    }
    return true;
}

static bool llps_session_tmr_self_test_single_repair(
    const uint32_t session_id,
    const uint32_t max_clients,
    const llps_session_tmr_snapshot_t * const expected,
    llps_session_tmr_snapshot_t * const voted,
    llps_session_tmr_record_t * const rec0,
    uint32_t * const coverage) {
    if ((expected == NULL) || (voted == NULL) || (rec0 == NULL) ||
        (coverage == NULL)) {
        return false;
    }

    rec0->magic_start ^= UINT32_MAX;
    const bool passed =
        llps_session_tmr_vote(session_id, max_clients, voted) &&
        llps_session_tmr_snapshot_equal(expected, voted) &&
        llps_session_tmr_record_is_valid(rec0, 0u, session_id);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_SESSION_SINGLE_REPAIR;
    }
    return passed;
}

static bool llps_session_tmr_self_test_no_majority(
    const uint32_t session_id,
    const uint32_t max_clients,
    const llps_session_tmr_snapshot_t * const expected,
    llps_session_tmr_snapshot_t * const voted,
    llps_session_tmr_record_t * const rec0,
    llps_session_tmr_record_t * const rec1,
    llps_session_tmr_record_t * const rec2,
    uint32_t * const coverage) {
    llps_session_tmr_snapshot_t no_majority0;
    llps_session_tmr_snapshot_t no_majority1;
    llps_session_tmr_snapshot_t no_majority2;

    if ((expected == NULL) || (voted == NULL) || (rec0 == NULL) ||
        (rec1 == NULL) || (rec2 == NULL) || (coverage == NULL)) {
        return false;
    }

    no_majority0 = *expected;
    no_majority1 = *expected;
    no_majority2 = *expected;
    no_majority1.last_activity_ns ^= UINT64_C(0xA5A5A5A5A5A5A5A5);
    no_majority2.last_activity_ns ^= UINT64_C(0x5A5A5A5A5A5A5A5A);
    llps_session_tmr_record_from_snapshot(rec0, 0u, &no_majority0);
    llps_session_tmr_record_from_snapshot(rec1, 1u, &no_majority1);
    llps_session_tmr_record_from_snapshot(rec2, 2u, &no_majority2);
    const bool passed = !llps_session_tmr_vote(session_id,
                                               max_clients,
                                               voted);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_SESSION_NO_MAJORITY_FAIL_CLOSED;
    }
    return passed;
}

static bool llps_session_tmr_self_test_dual_fail(
    const uint32_t session_id,
    const uint32_t max_clients,
    const llps_session_tmr_snapshot_t * const expected,
    llps_session_tmr_snapshot_t * const voted,
    llps_session_tmr_record_t * const rec0,
    llps_session_tmr_record_t * const rec1,
    uint32_t * const coverage) {
    if ((expected == NULL) || (voted == NULL) || (rec0 == NULL) ||
        (rec1 == NULL) || (coverage == NULL)) {
        return false;
    }

    llps_session_tmr_write_all(expected);
    rec0->magic_start = 0u;
    rec1->magic_start = 0u;
    const bool passed = !llps_session_tmr_vote(session_id,
                                               max_clients,
                                               voted);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_SESSION_DUAL_FAIL_CLOSED;
    }
    return passed;
}

static bool llps_session_tmr_self_test_run_cases(
    const uint32_t session_id,
    const uint32_t max_clients,
    const llps_session_tmr_snapshot_t * const expected,
    uint32_t * const coverage) {
    llps_session_tmr_snapshot_t voted;
    llps_session_tmr_record_t *rec0 = NULL;
    llps_session_tmr_record_t *rec1 = NULL;
    llps_session_tmr_record_t *rec2 = NULL;

    (void)memset(&voted, 0, sizeof(voted));
    bool passed = llps_session_tmr_self_test_record_refs(session_id,
                                                         &rec0,
                                                         &rec1,
                                                         &rec2);
    if (passed) {
        passed = llps_session_tmr_self_test_single_repair(session_id,
                                                          max_clients,
                                                          expected,
                                                          &voted,
                                                          rec0,
                                                          coverage);
    }
    if (passed) {
        passed = llps_session_tmr_self_test_no_majority(session_id,
                                                        max_clients,
                                                        expected,
                                                        &voted,
                                                        rec0,
                                                        rec1,
                                                        rec2,
                                                        coverage);
    }
    if (passed) {
        passed = llps_session_tmr_self_test_dual_fail(session_id,
                                                      max_clients,
                                                      expected,
                                                      &voted,
                                                      rec0,
                                                      rec1,
                                                      coverage);
    }
    return passed;
}

bool llps_session_tmr_startup_self_test(const uint32_t max_clients,
                                        uint32_t * const coverage) {
    const uint32_t test_session_id = 0u;
    llps_session_tmr_record_t
        saved_records[LLPS_SESSION_TMR_BANK_COUNT];
    llps_session_tmr_snapshot_t expected;
    bool passed = false;
    bool saved_records_valid = false;

    (void)memset(&expected, 0, sizeof(expected));

    if ((coverage == NULL) || (max_clients == 0u)) {
        return false;
    }

    saved_records_valid =
        llps_session_tmr_save_records(test_session_id, saved_records);
    passed = saved_records_valid &&
             llps_session_tmr_vote(test_session_id, max_clients, &expected);

    if (passed) {
        passed = llps_session_tmr_self_test_run_cases(test_session_id,
                                                      max_clients,
                                                      &expected,
                                                      coverage);
    }

    if (saved_records_valid) {
        llps_session_tmr_restore_records(test_session_id, saved_records);
    }
    return passed;
}
