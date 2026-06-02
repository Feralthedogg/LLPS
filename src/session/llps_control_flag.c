/**
 * @file src/session/llps_control_flag.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_control_flag.h"

#include "llps_crc.h"
#include "llps_guard.h"
#include "llps_internal.h"
#include "llps_safety_counters.h"
#include "llps_tmr_vote.h"

#include <stdbool.h>
#include <stdint.h>

static volatile bool g_server_shutdown_requested = false;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK0)
LLPS_USED
llps_control_flag_bank_t g_control_flag_bank0;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK1)
LLPS_USED
llps_control_flag_bank_t g_control_flag_bank1;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK2)
LLPS_USED
llps_control_flag_bank_t g_control_flag_bank2;

static llps_control_flag_bank_t *llps_control_flag_bank_ref(
    const uint32_t bank_id) {
    static llps_control_flag_bank_t * const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_control_flag_bank0,
        &g_control_flag_bank1,
        &g_control_flag_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static const llps_control_flag_bank_t *llps_control_flag_bank_cref(
    const uint32_t bank_id) {
    static const llps_control_flag_bank_t *
        const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_control_flag_bank0,
        &g_control_flag_bank1,
        &g_control_flag_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static uint32_t llps_control_flag_bank_magic_for_bank(const uint32_t bank_id) {
    return LLPS_CONTROL_FLAG_BANK_MAGIC ^ (0x01010101u * (bank_id + 1u));
}

bool llps_control_flag_value_is_valid(const uint32_t value) {
    return value <= 1u;
}

uint32_t llps_control_flag_bank_compute_crc(
    const llps_control_flag_bank_t * const bank) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (bank == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, bank->magic_start);
    crc = llps_crc32_update_u32(crc, bank->bank_id);
    crc = llps_crc32_update_u32(crc, bank->shutdown_requested);
    crc = llps_crc32_update_u32(crc, bank->shutdown_requested_inverse);
    crc = llps_crc32_update_u32(crc, bank->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

bool llps_control_flag_bank_is_valid(
    const llps_control_flag_bank_t * const bank,
    const uint32_t expected_bank_id) {
    const uint32_t magic =
        llps_control_flag_bank_magic_for_bank(expected_bank_id);

    if (bank == NULL) {
        return false;
    }

    if ((bank->magic_start != magic) ||
        (bank->magic_end != magic) ||
        (bank->bank_id != expected_bank_id) ||
        !llps_control_flag_value_is_valid(bank->shutdown_requested) ||
        (bank->shutdown_requested_inverse != ~bank->shutdown_requested)) {
        return false;
    }

    return (bank->crc_inverse == ~bank->crc) &&
           (bank->crc == llps_control_flag_bank_compute_crc(bank));
}

void llps_control_flag_bank_from_value(
    llps_control_flag_bank_t * const bank,
    const uint32_t bank_id,
    const bool shutdown_requested) {
    const uint32_t magic = llps_control_flag_bank_magic_for_bank(bank_id);
    const uint32_t encoded = llps_bool_to_u32(shutdown_requested);

    if (bank != NULL) {
        bank->magic_start = magic;
        bank->bank_id = bank_id;
        bank->shutdown_requested = encoded;
        bank->shutdown_requested_inverse = ~encoded;
        bank->magic_end = magic;
        bank->crc = llps_control_flag_bank_compute_crc(bank);
        bank->crc_inverse = ~bank->crc;
    }
}

void llps_control_flag_write_all(const bool shutdown_requested) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_control_flag_bank_t * const bank =
            llps_control_flag_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        llps_control_flag_bank_from_value(bank, bank_id, shutdown_requested);
    }

    g_server_shutdown_requested = shutdown_requested;
}

static void llps_control_flag_repair_divergent_banks(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    const bool snapshots[LLPS_SESSION_TMR_BANK_COUNT],
    const bool majority) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        if (!valid[bank_id] || (snapshots[bank_id] != majority)) {
            llps_control_flag_bank_t * const bank =
                llps_control_flag_bank_ref(bank_id);
            if (bank != NULL) {
                llps_control_flag_bank_from_value(bank, bank_id, majority);
                LLPS_MEMORY_SAFETY_COUNTER_INC(control_flag_single_bank_repairs);
            }
        }
    }
}

bool llps_control_flag_reconcile(bool * const out_shutdown_requested) {
    bool valid[LLPS_SESSION_TMR_BANK_COUNT] = { false, false, false };
    bool snapshots[LLPS_SESSION_TMR_BANK_COUNT] = { false, false, false };
    uint32_t valid_count = 0u;
    uint32_t majority_index = UINT32_MAX;
    bool majority = false;

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_control_flag_bank_t * const bank =
            llps_control_flag_bank_cref(bank_id);

        valid[bank_id] = llps_control_flag_bank_is_valid(bank, bank_id);
        if (valid[bank_id] && (bank != NULL)) {
            snapshots[bank_id] = bank->shutdown_requested != 0u;
            ++valid_count;
        }
    }

    if (valid_count < 2u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(control_flag_majority_failures);
        g_server_shutdown_requested = true;
        if (out_shutdown_requested != NULL) {
            *out_shutdown_requested = true;
        }
        return false;
    }

    if (!llps_tmr_vote_find_matching_pair(
            valid,
            snapshots[0u] == snapshots[1u],
            snapshots[0u] == snapshots[2u],
            snapshots[1u] == snapshots[2u],
            &majority_index)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(control_flag_majority_failures);
        g_server_shutdown_requested = true;
        if (out_shutdown_requested != NULL) {
            *out_shutdown_requested = true;
        }
        return false;
    }
    majority = snapshots[majority_index];

    llps_control_flag_repair_divergent_banks(valid, snapshots, majority);
    g_server_shutdown_requested = majority;
    if (out_shutdown_requested != NULL) {
        *out_shutdown_requested = majority;
    }

    return true;
}

bool llps_control_shutdown_is_requested(void) {
    bool shutdown_requested = true;

    if (!llps_control_flag_reconcile(&shutdown_requested)) {
        return true;
    }

    return shutdown_requested;
}

void llps_control_request_shutdown(void) {
    llps_control_flag_write_all(true);
}

void llps_control_clear_shutdown(void) {
    llps_control_flag_write_all(false);
}

static bool llps_control_flag_save_banks(
    llps_control_flag_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (saved == NULL) {
        return false;
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_control_flag_bank_t * const bank =
            llps_control_flag_bank_cref(bank_id);
        if (bank == NULL) {
            return false;
        }
        saved[bank_id] = *bank;
    }

    return true;
}

static void llps_control_flag_restore_banks(
    const llps_control_flag_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT],
    const bool shutdown_requested) {
    if (saved == NULL) {
        LLPS_EXPECT(false, return);
    }

    g_server_shutdown_requested = shutdown_requested;
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_control_flag_bank_t * const bank =
            llps_control_flag_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        *bank = saved[bank_id];
    }
}

bool llps_control_flag_tmr_startup_self_test(uint32_t * const coverage) {
    const bool saved_shutdown_requested = g_server_shutdown_requested;
    llps_control_flag_bank_t saved_banks[LLPS_SESSION_TMR_BANK_COUNT];
    bool saved_banks_valid = false;
    bool shutdown_requested = true;
    bool passed = false;
    llps_control_flag_bank_t *bank0 = NULL;
    llps_control_flag_bank_t *bank1 = NULL;

    if (coverage == NULL) {
        return false;
    }

    saved_banks_valid = llps_control_flag_save_banks(saved_banks);
    passed = saved_banks_valid &&
             llps_control_flag_reconcile(&shutdown_requested) &&
             (shutdown_requested == saved_shutdown_requested);

    if (passed) {
        bank0 = llps_control_flag_bank_ref(0u);
        bank1 = llps_control_flag_bank_ref(1u);
        if ((bank0 == NULL) || (bank1 == NULL)) {
            LLPS_EXPECT(false, passed = false);
        }
    }

    if (passed) {
        bank0->magic_start ^= UINT32_MAX;
        passed = llps_control_flag_reconcile(&shutdown_requested) &&
                 (shutdown_requested == saved_shutdown_requested) &&
                 llps_control_flag_bank_is_valid(bank0, 0u);
        if (passed) {
            *coverage |= LLPS_TMR_SELF_TEST_CONTROL_FLAG_SINGLE_REPAIR;
        }
    }

    if (passed) {
        bank0->magic_start = 0u;
        bank1->magic_start = 0u;
        passed = !llps_control_flag_reconcile(&shutdown_requested);
        if (passed) {
            *coverage |= LLPS_TMR_SELF_TEST_CONTROL_FLAG_DUAL_FAIL_CLOSED;
        }
    }

    if (saved_banks_valid) {
        llps_control_flag_restore_banks(saved_banks, saved_shutdown_requested);
    }
    return passed;
}
