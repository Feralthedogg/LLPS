/**
 * @file src/session/llps_free_list_tmr.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_free_list_tmr.h"

#include "llps_crc.h"
#include "llps_internal.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_safety_counters.h"
#include "llps_tmr_vote.h"

#include <stdint.h>
#include <string.h>

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK0)
LLPS_USED
llps_free_list_bank_t g_free_list_bank0;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK1)
LLPS_USED
llps_free_list_bank_t g_free_list_bank1;

LLPS_ALIGNED(LLPS_SESSION_TMR_ALIGNMENT_BYTES)
LLPS_SECTION(LLPS_TMR_SECTION_BANK2)
LLPS_USED
llps_free_list_bank_t g_free_list_bank2;

static llps_free_list_bank_t *llps_free_list_bank_ref(const uint32_t bank_id) {
    static llps_free_list_bank_t * const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_free_list_bank0,
        &g_free_list_bank1,
        &g_free_list_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static const llps_free_list_bank_t *llps_free_list_bank_cref(
    const uint32_t bank_id) {
    static const llps_free_list_bank_t *
        const banks[LLPS_SESSION_TMR_BANK_COUNT] =
    {
        &g_free_list_bank0,
        &g_free_list_bank1,
        &g_free_list_bank2
    };

    return bank_id < LLPS_SESSION_TMR_BANK_COUNT ? banks[bank_id] : NULL;
}

static uint32_t llps_free_list_bank_magic_for_bank(const uint32_t bank_id) {
    return LLPS_FREE_LIST_BANK_MAGIC ^ (0x01020408u * (bank_id + 1u));
}

uint32_t llps_free_list_bank_compute_crc(
    const llps_free_list_bank_t * const bank) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (bank == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, bank->magic_start);
    crc = llps_crc32_update_u32(crc, bank->bank_id);
    crc = llps_crc32_update_u32(crc, bank->count);
    crc = llps_crc32_update_u32(crc, bank->count_inverse);
    for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
        crc = llps_crc32_update_u32(crc, bank->entries[i]);
        crc = llps_crc32_update_u32(crc, bank->entries_inverse[i]);
    }
    crc = llps_crc32_update_u32(crc, bank->magic_end);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

bool llps_free_list_snapshot_equal(
    const llps_free_list_snapshot_t * const lhs,
    const llps_free_list_snapshot_t * const rhs) {
    if ((lhs == NULL) || (rhs == NULL) || (lhs->count != rhs->count)) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
        if (lhs->entries[i] != rhs->entries[i]) {
            return false;
        }
    }

    return true;
}

bool llps_free_list_bank_is_valid(
    const llps_free_list_bank_t * const bank,
    const uint32_t expected_bank_id,
    const uint32_t max_clients) {
    const uint32_t magic = llps_free_list_bank_magic_for_bank(expected_bank_id);

    if (bank == NULL) {
        return false;
    }

    if ((bank->magic_start != magic) ||
        (bank->magic_end != magic) ||
        (bank->bank_id != expected_bank_id) ||
        (bank->count > max_clients) ||
        (bank->count_inverse != ~bank->count)) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
        if (bank->entries_inverse[i] != ~bank->entries[i]) {
            return false;
        }
    }

    return (bank->crc_inverse == ~bank->crc) &&
           (bank->crc == llps_free_list_bank_compute_crc(bank));
}

static void llps_free_list_bank_to_snapshot(
    const llps_free_list_bank_t * const bank,
    llps_free_list_snapshot_t * const out_snapshot) {
    if ((bank != NULL) && (out_snapshot != NULL)) {
        out_snapshot->count = bank->count;
        for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
            out_snapshot->entries[i] = bank->entries[i];
        }
    }
}

void llps_free_list_bank_from_snapshot(
    llps_free_list_bank_t * const bank,
    const uint32_t bank_id,
    const llps_free_list_snapshot_t * const snapshot) {
    const uint32_t magic = llps_free_list_bank_magic_for_bank(bank_id);

    if ((bank != NULL) && (snapshot != NULL)) {
        bank->magic_start = magic;
        bank->bank_id = bank_id;
        bank->count = snapshot->count;
        bank->count_inverse = ~snapshot->count;
        for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
            bank->entries[i] = snapshot->entries[i];
            bank->entries_inverse[i] = ~snapshot->entries[i];
        }
        bank->magic_end = magic;
        bank->crc = llps_free_list_bank_compute_crc(bank);
        bank->crc_inverse = ~bank->crc;
    }
}

void llps_free_list_snapshot_from_canonical(
    llps_free_list_snapshot_t * const out_snapshot,
    const uint32_t entries[LLPS_MAX_CLIENTS],
    const uint32_t count) {
    if ((out_snapshot != NULL) && (entries != NULL)) {
        out_snapshot->count = count;
        for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
            out_snapshot->entries[i] = entries[i];
        }
    }
}

static void llps_free_list_apply_snapshot(
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t * const count,
    const llps_free_list_snapshot_t * const snapshot) {
    if ((entries != NULL) && (count != NULL) && (snapshot != NULL)) {
        *count = snapshot->count;
        for (uint32_t i = 0u; i < LLPS_MAX_CLIENTS; ++i) {
            entries[i] = snapshot->entries[i];
        }
    }
}

void llps_free_list_write_all_from_snapshot(
    const llps_free_list_snapshot_t * const snapshot) {
    if (snapshot == NULL) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_free_list_bank_t * const bank = llps_free_list_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        llps_free_list_bank_from_snapshot(bank, bank_id, snapshot);
    }
}

void llps_free_list_write_all_from_canonical(
    const uint32_t entries[LLPS_MAX_CLIENTS],
    const uint32_t count) {
    llps_free_list_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    llps_free_list_snapshot_from_canonical(&snapshot, entries, count);
    llps_free_list_write_all_from_snapshot(&snapshot);
}

static void llps_free_list_repair_divergent_banks(
    const bool valid[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_free_list_snapshot_t snapshots[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_free_list_snapshot_t * const majority) {
    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        if (!valid[bank_id] ||
            !llps_free_list_snapshot_equal(&snapshots[bank_id], majority)) {
            llps_free_list_bank_t * const bank =
                llps_free_list_bank_ref(bank_id);
            if (bank != NULL) {
                llps_free_list_bank_from_snapshot(bank, bank_id, majority);
                LLPS_MEMORY_SAFETY_COUNTER_INC(free_list_single_bank_repairs);
            }
        }
    }
}

bool llps_free_list_vote(llps_free_list_snapshot_t * const out_snapshot,
                         llps_yml_config_t * const runtime_cfg) {
    bool valid[LLPS_SESSION_TMR_BANK_COUNT] = { false, false, false };
    llps_free_list_snapshot_t snapshots[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t valid_count = 0u;
    uint32_t majority_index = UINT32_MAX;
    llps_free_list_snapshot_t majority;

    if ((out_snapshot == NULL) || (runtime_cfg == NULL)) {
        return false;
    }

    if (!llps_runtime_cfg_reconcile(runtime_cfg)) {
        return false;
    }

    (void)memset(snapshots, 0, sizeof(snapshots));
    (void)memset(&majority, 0, sizeof(majority));

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_free_list_bank_t * const bank =
            llps_free_list_bank_cref(bank_id);

        valid[bank_id] = llps_free_list_bank_is_valid(bank,
                                                      bank_id,
                                                      runtime_cfg->max_clients);
        if (valid[bank_id]) {
            llps_free_list_bank_to_snapshot(bank, &snapshots[bank_id]);
            ++valid_count;
        }
    }

    if (valid_count < 2u) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(free_list_majority_failures);
        return false;
    }

    if (!llps_tmr_vote_find_matching_pair(
            valid,
            llps_free_list_snapshot_equal(&snapshots[0u], &snapshots[1u]),
            llps_free_list_snapshot_equal(&snapshots[0u], &snapshots[2u]),
            llps_free_list_snapshot_equal(&snapshots[1u], &snapshots[2u]),
            &majority_index)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(free_list_majority_failures);
        return false;
    }
    majority = snapshots[majority_index];

    llps_free_list_repair_divergent_banks(valid, snapshots, &majority);
    *out_snapshot = majority;
    return true;
}

bool llps_free_list_reconcile(uint32_t entries[LLPS_MAX_CLIENTS],
                              uint32_t * const count,
                              llps_yml_config_t * const runtime_cfg) {
    llps_free_list_snapshot_t snapshot;

    if ((entries == NULL) || (count == NULL)) {
        return false;
    }

    if (!llps_free_list_vote(&snapshot, runtime_cfg)) {
        return false;
    }

    llps_free_list_apply_snapshot(entries, count, &snapshot);
    return true;
}

static bool llps_free_list_save_banks(
    llps_free_list_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (saved == NULL) {
        return false;
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        const llps_free_list_bank_t * const bank =
            llps_free_list_bank_cref(bank_id);
        if (bank == NULL) {
            return false;
        }
        saved[bank_id] = *bank;
    }

    return true;
}

static void llps_free_list_restore_banks(
    const llps_free_list_bank_t saved[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (saved == NULL) {
        LLPS_EXPECT(false, return);
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        llps_free_list_bank_t * const bank = llps_free_list_bank_ref(bank_id);
        if (bank == NULL) {
            LLPS_EXPECT(false, return);
        }
        *bank = saved[bank_id];
    }
}

static bool llps_free_list_self_test_bank_refs(
    llps_free_list_bank_t ** const bank0,
    llps_free_list_bank_t ** const bank1,
    llps_free_list_bank_t ** const bank2) {
    if ((bank0 == NULL) || (bank1 == NULL) || (bank2 == NULL)) {
        return false;
    }

    *bank0 = llps_free_list_bank_ref(0u);
    *bank1 = llps_free_list_bank_ref(1u);
    *bank2 = llps_free_list_bank_ref(2u);
    if ((*bank0 == NULL) || (*bank1 == NULL) || (*bank2 == NULL)) {
        LLPS_EXPECT(false, return false);
    }
    return true;
}

static bool llps_free_list_self_test_single_repair(
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t * const count,
    llps_yml_config_t * const runtime_cfg,
    llps_free_list_bank_t * const bank0,
    uint32_t * const coverage) {
    if ((entries == NULL) || (count == NULL) || (runtime_cfg == NULL) ||
        (bank0 == NULL) || (coverage == NULL)) {
        return false;
    }

    bank0->magic_start ^= UINT32_MAX;
    const bool passed =
        llps_free_list_reconcile(entries, count, runtime_cfg) &&
        llps_free_list_bank_is_valid(bank0, 0u, runtime_cfg->max_clients);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_FREE_LIST_SINGLE_REPAIR;
    }
    return passed;
}

static bool llps_free_list_self_test_no_majority(
    const llps_free_list_snapshot_t * const expected,
    llps_free_list_snapshot_t * const actual,
    llps_yml_config_t * const runtime_cfg,
    llps_free_list_bank_t * const bank0,
    llps_free_list_bank_t * const bank1,
    llps_free_list_bank_t * const bank2,
    uint32_t * const coverage) {
    llps_free_list_snapshot_t no_majority0;
    llps_free_list_snapshot_t no_majority1;
    llps_free_list_snapshot_t no_majority2;

    if ((expected == NULL) || (actual == NULL) || (runtime_cfg == NULL) ||
        (bank0 == NULL) || (bank1 == NULL) || (bank2 == NULL) ||
        (coverage == NULL) || (expected->count < 2u)) {
        return false;
    }

    no_majority0 = *expected;
    no_majority1 = *expected;
    no_majority2 = *expected;
    no_majority0.entries[0] ^= UINT32_C(0x1);
    no_majority1.entries[1] ^= UINT32_C(0x2);
    no_majority2.count ^= UINT32_C(0x1);
    llps_free_list_bank_from_snapshot(bank0, 0u, &no_majority0);
    llps_free_list_bank_from_snapshot(bank1, 1u, &no_majority1);
    llps_free_list_bank_from_snapshot(bank2, 2u, &no_majority2);
    const bool passed = !llps_free_list_vote(actual, runtime_cfg);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_FREE_LIST_NO_MAJORITY_FAIL_CLOSED;
    }
    return passed;
}

static bool llps_free_list_self_test_dual_fail(
    const llps_free_list_snapshot_t * const expected,
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t * const count,
    llps_yml_config_t * const runtime_cfg,
    llps_free_list_bank_t * const bank0,
    llps_free_list_bank_t * const bank1,
    uint32_t * const coverage) {
    if ((expected == NULL) || (entries == NULL) || (count == NULL) ||
        (runtime_cfg == NULL) || (bank0 == NULL) || (bank1 == NULL) ||
        (coverage == NULL)) {
        return false;
    }

    llps_free_list_write_all_from_snapshot(expected);
    bank0->magic_start = 0u;
    bank1->magic_start = 0u;
    const bool passed = !llps_free_list_reconcile(entries, count, runtime_cfg);
    if (passed) {
        *coverage |= LLPS_TMR_SELF_TEST_FREE_LIST_DUAL_FAIL_CLOSED;
    }
    return passed;
}

static bool llps_free_list_self_test_run_cases(
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t * const count,
    llps_yml_config_t * const runtime_cfg,
    const llps_free_list_snapshot_t * const expected,
    uint32_t * const coverage) {
    llps_free_list_snapshot_t actual;
    llps_free_list_bank_t *bank0 = NULL;
    llps_free_list_bank_t *bank1 = NULL;
    llps_free_list_bank_t *bank2 = NULL;

    (void)memset(&actual, 0, sizeof(actual));
    bool passed = llps_free_list_self_test_bank_refs(&bank0, &bank1, &bank2);
    if (passed) {
        passed = llps_free_list_self_test_single_repair(entries,
                                                        count,
                                                        runtime_cfg,
                                                        bank0,
                                                        coverage);
    }
    if (passed) {
        llps_free_list_snapshot_from_canonical(&actual, entries, *count);
        passed = llps_free_list_snapshot_equal(expected, &actual);
    }
    if (passed) {
        passed = llps_free_list_self_test_no_majority(expected,
                                                      &actual,
                                                      runtime_cfg,
                                                      bank0,
                                                      bank1,
                                                      bank2,
                                                      coverage);
    }
    if (passed) {
        passed = llps_free_list_self_test_dual_fail(expected,
                                                    entries,
                                                    count,
                                                    runtime_cfg,
                                                    bank0,
                                                    bank1,
                                                    coverage);
    }
    return passed;
}

bool llps_free_list_tmr_startup_self_test(
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t * const count,
    llps_yml_config_t * const runtime_cfg,
    uint32_t * const coverage) {
    const uint32_t saved_count = (count != NULL) ? *count : 0u;
    llps_free_list_bank_t saved_banks[LLPS_SESSION_TMR_BANK_COUNT];
    llps_free_list_snapshot_t saved;
    llps_free_list_snapshot_t expected;
    bool passed = false;
    bool saved_banks_valid = false;

    (void)memset(&saved, 0, sizeof(saved));
    (void)memset(&expected, 0, sizeof(expected));

    if ((entries == NULL) ||
        (count == NULL) ||
        (runtime_cfg == NULL) ||
        (coverage == NULL)) {
        return false;
    }

    llps_free_list_snapshot_from_canonical(&saved, entries, saved_count);
    expected = saved;

    saved_banks_valid = llps_free_list_save_banks(saved_banks);
    passed = saved_banks_valid &&
             llps_free_list_reconcile(entries, count, runtime_cfg);

    if (passed) {
        passed = llps_free_list_self_test_run_cases(entries,
                                                    count,
                                                    runtime_cfg,
                                                    &expected,
                                                    coverage);
    }

    llps_free_list_apply_snapshot(entries, count, &saved);
    if (saved_banks_valid) {
        llps_free_list_restore_banks(saved_banks);
    }
    return passed;
}
