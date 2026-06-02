/**
 * @file src/internal/llps_free_list_tmr.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_FREE_LIST_TMR_H
#define LLPS_FREE_LIST_TMR_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t magic_start;
    uint32_t bank_id;
    uint32_t count;
    uint32_t count_inverse;
    uint32_t entries[LLPS_MAX_CLIENTS];
    uint32_t entries_inverse[LLPS_MAX_CLIENTS];
    uint32_t crc;
    uint32_t crc_inverse;
    uint32_t magic_end;
} llps_free_list_bank_t;

typedef struct {
    uint32_t count;
    uint32_t entries[LLPS_MAX_CLIENTS];
} llps_free_list_snapshot_t;

extern llps_free_list_bank_t g_free_list_bank0;
extern llps_free_list_bank_t g_free_list_bank1;
extern llps_free_list_bank_t g_free_list_bank2;

/** @brief Compute the CRC for one replicated free-list bank. */
uint32_t llps_free_list_bank_compute_crc(const llps_free_list_bank_t *bank);
/** @brief Compare two free-list snapshots for exact equality. */
bool llps_free_list_snapshot_equal(const llps_free_list_snapshot_t *lhs,
                                   const llps_free_list_snapshot_t *rhs);
/** @brief Validate canaries, bounds, inverse fields, and CRC for one bank. */
bool llps_free_list_bank_is_valid(const llps_free_list_bank_t *bank,
                                  uint32_t expected_bank_id,
                                  uint32_t max_clients);
/** @brief Populate one free-list bank from a canonical snapshot. */
void llps_free_list_bank_from_snapshot(
    llps_free_list_bank_t *bank,
    uint32_t bank_id,
    const llps_free_list_snapshot_t *snapshot);
/** @brief Copy canonical free-list arrays into a snapshot. */
void llps_free_list_snapshot_from_canonical(
    llps_free_list_snapshot_t *out_snapshot,
    const uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t count);
/** @brief Write one snapshot into all free-list TMR banks. */
void llps_free_list_write_all_from_snapshot(
    const llps_free_list_snapshot_t *snapshot);
/** @brief Snapshot canonical free-list state and replicate it to all banks. */
void llps_free_list_write_all_from_canonical(
    const uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t count);
/** @brief Vote free-list banks and repair a single divergent bank. */
bool llps_free_list_vote(llps_free_list_snapshot_t *out_snapshot,
                         llps_yml_config_t *runtime_cfg);
/** @brief Reconcile TMR free-list state back into canonical arrays. */
bool llps_free_list_reconcile(uint32_t entries[LLPS_MAX_CLIENTS],
                              uint32_t *count,
                              llps_yml_config_t *runtime_cfg);
/** @brief Exercise free-list single-repair and fail-closed startup paths. */
bool llps_free_list_tmr_startup_self_test(
    uint32_t entries[LLPS_MAX_CLIENTS],
    uint32_t *count,
    llps_yml_config_t *runtime_cfg,
    uint32_t *coverage);

#endif /* LLPS_FREE_LIST_TMR_H */
