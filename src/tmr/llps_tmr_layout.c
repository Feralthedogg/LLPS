/**
 * @file src/tmr/llps_tmr_layout.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_layout.h"

#include "llps_control_flag.h"
#include "llps_crc.h"
#include "llps_free_list_tmr.h"
#include "llps_internal.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_session_tmr.h"

#include <stddef.h>
#include <stdint.h>

uintptr_t llps_abs_addr_distance(const uintptr_t lhs, const uintptr_t rhs) {
    if (lhs >= rhs) {
        return lhs - rhs;
    }

    return rhs - lhs;
}

static uintptr_t llps_min_addr_distance(const uintptr_t lhs,
                                        const uintptr_t rhs) {
    return (lhs < rhs) ? lhs : rhs;
}

uintptr_t llps_tmr_triplet_min_bank_distance(const void * const bank0,
                                             const void * const bank1,
                                             const void * const bank2) {
    const uintptr_t addr0 = (uintptr_t)bank0;
    const uintptr_t addr1 = (uintptr_t)bank1;
    const uintptr_t addr2 = (uintptr_t)bank2;
    const uintptr_t dist01 = llps_abs_addr_distance(addr0, addr1);
    const uintptr_t dist02 = llps_abs_addr_distance(addr0, addr2);
    const uintptr_t dist12 = llps_abs_addr_distance(addr1, addr2);

    return llps_min_addr_distance(dist01,
                                  llps_min_addr_distance(dist02, dist12));
}

bool llps_tmr_triplet_layout_is_valid(const void * const bank0,
                                      const void * const bank1,
                                      const void * const bank2) {
    const uintptr_t addr0 = (uintptr_t)bank0;
    const uintptr_t addr1 = (uintptr_t)bank1;
    const uintptr_t addr2 = (uintptr_t)bank2;

    if ((bank0 == NULL) || (bank1 == NULL) || (bank2 == NULL)) {
        return false;
    }

    if (((addr0 % LLPS_SESSION_TMR_ALIGNMENT_BYTES) != 0u) ||
        ((addr1 % LLPS_SESSION_TMR_ALIGNMENT_BYTES) != 0u) ||
        ((addr2 % LLPS_SESSION_TMR_ALIGNMENT_BYTES) != 0u)) {
        return false;
    }

    return llps_tmr_triplet_min_bank_distance(bank0, bank1, bank2) >=
           LLPS_SESSION_TMR_MIN_DISTANCE_BYTES;
}

uint64_t llps_tmr_metadata_min_bank_distance(void) {
    uintptr_t min_distance =
        llps_tmr_triplet_min_bank_distance(&g_session_tmr_region0,
                                           &g_session_tmr_region1,
                                           &g_session_tmr_region2);
    uintptr_t candidate =
        llps_tmr_triplet_min_bank_distance(&g_runtime_cfg_bank0,
                                           &g_runtime_cfg_bank1,
                                           &g_runtime_cfg_bank2);

    min_distance = llps_min_addr_distance(min_distance, candidate);
    candidate = llps_tmr_triplet_min_bank_distance(&g_free_list_bank0,
                                                   &g_free_list_bank1,
                                                   &g_free_list_bank2);
    min_distance = llps_min_addr_distance(min_distance, candidate);
    candidate = llps_tmr_triplet_min_bank_distance(&g_control_flag_bank0,
                                                   &g_control_flag_bank1,
                                                   &g_control_flag_bank2);
    min_distance = llps_min_addr_distance(min_distance, candidate);

    return (uint64_t)min_distance;
}

static uint32_t llps_tmr_layout_fingerprint_add_region(uint32_t crc,
                                                       const uint32_t region_id,
                                                       const size_t len) {
    crc = llps_crc32_update_u32(crc, region_id);
    return llps_crc32_update_size(crc, len);
}

uint32_t llps_tmr_layout_fingerprint(void) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_BANK_COUNT);
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_ALIGNMENT_BYTES);
    crc = llps_crc32_update_u32(crc, LLPS_SESSION_TMR_MIN_DISTANCE_BYTES);
    crc = llps_crc32_update_u64(crc, llps_tmr_metadata_min_bank_distance());

    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 0u,
                                                 sizeof(g_session_tmr_region0));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 1u,
                                                 sizeof(g_session_tmr_region1));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 2u,
                                                 sizeof(g_session_tmr_region2));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 3u,
                                                 sizeof(g_runtime_cfg_bank0));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 4u,
                                                 sizeof(g_runtime_cfg_bank1));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 5u,
                                                 sizeof(g_runtime_cfg_bank2));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 6u,
                                                 sizeof(g_free_list_bank0));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 7u,
                                                 sizeof(g_free_list_bank1));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 8u,
                                                 sizeof(g_free_list_bank2));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 9u,
                                                 sizeof(g_control_flag_bank0));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 10u,
                                                 sizeof(g_control_flag_bank1));
    crc = llps_tmr_layout_fingerprint_add_region(crc,
                                                 11u,
                                                 sizeof(g_control_flag_bank2));

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

bool llps_session_tmr_layout_is_valid(void) {
    if (!llps_tmr_triplet_layout_is_valid(&g_session_tmr_region0,
                                          &g_session_tmr_region1,
                                          &g_session_tmr_region2)) {
        return false;
    }

    for (uint32_t bank_id = 0u;
         bank_id < LLPS_SESSION_TMR_BANK_COUNT;
         ++bank_id) {
        if (!llps_session_tmr_region_guard_is_valid(bank_id)) {
            return false;
        }
    }

    return true;
}

bool llps_tmr_metadata_layout_is_valid(void) {
    if (!llps_session_tmr_layout_is_valid()) {
        return false;
    }

    if (!llps_tmr_triplet_layout_is_valid(&g_runtime_cfg_bank0,
                                          &g_runtime_cfg_bank1,
                                          &g_runtime_cfg_bank2)) {
        return false;
    }

    if (!llps_tmr_triplet_layout_is_valid(&g_free_list_bank0,
                                          &g_free_list_bank1,
                                          &g_free_list_bank2)) {
        return false;
    }

    return llps_tmr_triplet_layout_is_valid(&g_control_flag_bank0,
                                            &g_control_flag_bank1,
                                            &g_control_flag_bank2);
}
