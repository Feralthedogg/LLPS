/**
 * @file src/tmr/llps_tmr_probe.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_probe.h"

#include "llps_crc.h"
#include "llps_internal.h"

#include <string.h>

void llps_tmr_memory_residency_probe_init(
    llps_tmr_memory_residency_probe_t * const probe) {
    if (probe != NULL) {
        (void)memset(probe, 0, sizeof(*probe));
    }
}

void llps_tmr_memory_residency_probe_note_page(
    llps_tmr_memory_residency_probe_t * const probe,
    const uint32_t region_id,
    const uintptr_t page_addr,
    const bool probe_ok,
    const bool resident) {
    uint32_t page_crc = LLPS_SESSION_CRC_INIT;

    if (probe == NULL) {
        return;
    }

    page_crc = llps_crc32_update_u32(page_crc, region_id);
    page_crc = llps_crc32_update_u64(page_crc, (uint64_t)page_addr);
    page_crc = llps_crc32_update_u32(page_crc, probe_ok ? 1u : 0u);
    page_crc = llps_crc32_update_u32(page_crc, resident ? 1u : 0u);
    page_crc ^= LLPS_SESSION_CRC_XOROUT;
    probe->page_mix ^= page_crc;
    probe->page_sum += page_crc;

    ++probe->pages_checked;
    if (!probe_ok) {
        ++probe->probe_failures;
    } else if (resident) {
        ++probe->resident_pages;
    } else {
        ++probe->nonresident_pages;
    }
}

void llps_tmr_physical_frame_probe_init(
    llps_tmr_physical_frame_probe_t * const probe) {
    if (probe != NULL) {
        (void)memset(probe, 0, sizeof(*probe));
    }
}

uint64_t llps_abs_u64_distance(const uint64_t lhs, const uint64_t rhs) {
    return (lhs >= rhs) ? (lhs - rhs) : (rhs - lhs);
}

bool llps_tmr_physical_frame_pair_index(const uint32_t lhs_bank_id,
                                        const uint32_t rhs_bank_id,
                                        size_t * const out_index) {
    uint32_t low = lhs_bank_id;
    uint32_t high = rhs_bank_id;

    if ((out_index == NULL) ||
        (lhs_bank_id >= LLPS_SESSION_TMR_BANK_COUNT) ||
        (rhs_bank_id >= LLPS_SESSION_TMR_BANK_COUNT) ||
        (lhs_bank_id == rhs_bank_id)) {
        return false;
    }

    if (low > high) {
        low = rhs_bank_id;
        high = lhs_bank_id;
    }

    if ((low == 0u) && (high == 1u)) {
        *out_index = 0u;
        return true;
    }
    if ((low == 0u) && (high == 2u)) {
        *out_index = 1u;
        return true;
    }
    if ((low == 1u) && (high == 2u)) {
        *out_index = 2u;
        return true;
    }

    return false;
}

void llps_tmr_physical_frame_probe_note_distance(
    llps_tmr_physical_frame_probe_t * const probe,
    const uint32_t lhs_bank_id,
    const uint32_t rhs_bank_id,
    const uint64_t distance) {
    size_t pair_index = 0u;
    uint32_t pair_bit = 0u;

    if ((probe == NULL) ||
        !llps_tmr_physical_frame_pair_index(lhs_bank_id,
                                            rhs_bank_id,
                                            &pair_index) ||
        (pair_index >= LLPS_TMR_PHYSICAL_FRAME_PAIR_COUNT)) {
        return;
    }

    pair_bit = 1u << (uint32_t)pair_index;
    if (((probe->pair_coverage_mask & pair_bit) == 0u) ||
        (distance < probe->pair_min_distances[pair_index])) {
        probe->pair_min_distances[pair_index] = distance;
    }
    probe->pair_coverage_mask |= pair_bit;

    if ((!probe->min_cross_bank_distance_seen) ||
        (distance < probe->min_cross_bank_distance)) {
        probe->min_cross_bank_distance = distance;
        probe->min_cross_bank_distance_seen = true;
    }
}

uint64_t llps_tmr_physical_frame_required_distance_pages(void) {
    const size_t page_size = llps_tmr_platform_page_size();
    const uint64_t min_bytes = (uint64_t)LLPS_SESSION_TMR_MIN_DISTANCE_BYTES;
    uint64_t pages = 1u;

    if (page_size != 0u) {
        const uint64_t page_size_u64 = (uint64_t)page_size;

        pages = (min_bytes + page_size_u64 - 1u) / page_size_u64;
    }

    return (pages == 0u) ? 1u : pages;
}

bool llps_tmr_physical_frame_probe_seen(
    const llps_tmr_physical_frame_probe_t * const probe,
    const uint64_t pfn) {
    if (probe == NULL) {
        return false;
    }

    for (size_t i = 0u; i < probe->observed_pfn_count; ++i) {
        if (probe->observed_pfns[i] == pfn) {
            return true;
        }
    }

    return false;
}

static void llps_tmr_physical_frame_probe_note_cross_bank_distances(
    llps_tmr_physical_frame_probe_t * const probe,
    const uint32_t bank_id,
    const uint64_t pfn) {
    if ((probe == NULL) || (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return;
    }

    for (size_t i = 0u; i < probe->observed_pfn_count; ++i) {
        if (probe->observed_pfn_bank_ids[i] != bank_id) {
            const uint64_t distance =
                llps_abs_u64_distance(probe->observed_pfns[i], pfn);

            llps_tmr_physical_frame_probe_note_distance(
                probe,
                probe->observed_pfn_bank_ids[i],
                bank_id,
                distance);
        }
    }
}

static bool llps_tmr_physical_frame_probe_remember_pfn(
    llps_tmr_physical_frame_probe_t * const probe,
    const uint32_t bank_id,
    const uint64_t pfn) {
    if ((probe == NULL) || (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return false;
    }
    if (llps_tmr_physical_frame_probe_seen(probe, pfn)) {
        return true;
    }
    if (probe->observed_pfn_count < LLPS_TMR_PHYSICAL_FRAME_MAX_PAGES) {
        probe->observed_pfns[probe->observed_pfn_count] = pfn;
        probe->observed_pfn_bank_ids[probe->observed_pfn_count] = bank_id;
        ++probe->observed_pfn_count;
    } else {
        ++probe->probe_failures;
    }
    return false;
}

static uint32_t llps_tmr_physical_frame_page_crc(
    const uint32_t region_id,
    const uint32_t bank_id,
    const uintptr_t page_addr,
    const bool effective_probe_ok,
    const uint64_t pfn) {
    uint32_t page_crc = LLPS_SESSION_CRC_INIT;

    page_crc = llps_crc32_update_u32(page_crc, region_id);
    page_crc = llps_crc32_update_u32(page_crc, bank_id);
    page_crc = llps_crc32_update_u64(page_crc, (uint64_t)page_addr);
    page_crc = llps_crc32_update_u32(page_crc, effective_probe_ok ? 1u : 0u);
    page_crc = llps_crc32_update_u64(page_crc, effective_probe_ok ? pfn : 0u);
    page_crc ^= LLPS_SESSION_CRC_XOROUT;
    return page_crc;
}

static void llps_tmr_physical_frame_probe_note_outcome(
    llps_tmr_physical_frame_probe_t * const probe,
    const bool effective_probe_ok,
    const bool duplicate) {
    if (probe == NULL) {
        return;
    }

    ++probe->pages_checked;
    if (!effective_probe_ok) {
        ++probe->probe_failures;
    } else if (duplicate) {
        ++probe->duplicate_pages;
    } else {
        ++probe->distinct_pages;
    }
}

void llps_tmr_physical_frame_probe_note_page(
    llps_tmr_physical_frame_probe_t * const probe,
    const uint32_t region_id,
    const uint32_t bank_id,
    const uintptr_t page_addr,
    const bool probe_ok,
    const uint64_t pfn) {
    bool duplicate = false;
    const bool bank_ok = bank_id < LLPS_SESSION_TMR_BANK_COUNT;
    const bool effective_probe_ok = probe_ok && bank_ok;
    uint32_t page_crc = 0u;

    if (probe == NULL) {
        return;
    }

    if (effective_probe_ok) {
        llps_tmr_physical_frame_probe_note_cross_bank_distances(probe,
                                                                bank_id,
                                                                pfn);
        duplicate = llps_tmr_physical_frame_probe_remember_pfn(probe,
                                                               bank_id,
                                                               pfn);
    }

    page_crc = llps_tmr_physical_frame_page_crc(region_id,
                                                bank_id,
                                                page_addr,
                                                effective_probe_ok,
                                                pfn);
    probe->page_mix ^= page_crc;
    probe->page_sum += page_crc;
    llps_tmr_physical_frame_probe_note_outcome(probe,
                                               effective_probe_ok,
                                               duplicate);
}
