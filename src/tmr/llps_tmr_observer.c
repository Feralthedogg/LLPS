/**
 * @file src/tmr/llps_tmr_observer.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_observer.h"

#include "llps_crc.h"
#include "llps_domain.h"
#include "llps_internal.h"
#include "llps_runtime_latches.h"
#include "llps_safety_counters.h"
#include "llps_tmr_memory_regions.h"
#include "llps_tmr_platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#if defined(LLPS_TEST_HOOKS) && defined(madvise)
int __wrap_madvise(void *addr, size_t len, int advice);
#endif

#if !defined(LLPS_MADV_DONTDUMP) && defined(MADV_DONTDUMP)
#define LLPS_MADV_DONTDUMP                 MADV_DONTDUMP
#endif

#if !defined(LLPS_MADV_NOHUGEPAGE) && defined(MADV_NOHUGEPAGE)
#define LLPS_MADV_NOHUGEPAGE               MADV_NOHUGEPAGE
#endif

#if !defined(LLPS_MADV_UNMERGEABLE) && defined(MADV_UNMERGEABLE)
#define LLPS_MADV_UNMERGEABLE              MADV_UNMERGEABLE
#endif

#if defined(LLPS_MADV_DONTDUMP) || \
    defined(LLPS_MADV_NOHUGEPAGE) || \
    defined(LLPS_MADV_UNMERGEABLE)
#define LLPS_TMR_MADVISE_SUPPORTED         (1)
#else
#define LLPS_TMR_MADVISE_SUPPORTED         (0)
#endif

bool g_tmr_memory_domain_probe_override_enabled = false;
uint32_t
    g_tmr_memory_domain_probe_override_domains[LLPS_SESSION_TMR_BANK_COUNT] =
        { 0u, 0u, 0u };
bool g_tmr_memory_residency_probe_override_enabled = false;
bool g_tmr_memory_residency_probe_override_resident = true;
bool g_tmr_physical_frame_probe_synthetic_enabled = false;
bool g_tmr_physical_frame_probe_override_alias = false;
static bool g_tmr_software_memory_observation_configured = false;

typedef struct {
    uint64_t pages_checked;
    uint64_t mismatch_count;
    uint64_t probe_failures;
    uint32_t region_coverage_mask;
    uint32_t domain_mix;
    uint64_t domain_sum;
    uint32_t observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
    bool observed_domain_seen[LLPS_SESSION_TMR_BANK_COUNT];
    bool observed_domain_mixed[LLPS_SESSION_TMR_BANK_COUNT];
} llps_tmr_memory_domain_probe_t;

void llps_configure_tmr_software_memory_observation(
    const bool enabled,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (!enabled) {
        if (g_tmr_software_memory_observation_configured) {
            g_tmr_memory_domain_probe_override_enabled = false;
            for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
                g_tmr_memory_domain_probe_override_domains[i] = 0u;
            }
            g_tmr_memory_residency_probe_override_enabled = false;
            g_tmr_memory_residency_probe_override_resident = true;
            g_tmr_physical_frame_probe_synthetic_enabled = false;
            g_tmr_physical_frame_probe_override_alias = false;
            g_tmr_software_memory_observation_configured = false;
        }
        return;
    }

    g_tmr_memory_domain_probe_override_enabled = true;
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        g_tmr_memory_domain_probe_override_domains[i] =
            (domain_ids != NULL) ? domain_ids[i] : 0u;
    }
    g_tmr_memory_residency_probe_override_enabled = true;
    g_tmr_memory_residency_probe_override_resident = true;
    g_tmr_physical_frame_probe_synthetic_enabled = true;
    g_tmr_physical_frame_probe_override_alias = false;
    g_tmr_software_memory_observation_configured = true;
}

#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED || \
    LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
static size_t llps_system_page_size(void) {
    return llps_tmr_platform_page_size();
}
#endif

#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED
static bool llps_tmr_page_is_resident(const void * const page_addr,
                                      const size_t page_size,
                                      bool * const out_resident) {
    bool override_enabled = g_tmr_memory_residency_probe_override_enabled;
    bool override_resident = g_tmr_memory_residency_probe_override_resident;

    if ((page_addr == NULL) || (page_size == 0u) || (out_resident == NULL)) {
        return false;
    }

#if defined(LLPS_TEST_HOOKS)
    if (!override_enabled) {
        override_enabled = true;
        override_resident = true;
    }
#endif

    return llps_tmr_platform_page_is_resident(page_addr,
                                             page_size,
                                             override_enabled,
                                             override_resident,
                                             out_resident);
}

static bool llps_probe_tmr_region_memory_residency(
    const uint32_t region_id,
    const void * const addr,
    const size_t len,
    llps_tmr_memory_residency_probe_t * const probe) {
    const uintptr_t base = (uintptr_t)addr;
    const size_t page_size = llps_system_page_size();
    uintptr_t first_page = 0u;
    uintptr_t last_byte = 0u;
    uintptr_t page = 0u;

    if ((addr == NULL) || (len == 0u) || (probe == NULL) ||
        (page_size == 0u)) {
        return false;
    }

    last_byte = base + ((uintptr_t)len - 1u);
    if (last_byte < base) {
        return false;
    }
    first_page = base - (base % (uintptr_t)page_size);
    page = first_page;

    for (uint64_t page_scan = 0u; page_scan < UINT64_MAX; ++page_scan) {
        bool resident = false;
        const void * const page_addr = (const void *)page;
        const bool probe_ok =
            llps_tmr_page_is_resident(page_addr, page_size, &resident);

        llps_tmr_memory_residency_probe_note_page(probe,
                                                  region_id,
                                                  page,
                                                  probe_ok,
                                                  resident);
        if ((last_byte - page) < (uintptr_t)page_size) {
            break;
        }
        page += (uintptr_t)page_size;
    }

    return true;
}
#endif

static bool llps_probe_tmr_memory_residency_software_override(
    bool * const out_resident,
    uint64_t * const out_resident_pages,
    uint32_t * const out_residency_fingerprint) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;
    static const char source_label[] = "software-tmr-residency";
    const uint64_t pages_checked =
        (uint64_t)LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT;

    if (!g_tmr_software_memory_observation_configured) {
        return false;
    }

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 source_label,
                                                 sizeof(source_label));
    fingerprint = llps_crc32_update_u32(fingerprint, 1u);
    fingerprint = llps_crc32_update_u64(fingerprint, pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, 0u);
    *out_resident = true;
    *out_resident_pages = pages_checked;
    *out_residency_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    return true;
}

static void llps_probe_tmr_memory_residency_publish_probe(
    const llps_tmr_memory_residency_probe_t * const probe,
    const bool regions_probed,
    const bool count_failures,
    bool * const out_resident,
    uint64_t * const out_resident_pages,
    uint32_t * const out_residency_fingerprint) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if ((probe == NULL) || (out_resident == NULL) ||
        (out_resident_pages == NULL) || (out_residency_fingerprint == NULL)) {
        return;
    }

    fingerprint = llps_crc32_update_u32(fingerprint, regions_probed ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->resident_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->nonresident_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->probe_failures);
    fingerprint = llps_crc32_update_u32(fingerprint, probe->page_mix);
    fingerprint = llps_crc32_update_u32(fingerprint, probe->page_sum);
    *out_resident_pages = probe->resident_pages;
    *out_residency_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    *out_resident = regions_probed &&
                    (probe->pages_checked != 0u) &&
                    (probe->resident_pages == probe->pages_checked) &&
                    (probe->nonresident_pages == 0u) &&
                    (probe->probe_failures == 0u);
    if ((!*out_resident) && count_failures) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_residency_failures);
    }
}

static void llps_probe_tmr_memory_residency_internal(
    bool * const out_resident,
    uint64_t * const out_resident_pages,
    uint32_t * const out_residency_fingerprint,
    const bool count_failures) {
    llps_tmr_memory_residency_probe_t probe;
#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool regions_probed = true;
#endif

    llps_tmr_memory_residency_probe_init(&probe);

    if ((out_resident == NULL) ||
        (out_resident_pages == NULL) ||
        (out_residency_fingerprint == NULL)) {
        return;
    }

    *out_resident = false;
    *out_resident_pages = 0u;
    *out_residency_fingerprint = 0u;

    if (llps_probe_tmr_memory_residency_software_override(
            out_resident,
            out_resident_pages,
            out_residency_fingerprint)) {
        return;
    }

#if LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED
    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        if (!llps_probe_tmr_region_memory_residency(regions[i].region_id,
                                                    regions[i].addr,
                                                    regions[i].len,
                                                    &probe)) {
            regions_probed = false;
        }
    }

    llps_probe_tmr_memory_residency_publish_probe(&probe,
                                                  regions_probed,
                                                  count_failures,
                                                  out_resident,
                                                  out_resident_pages,
                                                  out_residency_fingerprint);
#else
    llps_probe_tmr_memory_residency_publish_probe(&probe,
                                                  false,
                                                  count_failures,
                                                  out_resident,
                                                  out_resident_pages,
                                                  out_residency_fingerprint);
#endif
}

void llps_probe_tmr_memory_residency(
    bool * const out_resident,
    uint64_t * const out_resident_pages,
    uint32_t * const out_residency_fingerprint) {
    llps_probe_tmr_memory_residency_internal(out_resident,
                                             out_resident_pages,
                                             out_residency_fingerprint,
                                             true);
}

void llps_observe_tmr_memory_residency(
    bool * const out_resident,
    uint64_t * const out_resident_pages,
    uint32_t * const out_residency_fingerprint) {
    llps_probe_tmr_memory_residency_internal(out_resident,
                                             out_resident_pages,
                                             out_residency_fingerprint,
                                             false);
}

#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
static bool llps_tmr_page_physical_frame(
    const uintptr_t page_addr,
    uint64_t * const out_pfn) {
#if defined(LLPS_TEST_HOOKS)
    const bool synthetic_enabled = true;
    const bool override_alias = g_tmr_physical_frame_probe_override_alias;
#else
    const bool synthetic_enabled = g_tmr_physical_frame_probe_synthetic_enabled;
    const bool override_alias = false;
#endif

    return llps_tmr_platform_page_physical_frame(page_addr,
                                                 synthetic_enabled,
                                                 override_alias,
                                                 out_pfn);
}

static bool llps_probe_tmr_region_physical_frames(
    const uint32_t region_id,
    const uint32_t bank_id,
    const void * const addr,
    const size_t len,
    llps_tmr_physical_frame_probe_t * const probe) {
    const uintptr_t base = (uintptr_t)addr;
    const size_t page_size = llps_system_page_size();
    uintptr_t first_page = 0u;
    uintptr_t last_byte = 0u;
    uintptr_t page = 0u;

    if ((addr == NULL) || (len == 0u) || (probe == NULL) ||
        (page_size == 0u) ||
        (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return false;
    }

    last_byte = base + ((uintptr_t)len - 1u);
    if (last_byte < base) {
        return false;
    }
    first_page = base - (base % (uintptr_t)page_size);
    page = first_page;

    for (uint64_t page_scan = 0u; page_scan < UINT64_MAX; ++page_scan) {
        uint64_t pfn = 0u;
        const bool probe_ok = llps_tmr_page_physical_frame(page, &pfn);

        llps_tmr_physical_frame_probe_note_page(probe,
                                                region_id,
                                                bank_id,
                                                page,
                                                probe_ok,
                                                pfn);
        if ((last_byte - page) < (uintptr_t)page_size) {
            break;
        }
        page += (uintptr_t)page_size;
    }

    return true;
}
#endif

static void llps_probe_tmr_physical_frames_internal(
    bool * const out_distinct,
    bool * const out_spaced,
    uint64_t * const out_pages,
    uint64_t * const out_probe_failures,
    uint64_t * const out_min_distance,
    uint64_t * const out_required_distance,
    uint64_t * const out_distance_01,
    uint64_t * const out_distance_02,
    uint64_t * const out_distance_12,
    uint32_t * const out_pair_coverage,
    uint32_t * const out_fingerprint,
    const bool count_failures) {
    llps_tmr_physical_frame_probe_t probe;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;
    uint64_t required_distance = 1u;
#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool regions_probed = true;
#endif

    llps_tmr_physical_frame_probe_init(&probe);
#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
    required_distance = llps_tmr_physical_frame_required_distance_pages();
#endif

    if ((out_distinct == NULL) ||
        (out_spaced == NULL) ||
        (out_pages == NULL) ||
        (out_probe_failures == NULL) ||
        (out_min_distance == NULL) ||
        (out_required_distance == NULL) ||
        (out_distance_01 == NULL) ||
        (out_distance_02 == NULL) ||
        (out_distance_12 == NULL) ||
        (out_pair_coverage == NULL) ||
        (out_fingerprint == NULL)) {
        return;
    }

    *out_distinct = false;
    *out_spaced = false;
    *out_pages = 0u;
    *out_probe_failures = 0u;
    *out_min_distance = 0u;
    *out_required_distance = required_distance;
    *out_distance_01 = 0u;
    *out_distance_02 = 0u;
    *out_distance_12 = 0u;
    *out_pair_coverage = 0u;
    *out_fingerprint = 0u;

    if (g_tmr_software_memory_observation_configured) {
        static const char source_label[] = "software-tmr-physical-frames";
        const uint64_t pages =
            (uint64_t)LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT;
        const uint64_t distance = required_distance;

        fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                     source_label,
                                                     sizeof(source_label));
        fingerprint = llps_crc32_update_u32(fingerprint, 1u);
        fingerprint = llps_crc32_update_u64(fingerprint, pages);
        fingerprint = llps_crc32_update_u64(fingerprint, pages);
        fingerprint = llps_crc32_update_u64(fingerprint, 0u);
        fingerprint = llps_crc32_update_u64(fingerprint, 0u);
        fingerprint = llps_crc32_update_u64(fingerprint, distance);
        fingerprint = llps_crc32_update_u32(
            fingerprint,
            LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL);
        fingerprint = llps_crc32_update_u64(fingerprint, distance);
        fingerprint = llps_crc32_update_u64(fingerprint, distance);
        fingerprint = llps_crc32_update_u64(fingerprint, distance);

        *out_distinct = true;
        *out_spaced = true;
        *out_pages = pages;
        *out_probe_failures = 0u;
        *out_min_distance = distance;
        *out_required_distance = required_distance;
        *out_distance_01 = distance;
        *out_distance_02 = distance;
        *out_distance_12 = distance;
        *out_pair_coverage = LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL;
        *out_fingerprint =
            llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
        return;
    }

#if LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED
    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        if (!llps_probe_tmr_region_physical_frames(regions[i].region_id,
                                                   regions[i].bank_id,
                                                   regions[i].addr,
                                                   regions[i].len,
                                                   &probe)) {
            regions_probed = false;
        }
    }

    fingerprint = llps_crc32_update_u32(fingerprint, regions_probed ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.distinct_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.duplicate_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.probe_failures);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe.min_cross_bank_distance_seen ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        probe.min_cross_bank_distance);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        probe.pair_coverage_mask);
    for (size_t i = 0u; i < LLPS_TMR_PHYSICAL_FRAME_PAIR_COUNT; ++i) {
        fingerprint = llps_crc32_update_u64(fingerprint,
                                            probe.pair_min_distances[i]);
    }
    fingerprint = llps_crc32_update_u64(fingerprint, required_distance);
    fingerprint = llps_crc32_update_u32(fingerprint, probe.page_mix);
    fingerprint = llps_crc32_update_u32(fingerprint, probe.page_sum);

    *out_pages = probe.distinct_pages;
    *out_probe_failures = probe.probe_failures;
    *out_min_distance =
        probe.min_cross_bank_distance_seen ?
        probe.min_cross_bank_distance :
        0u;
    *out_distance_01 = probe.pair_min_distances[0];
    *out_distance_02 = probe.pair_min_distances[1];
    *out_distance_12 = probe.pair_min_distances[2];
    *out_pair_coverage = probe.pair_coverage_mask;
    *out_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    *out_distinct = regions_probed &&
                    (probe.pages_checked != 0u) &&
                    (probe.distinct_pages == probe.pages_checked) &&
                    (probe.duplicate_pages == 0u) &&
                    (probe.probe_failures == 0u);
    *out_spaced = *out_distinct &&
                  ((probe.pair_coverage_mask &
                    LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) ==
                   LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL) &&
                  (probe.min_cross_bank_distance >= required_distance);
    if (count_failures && (!*out_distinct || !*out_spaced)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_physical_frame_faults);
    }
#else
    fingerprint = llps_crc32_update_u32(fingerprint, 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.distinct_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.duplicate_pages);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.probe_failures);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe.min_cross_bank_distance_seen ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        probe.min_cross_bank_distance);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        probe.pair_coverage_mask);
    for (size_t i = 0u; i < LLPS_TMR_PHYSICAL_FRAME_PAIR_COUNT; ++i) {
        fingerprint = llps_crc32_update_u64(fingerprint,
                                            probe.pair_min_distances[i]);
    }
    fingerprint = llps_crc32_update_u64(fingerprint, required_distance);
    fingerprint = llps_crc32_update_u32(fingerprint, probe.page_mix);
    fingerprint = llps_crc32_update_u32(fingerprint, probe.page_sum);

    *out_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    if (count_failures) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_physical_frame_faults);
    }
#endif
}

void llps_probe_tmr_physical_frames(
    bool * const out_distinct,
    bool * const out_spaced,
    uint64_t * const out_pages,
    uint64_t * const out_probe_failures,
    uint64_t * const out_min_distance,
    uint64_t * const out_required_distance,
    uint64_t * const out_distance_01,
    uint64_t * const out_distance_02,
    uint64_t * const out_distance_12,
    uint32_t * const out_pair_coverage,
    uint32_t * const out_fingerprint) {
    llps_probe_tmr_physical_frames_internal(out_distinct,
                                            out_spaced,
                                            out_pages,
                                            out_probe_failures,
                                            out_min_distance,
                                            out_required_distance,
                                            out_distance_01,
                                            out_distance_02,
                                            out_distance_12,
                                            out_pair_coverage,
                                            out_fingerprint,
                                            true);
}

void llps_observe_tmr_physical_frames(
    bool * const out_distinct,
    bool * const out_spaced,
    uint64_t * const out_pages,
    uint64_t * const out_probe_failures,
    uint64_t * const out_min_distance,
    uint64_t * const out_required_distance,
    uint64_t * const out_distance_01,
    uint64_t * const out_distance_02,
    uint64_t * const out_distance_12,
    uint32_t * const out_pair_coverage,
    uint32_t * const out_fingerprint) {
    llps_probe_tmr_physical_frames_internal(out_distinct,
                                            out_spaced,
                                            out_pages,
                                            out_probe_failures,
                                            out_min_distance,
                                            out_required_distance,
                                            out_distance_01,
                                            out_distance_02,
                                            out_distance_12,
                                            out_pair_coverage,
                                            out_fingerprint,
                                            false);
}

bool llps_config_requests_physical_memory_separation(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           ((cfg->platform_safety_flags & LLPS_PLATFORM_EVIDENCE_PHYS_SEP) != 0u);
}

static bool llps_config_uses_software_memory_domains(
    const llps_yml_config_t * const cfg) {
    return (cfg != NULL) &&
           (cfg->software_numa_enabled != 0u) &&
           (cfg->platform_evidence_mode != LLPS_PLATFORM_EVIDENCE_MODE_REAL);
}

static void llps_tmr_memory_domain_probe_init(
    llps_tmr_memory_domain_probe_t * const probe) {
    if (probe != NULL) {
        (void)memset(probe, 0, sizeof(*probe));
        for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            probe->observed_domain_ids[i] = LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;
        }
    }
}

#if LLPS_TMR_MEMORY_DOMAIN_PROBE_SUPPORTED
static void llps_tmr_memory_domain_probe_note_page(
    llps_tmr_memory_domain_probe_t * const probe,
    const uint32_t bank_id,
    const uint32_t observed_domain_id) {
    if ((probe == NULL) || (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return;
    }

    if (!probe->observed_domain_seen[bank_id]) {
        probe->observed_domain_ids[bank_id] = observed_domain_id;
        probe->observed_domain_seen[bank_id] = true;
    } else if (probe->observed_domain_ids[bank_id] != observed_domain_id) {
        probe->observed_domain_ids[bank_id] =
            LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;
        probe->observed_domain_mixed[bank_id] = true;
    } else {
        /* Repeated observation confirms the bank-local NUMA domain. */
    }
}

static bool llps_tmr_page_domain(
    const uint32_t bank_id,
    const void * const page_addr,
    uint32_t * const out_domain_id) {
    const bool override_enabled = g_tmr_memory_domain_probe_override_enabled;
    const uint32_t * const override_domains =
        g_tmr_memory_domain_probe_override_domains;

    return llps_tmr_platform_page_domain(bank_id,
                                         page_addr,
                                         override_enabled,
                                         override_domains,
                                         out_domain_id);
}

static uint32_t llps_tmr_memory_domain_page_observation(
    const uint32_t region_id,
    const uint32_t bank_id,
    const size_t len,
    const size_t offset,
    const uint32_t expected_domain_id,
    const uint32_t observed_domain_id,
    const bool probe_ok) {
    uint32_t page_crc = LLPS_SESSION_CRC_INIT;

    page_crc = llps_crc32_update_u32(page_crc, region_id);
    page_crc = llps_crc32_update_u32(page_crc, bank_id);
    page_crc = llps_crc32_update_size(page_crc, len);
    page_crc = llps_crc32_update_size(page_crc, offset);
    page_crc = llps_crc32_update_u32(page_crc, expected_domain_id);
    page_crc = llps_crc32_update_u32(page_crc,
                                     probe_ok ? observed_domain_id : 0u);
    page_crc = llps_crc32_update_u32(page_crc, probe_ok ? 1u : 0u);
    return page_crc ^ LLPS_SESSION_CRC_XOROUT;
}

static void llps_tmr_memory_domain_probe_accumulate_page(
    llps_tmr_memory_domain_probe_t * const probe,
    const uint32_t bank_id,
    const uint32_t expected_domain_id,
    const uint32_t observed_domain_id,
    const bool probe_ok,
    const uint32_t page_observation) {
    if (probe == NULL) {
        return;
    }

    probe->domain_mix ^= page_observation;
    if ((UINT64_MAX - probe->domain_sum) < (uint64_t)page_observation) {
        probe->domain_sum = UINT64_MAX;
        ++probe->probe_failures;
    } else {
        probe->domain_sum += (uint64_t)page_observation;
    }
    ++probe->pages_checked;

    if (!probe_ok) {
        ++probe->probe_failures;
    } else if (observed_domain_id != expected_domain_id) {
        llps_tmr_memory_domain_probe_note_page(probe,
                                               bank_id,
                                               observed_domain_id);
        ++probe->mismatch_count;
    } else {
        llps_tmr_memory_domain_probe_note_page(probe,
                                               bank_id,
                                               observed_domain_id);
    }
}

static bool llps_probe_tmr_region_memory_domain(
    const uint32_t region_id,
    const uint32_t bank_id,
    const void * const addr,
    const size_t len,
    const uint32_t expected_domain_id,
    llps_tmr_memory_domain_probe_t * const probe) {
    uintptr_t base = (uintptr_t)addr;
    size_t offset = 0u;

    if ((addr == NULL) || (len == 0u) ||
        (probe == NULL) ||
        (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return false;
    }
    if (region_id < LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT) {
        probe->region_coverage_mask |= 1u << region_id;
    } else {
        ++probe->probe_failures;
    }

    for (size_t step = 0u;
         (offset < len) && (step < LLPS_MAX_CLIENTS);
         ++step) {
        uint32_t observed_domain_id = 0u;
        const void * const page_addr = (const void *)(base + offset);
        const bool probe_ok =
            llps_tmr_page_domain(bank_id, page_addr, &observed_domain_id);
        const uint32_t page_observation =
            llps_tmr_memory_domain_page_observation(region_id,
                                                    bank_id,
                                                    len,
                                                    offset,
                                                    expected_domain_id,
                                                    observed_domain_id,
                                                    probe_ok);

        llps_tmr_memory_domain_probe_accumulate_page(probe,
                                                     bank_id,
                                                     expected_domain_id,
                                                     observed_domain_id,
                                                     probe_ok,
                                                     page_observation);

        if ((len - offset) <= LLPS_SESSION_TMR_ALIGNMENT_BYTES) {
            break;
        }
        offset += LLPS_SESSION_TMR_ALIGNMENT_BYTES;
    }

    return true;
}
#endif

void llps_probe_tmr_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool * const out_domains_bound,
    uint32_t * const out_observation_fingerprint,
    uint32_t out_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint64_t * const out_pages_checked,
    uint64_t * const out_mismatch_count,
    uint64_t * const out_probe_failures,
    uint32_t * const out_region_coverage) {
    llps_tmr_memory_domain_probe_t probe;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;
    const bool domains_distinct = llps_domain_ids_are_distinct(domain_ids);
    bool observed_domains_complete = true;

    llps_tmr_memory_domain_probe_init(&probe);

    if ((out_domains_bound == NULL) ||
        (out_observation_fingerprint == NULL)) {
        return;
    }

    *out_domains_bound = false;
    *out_observation_fingerprint = 0u;
    if (out_pages_checked != NULL) {
        *out_pages_checked = 0u;
    }
    if (out_mismatch_count != NULL) {
        *out_mismatch_count = 0u;
    }
    if (out_probe_failures != NULL) {
        *out_probe_failures = 0u;
    }
    if (out_region_coverage != NULL) {
        *out_region_coverage = 0u;
    }
    if (out_observed_domain_ids != NULL) {
        for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            out_observed_domain_ids[i] = LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;
        }
    }

#if LLPS_TMR_MEMORY_DOMAIN_PROBE_SUPPORTED
    if (domains_distinct) {
        llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];

        llps_tmr_memory_regions_snapshot(regions);
        for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
            (void)llps_probe_tmr_region_memory_domain(
                regions[i].region_id,
                regions[i].bank_id,
                regions[i].addr,
                regions[i].len,
                domain_ids[regions[i].bank_id],
                &probe);
        }
    }
#endif

    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if ((!probe.observed_domain_seen[i]) ||
            probe.observed_domain_mixed[i] ||
            (probe.observed_domain_ids[i] == LLPS_TMR_MEMORY_DOMAIN_UNKNOWN)) {
            observed_domains_complete = false;
            probe.observed_domain_ids[i] = LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;
        }
        if (out_observed_domain_ids != NULL) {
            out_observed_domain_ids[i] = probe.observed_domain_ids[i];
        }
    }

    fingerprint = llps_crc32_update_u32(fingerprint,
                                        domains_distinct ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        observed_domains_complete ? 1u : 0u);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        const uint32_t domain_id = (domain_ids != NULL) ? domain_ids[i] : 0u;

        fingerprint = llps_crc32_update_u32(fingerprint, domain_id);
    }
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        fingerprint = llps_crc32_update_u32(
            fingerprint,
            probe.observed_domain_ids[i]);
        fingerprint = llps_crc32_update_u32(
            fingerprint,
            probe.observed_domain_seen[i] ? 1u : 0u);
        fingerprint = llps_crc32_update_u32(
            fingerprint,
            probe.observed_domain_mixed[i] ? 1u : 0u);
    }
    fingerprint = llps_crc32_update_u64(fingerprint, probe.pages_checked);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.mismatch_count);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.probe_failures);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        probe.region_coverage_mask);
    fingerprint = llps_crc32_update_u32(fingerprint, probe.domain_mix);
    fingerprint = llps_crc32_update_u64(fingerprint, probe.domain_sum);

#if LLPS_TMR_MEMORY_DOMAIN_PROBE_SUPPORTED
    *out_domains_bound =
        domains_distinct && observed_domains_complete &&
        llps_domain_ids_match(probe.observed_domain_ids, domain_ids) &&
        ((probe.region_coverage_mask &
          LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) ==
         LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL) &&
        (probe.pages_checked != 0u) &&
        (probe.mismatch_count == 0u) && (probe.probe_failures == 0u);
#else
    *out_domains_bound = false;
#endif
    if (out_pages_checked != NULL) {
        *out_pages_checked = probe.pages_checked;
    }
    if (out_mismatch_count != NULL) {
        *out_mismatch_count = probe.mismatch_count;
    }
    if (out_probe_failures != NULL) {
        *out_probe_failures = probe.probe_failures;
    }
    if (out_region_coverage != NULL) {
        *out_region_coverage = probe.region_coverage_mask;
    }
    *out_observation_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
}

void llps_synthesize_tmr_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool * const out_domains_bound,
    uint32_t * const out_observation_fingerprint,
    uint32_t out_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint64_t * const out_pages_checked,
    uint64_t * const out_mismatch_count,
    uint64_t * const out_probe_failures,
    uint32_t * const out_region_coverage) {
    static const char source_label[] = "software-tmr-numa";
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;
    const bool domains_distinct = llps_domain_ids_are_distinct(domain_ids);
    const uint64_t pages_checked =
        domains_distinct ? (uint64_t)LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT : 0u;

    if ((out_domains_bound == NULL) ||
        (out_observation_fingerprint == NULL)) {
        return;
    }

    *out_domains_bound = false;
    *out_observation_fingerprint = 0u;
    if (out_pages_checked != NULL) {
        *out_pages_checked = 0u;
    }
    if (out_mismatch_count != NULL) {
        *out_mismatch_count = 0u;
    }
    if (out_probe_failures != NULL) {
        *out_probe_failures = 0u;
    }
    if (out_region_coverage != NULL) {
        *out_region_coverage = 0u;
    }
    if (out_observed_domain_ids != NULL) {
        for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            out_observed_domain_ids[i] = LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;
        }
    }

    if (!domains_distinct) {
        return;
    }

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 source_label,
                                                 sizeof(source_label));
    fingerprint = llps_crc32_update_u32(fingerprint, 1u);
    fingerprint = llps_crc32_update_u64(fingerprint, pages_checked);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL);
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        fingerprint = llps_crc32_update_u32(fingerprint, domain_ids[i]);
        if (out_observed_domain_ids != NULL) {
            out_observed_domain_ids[i] = domain_ids[i];
        }
    }
    for (uint32_t region_id = 0u;
         region_id < LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT;
         ++region_id) {
        const uint32_t bank_id =
            region_id % (uint32_t)LLPS_SESSION_TMR_BANK_COUNT;
        fingerprint = llps_crc32_update_u32(fingerprint, region_id);
        fingerprint = llps_crc32_update_u32(fingerprint, bank_id);
        fingerprint = llps_crc32_update_u32(fingerprint,
                                            domain_ids[bank_id]);
    }

    *out_domains_bound = true;
    *out_observation_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    if (out_pages_checked != NULL) {
        *out_pages_checked = pages_checked;
    }
    if (out_region_coverage != NULL) {
        *out_region_coverage = LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL;
    }
}

#if LLPS_TMR_MEMORY_DOMAIN_BIND_SUPPORTED
static bool llps_bind_tmr_region_to_memory_domain(
    const uint32_t bank_id,
    const void * const addr,
    const size_t len,
    const uint32_t domain_id) {
    const bool override_enabled = g_tmr_memory_domain_probe_override_enabled;
    const uint32_t * const override_domains =
        g_tmr_memory_domain_probe_override_domains;

    return llps_tmr_platform_bind_region_to_memory_domain(bank_id,
                                                          addr,
                                                          len,
                                                          domain_id,
                                                          override_enabled,
                                                          override_domains);
}
#endif

bool llps_bind_tmr_memory_to_configured_domains(
    const llps_yml_config_t * const cfg) {
#if LLPS_TMR_MEMORY_DOMAIN_BIND_SUPPORTED
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool bound = true;
#endif

    if (!llps_config_requests_physical_memory_separation(cfg)) {
        return true;
    }

    if (!llps_domain_ids_are_distinct(cfg->platform_physical_memory_domains)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
        return false;
    }

    if (llps_config_uses_software_memory_domains(cfg)) {
        return true;
    }

#if LLPS_TMR_MEMORY_DOMAIN_BIND_SUPPORTED
    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        const uint32_t domain_id =
            cfg->platform_physical_memory_domains[regions[i].bank_id];

        if (!llps_bind_tmr_region_to_memory_domain(regions[i].bank_id,
                                                   regions[i].addr,
                                                   regions[i].len,
                                                   domain_id)) {
            bound = false;
        }
    }

    if (!bound) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
    }

    return bound;
#else
    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
    return false;
#endif
}

bool llps_refresh_tmr_memory_domain_binding(
    const llps_yml_config_t * const cfg) {
    bool bound = false;
    uint32_t fingerprint = 0u;
    uint32_t observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];

    llps_tmr_memory_domains_bound_set(false);
    llps_tmr_memory_domain_observation_fingerprint_set(0u);
    llps_tmr_memory_observed_domains_set(NULL);

    if (!llps_config_requests_physical_memory_separation(cfg)) {
        return true;
    }

    if (llps_config_uses_software_memory_domains(cfg)) {
        llps_synthesize_tmr_memory_domains(cfg->platform_physical_memory_domains,
                                           &bound,
                                           &fingerprint,
                                           observed_domain_ids,
                                           NULL,
                                           NULL,
                                           NULL,
                                           NULL);
    } else {
        llps_probe_tmr_memory_domains(cfg->platform_physical_memory_domains,
                                      &bound,
                                      &fingerprint,
                                      observed_domain_ids,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL);
    }
    llps_tmr_memory_domains_bound_set(bound);
    llps_tmr_memory_domain_observation_fingerprint_set(fingerprint);
    llps_tmr_memory_observed_domains_set(observed_domain_ids);
    if (!bound) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_domain_bind_failures);
    }

    return bound;
}

#if LLPS_TMR_MADVISE_SUPPORTED
static bool llps_harden_tmr_region(void * const addr, const size_t len) {
    bool hardened = true;

    if ((addr == NULL) || (len == 0u)) {
        return false;
    }

#if defined(LLPS_MADV_DONTDUMP)
    if (madvise(addr, len, LLPS_MADV_DONTDUMP) != 0) {
        hardened = false;
    }
#endif

#if defined(LLPS_MADV_NOHUGEPAGE)
    if (madvise(addr, len, LLPS_MADV_NOHUGEPAGE) != 0) {
        hardened = false;
    }
#endif

#if defined(LLPS_MADV_UNMERGEABLE)
    if (madvise(addr, len, LLPS_MADV_UNMERGEABLE) != 0) {
        hardened = false;
    }
#endif

    return hardened;
}
#endif

bool llps_harden_tmr_memory(void) {
#if LLPS_TMR_MADVISE_SUPPORTED
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool hardened = true;

    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        if (!llps_harden_tmr_region(regions[i].addr, regions[i].len)) {
            hardened = false;
        }
    }

    llps_tmr_memory_hardened_set(hardened);
    if (!hardened) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_harden_failures);
    }

    return hardened;
#else
    llps_tmr_memory_hardened_set(false);
    LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_harden_failures);
    return false;
#endif
}
