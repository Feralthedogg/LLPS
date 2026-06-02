/**
 * @file src/internal/llps_tmr_platform.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_PLATFORM_H
#define LLPS_TMR_PLATFORM_H

#include "llps.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(__linux__) && !defined(LLPS_MPOL_BIND)
#define LLPS_MPOL_BIND                    (2L)
#endif

#if defined(LLPS_TEST_HOOKS) || \
    (defined(__linux__) && defined(SYS_move_pages))
#define LLPS_TMR_MEMORY_DOMAIN_PROBE_SUPPORTED (1)
#else
#define LLPS_TMR_MEMORY_DOMAIN_PROBE_SUPPORTED (0)
#endif

#if defined(LLPS_TEST_HOOKS) || \
    (defined(__linux__) && defined(SYS_mbind) && defined(LLPS_MPOL_BIND))
#define LLPS_TMR_MEMORY_DOMAIN_BIND_SUPPORTED  (1)
#else
#define LLPS_TMR_MEMORY_DOMAIN_BIND_SUPPORTED  (0)
#endif

#if defined(LLPS_TEST_HOOKS) || \
    (defined(__linux__) && defined(SYS_mincore))
#define LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED (1)
#else
#define LLPS_TMR_MEMORY_RESIDENCY_PROBE_SUPPORTED (0)
#endif

#if defined(LLPS_TEST_HOOKS) || defined(__linux__)
#define LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED (1)
#else
#define LLPS_TMR_PHYSICAL_FRAME_PROBE_SUPPORTED (0)
#endif

#define LLPS_PROC_SELF_PAGEMAP_PATH       "/proc/self/pagemap"
#define LLPS_PAGEMAP_ENTRY_BYTES          (8u)
#define LLPS_PAGEMAP_PRESENT_MASK         (1ULL << 63u)
#define LLPS_PAGEMAP_PFN_MASK             ((1ULL << 55u) - 1ULL)
#define LLPS_TMR_PHYSICAL_FRAME_MAX_PAGES (256u)
#define LLPS_TMR_PHYSICAL_FRAME_PAIR_COUNT (3u)
#define LLPS_TMR_PHYSICAL_FRAME_PAIR_MASK_ALL (0x7u)
#define LLPS_TMR_MEMORY_DOMAIN_REGION_COUNT (12u)
#define LLPS_TMR_MEMORY_DOMAIN_REGION_MASK_ALL (0x0fffu)
#define LLPS_TMR_PLATFORM_FALLBACK_PAGE_SIZE (16384u)

/** @brief Return the system page size used by TMR probes. */
size_t llps_tmr_platform_page_size(void);
/** @brief Query or override residency for one page. */
bool llps_tmr_platform_page_is_resident(const void *page_addr,
                                        size_t page_size,
                                        bool override_enabled,
                                        bool override_resident,
                                        bool *out_resident);
/** @brief Resolve or synthesize the physical frame number for one page. */
bool llps_tmr_platform_page_physical_frame(uintptr_t page_addr,
                                           bool synthetic_enabled,
                                           bool override_alias,
                                           uint64_t *out_pfn);
/** @brief Resolve or override the memory-domain ID for one page. */
bool llps_tmr_platform_page_domain(
    uint32_t bank_id,
    const void *page_addr,
    bool override_enabled,
    const uint32_t override_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t *out_domain_id);
/** @brief Bind a memory region to the requested platform memory domain. */
bool llps_tmr_platform_bind_region_to_memory_domain(
    uint32_t bank_id,
    const void *addr,
    size_t len,
    uint32_t domain_id,
    bool override_enabled,
    const uint32_t override_domains[LLPS_SESSION_TMR_BANK_COUNT]);

#endif /* LLPS_TMR_PLATFORM_H */
