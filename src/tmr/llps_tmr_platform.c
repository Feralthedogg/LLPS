/**
 * @file src/tmr/llps_tmr_platform.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_platform.h"

#include "llps_numa.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

size_t llps_tmr_platform_page_size(void) {
#if defined(_SC_PAGESIZE)
    const long page_size = sysconf(_SC_PAGESIZE);

    if (page_size > 0L) {
        return (size_t)page_size;
    }
#endif

    return LLPS_TMR_PLATFORM_FALLBACK_PAGE_SIZE;
}

bool llps_tmr_platform_page_is_resident(const void * const page_addr,
                                        const size_t page_size,
                                        const bool override_enabled,
                                        const bool override_resident,
                                        bool * const out_resident) {
    if ((page_addr == NULL) || (page_size == 0u) || (out_resident == NULL)) {
        return false;
    }

    if (override_enabled) {
        *out_resident = override_resident;
        return true;
    }

#if defined(__linux__) && defined(SYS_mincore)
    {
        unsigned char vec[1] = { 0u };
        const long result = syscall(SYS_mincore, page_addr, page_size, vec);

        if (result != 0L) {
            return false;
        }

        *out_resident = (vec[0] & 1u) != 0u;
        return true;
    }
#else
    return false;
#endif
}

bool llps_tmr_platform_page_physical_frame(const uintptr_t page_addr,
                                           const bool synthetic_enabled,
                                           const bool override_alias,
                                           uint64_t * const out_pfn) {
    const size_t page_size = llps_tmr_platform_page_size();

    if ((page_addr == 0u) || (out_pfn == NULL)) {
        return false;
    }

    if (synthetic_enabled) {
        if (override_alias) {
            *out_pfn = 1u;
        } else {
            *out_pfn = (uint64_t)(page_addr / (uintptr_t)page_size);
        }
        return *out_pfn != 0u;
    }

#if defined(__linux__)
    {
        const uint64_t page_index =
            (uint64_t)(page_addr / (uintptr_t)page_size);
        const uint64_t offset = page_index * LLPS_PAGEMAP_ENTRY_BYTES;
        uint8_t raw[LLPS_PAGEMAP_ENTRY_BYTES];
        uint64_t entry = 0u;
        int fd = -1;
        ssize_t n = 0;

        (void)memset(raw, 0, sizeof(raw));
        fd = open(LLPS_PROC_SELF_PAGEMAP_PATH, O_RDONLY);
        if (fd < 0) {
            return false;
        }
        n = pread(fd, raw, sizeof(raw), (off_t)offset);
        if (close(fd) != 0) {
            return false;
        }
        if (n != (ssize_t)sizeof(raw)) {
            return false;
        }

        for (size_t i = 0u; i < sizeof(raw); ++i) {
            entry |= ((uint64_t)raw[i]) << (8u * i);
        }
        if ((entry & LLPS_PAGEMAP_PRESENT_MASK) == 0u) {
            return false;
        }

        *out_pfn = entry & LLPS_PAGEMAP_PFN_MASK;
        return *out_pfn != 0u;
    }
#else
    return false;
#endif
}

static bool llps_tmr_platform_domain_override_value(
    const uint32_t bank_id,
    const bool override_enabled,
    const uint32_t override_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_domain_id) {
    if ((out_domain_id == NULL) ||
        (!override_enabled) ||
        (override_domains == NULL) ||
        (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return false;
    }

    *out_domain_id = override_domains[bank_id];
    return true;
}

bool llps_tmr_platform_page_domain(
    const uint32_t bank_id,
    const void * const page_addr,
    const bool override_enabled,
    const uint32_t override_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_domain_id) {
    if ((page_addr == NULL) || (out_domain_id == NULL)) {
        return false;
    }

    if (llps_tmr_platform_domain_override_value(bank_id,
                                                override_enabled,
                                                override_domains,
                                                out_domain_id)) {
        return true;
    }

#if defined(__linux__) && defined(SYS_move_pages)
    {
        void *pages[1];
        int status[1] = { -1 };
        long rc = 0L;

        pages[0] = (void *)(uintptr_t)page_addr;
        rc = syscall(SYS_move_pages,
                     0L,
                     1UL,
                     pages,
                     NULL,
                     status,
                     0L);
        if ((rc != 0L) || (status[0] < 0)) {
            return false;
        }

        *out_domain_id = (uint32_t)status[0];
        return true;
    }
#else
    return false;
#endif
}

bool llps_tmr_platform_bind_region_to_memory_domain(
    const uint32_t bank_id,
    const void * const addr,
    const size_t len,
    const uint32_t domain_id,
    const bool override_enabled,
    const uint32_t override_domains[LLPS_SESSION_TMR_BANK_COUNT]) {
    uint32_t override_domain = 0u;

    if ((addr == NULL) || (len == 0u) ||
        (bank_id >= LLPS_SESSION_TMR_BANK_COUNT)) {
        return false;
    }

    if (llps_tmr_platform_domain_override_value(bank_id,
                                                override_enabled,
                                                override_domains,
                                                &override_domain)) {
        return override_domain == domain_id;
    }

#if defined(__linux__) && defined(SYS_mbind) && defined(LLPS_MPOL_BIND)
    {
        unsigned long node_mask[LLPS_NUMA_NODE_MASK_WORDS];
        unsigned long maxnode = 0UL;
        const bool mask_ok =
            llps_numa_make_single_node_mask(domain_id,
                                            node_mask,
                                            &maxnode);

        if (!mask_ok) {
            return false;
        }

        return syscall(SYS_mbind,
                       addr,
                       len,
                       LLPS_MPOL_BIND,
                       node_mask,
                       maxnode,
                       0UL) == 0L;
    }
#else
    return false;
#endif
}
