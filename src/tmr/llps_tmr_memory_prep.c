/**
 * @file src/tmr/llps_tmr_memory_prep.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_memory_prep.h"

#include "llps.h"
#include "llps_guard.h"
#include "llps_internal.h"
#include "llps_runtime_latches.h"
#include "llps_safety_counters.h"
#include "llps_tmr_memory_regions.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#if defined(LLPS_TEST_HOOKS) && defined(mlock)
int __wrap_mlock(const void *addr, size_t len);
#endif

#if defined(LLPS_TEST_HOOKS) && defined(mlockall)
int __wrap_mlockall(int flags);
#endif

static bool llps_lock_tmr_region(const void * const addr, const size_t len) {
    if ((addr == NULL) || (len == 0u)) {
        return false;
    }

    return mlock(addr, len) == 0;
}

bool llps_lock_process_memory(void) {
#if defined(MCL_CURRENT) && defined(MCL_FUTURE)
    const int flags = MCL_CURRENT | MCL_FUTURE;
    const bool locked = mlockall(flags) == 0;

    llps_process_memory_locked_set(locked);
    if (!locked) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(process_memory_lock_failures);
    }

    return locked;
#else
    llps_process_memory_locked_set(false);
    LLPS_MEMORY_SAFETY_COUNTER_INC(process_memory_lock_failures);
    return false;
#endif
}

bool llps_lock_tmr_memory(void) {
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool locked = true;

    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        if (!llps_lock_tmr_region(regions[i].addr, regions[i].len)) {
            locked = false;
        }
    }

    llps_tmr_memory_locked_set(locked);
    if (!locked) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_lock_failures);
    }

    return locked;
}

static bool llps_prefault_tmr_region(void * const addr,
                                     const size_t len,
                                     uint64_t * const pages_ref) {
    volatile uint8_t *bytes = (volatile uint8_t *)addr;
    size_t offset = 0u;

    if ((addr == NULL) || (len == 0u) || (pages_ref == NULL)) {
        return false;
    }

    for (size_t step = 0u;
         (offset < len) && (step < LLPS_MAX_CLIENTS);
         ++step) {
        const uint8_t value = bytes[offset];

        bytes[offset] = value;
        ++(*pages_ref);

        if ((len - offset) <= LLPS_SESSION_TMR_ALIGNMENT_BYTES) {
            break;
        }
        offset += LLPS_SESSION_TMR_ALIGNMENT_BYTES;
    }

    {
        const uint8_t tail_value = bytes[len - 1u];

        bytes[len - 1u] = tail_value;
    }
    return true;
}

bool llps_prefault_tmr_memory(void) {
    llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT];
    bool prefaulted = true;
    uint64_t pages = 0u;

    llps_tmr_memory_regions_snapshot(regions);
    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        if (!llps_prefault_tmr_region(regions[i].addr,
                                      regions[i].len,
                                      &pages)) {
            prefaulted = false;
        }
    }

    llps_tmr_memory_prefaulted_set(prefaulted && (pages != 0u));
    llps_tmr_memory_prefault_pages_set(pages);
    if (!llps_guarded_bool_read(g_tmr_memory_prefaulted,
                                g_tmr_memory_prefaulted_inverse)) {
        LLPS_MEMORY_SAFETY_COUNTER_INC(tmr_memory_prefault_failures);
    }

    return llps_guarded_bool_read(g_tmr_memory_prefaulted,
                                  g_tmr_memory_prefaulted_inverse);
}
