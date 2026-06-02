/**
 * @file src/tmr/llps_tmr_memory_regions.c
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#include "llps_tmr_memory_regions.h"

#include "llps_control_flag.h"
#include "llps_free_list_tmr.h"
#include "llps_runtime_cfg_tmr.h"
#include "llps_session_tmr.h"

#include <stddef.h>

void llps_tmr_memory_regions_snapshot(
    llps_tmr_memory_region_t out_regions[LLPS_TMR_MEMORY_REGION_COUNT]) {
    const llps_tmr_memory_region_t regions[LLPS_TMR_MEMORY_REGION_COUNT] = {
        { &g_session_tmr_region0, sizeof(g_session_tmr_region0), 0u, 0u },
        { &g_session_tmr_region1, sizeof(g_session_tmr_region1), 1u, 1u },
        { &g_session_tmr_region2, sizeof(g_session_tmr_region2), 2u, 2u },
        { &g_runtime_cfg_bank0, sizeof(g_runtime_cfg_bank0), 3u, 0u },
        { &g_runtime_cfg_bank1, sizeof(g_runtime_cfg_bank1), 4u, 1u },
        { &g_runtime_cfg_bank2, sizeof(g_runtime_cfg_bank2), 5u, 2u },
        { &g_free_list_bank0, sizeof(g_free_list_bank0), 6u, 0u },
        { &g_free_list_bank1, sizeof(g_free_list_bank1), 7u, 1u },
        { &g_free_list_bank2, sizeof(g_free_list_bank2), 8u, 2u },
        { &g_control_flag_bank0, sizeof(g_control_flag_bank0), 9u, 0u },
        { &g_control_flag_bank1, sizeof(g_control_flag_bank1), 10u, 1u },
        { &g_control_flag_bank2, sizeof(g_control_flag_bank2), 11u, 2u }
    };

    if (out_regions == NULL) {
        return;
    }

    for (size_t i = 0u; i < LLPS_TMR_MEMORY_REGION_COUNT; ++i) {
        out_regions[i] = regions[i];
    }
}
