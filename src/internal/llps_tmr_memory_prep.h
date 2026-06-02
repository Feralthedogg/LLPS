/**
 * @file src/internal/llps_tmr_memory_prep.h
 * @brief Triple-modular-redundancy layout, probing, and hardening helpers.
 *
 * @details
 * TMR modules own replicated storage layout, memory residency, and domain
 * evidence.
 */

#ifndef LLPS_TMR_MEMORY_PREP_H
#define LLPS_TMR_MEMORY_PREP_H

#include <stdbool.h>

/** @brief Try to lock current and future process memory into RAM. */
bool llps_lock_process_memory(void);
/** @brief Try to lock only the TMR metadata memory regions into RAM. */
bool llps_lock_tmr_memory(void);
/** @brief Touch protected TMR memory pages so residency can be observed. */
bool llps_prefault_tmr_memory(void);

#endif /* LLPS_TMR_MEMORY_PREP_H */
