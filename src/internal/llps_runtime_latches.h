/**
 * @file src/internal/llps_runtime_latches.h
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#ifndef LLPS_RUNTIME_LATCHES_H
#define LLPS_RUNTIME_LATCHES_H

#include "llps.h"

#include <stdbool.h>
#include <stdint.h>

extern bool g_process_memory_locked;
extern uint32_t g_process_memory_locked_inverse;
extern bool g_tmr_memory_locked;
extern uint32_t g_tmr_memory_locked_inverse;
extern bool g_tmr_memory_prefaulted;
extern uint32_t g_tmr_memory_prefaulted_inverse;
extern bool g_tmr_memory_domains_bound;
extern uint32_t g_tmr_memory_domains_bound_inverse;
extern bool g_tmr_memory_hardened;
extern uint32_t g_tmr_memory_hardened_inverse;
extern bool g_tmr_startup_self_test_passed;
extern uint32_t g_tmr_startup_self_test_passed_inverse;
extern uint32_t g_tmr_startup_self_test_coverage;
extern uint32_t g_tmr_startup_self_test_coverage_inverse;
extern uint64_t g_tmr_memory_prefault_pages;
extern uint64_t g_tmr_memory_prefault_pages_inverse;
extern uint32_t g_tmr_memory_domain_observation_fingerprint;
extern uint32_t g_tmr_memory_domain_observation_fingerprint_inverse;
extern uint32_t
    g_tmr_memory_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT];
extern uint32_t
    g_tmr_memory_observed_domain_ids_inverse[LLPS_SESSION_TMR_BANK_COUNT];

/** @brief Record whether process memory lock succeeded. */
void llps_process_memory_locked_set(bool value);
/** @brief Record whether TMR memory lock succeeded. */
void llps_tmr_memory_locked_set(bool value);
/** @brief Record whether TMR memory prefaulting succeeded. */
void llps_tmr_memory_prefaulted_set(bool value);
/** @brief Record the number of prefaulted TMR memory pages. */
void llps_tmr_memory_prefault_pages_set(uint64_t pages);
/** @brief Validate the prefault page count inverse guard. */
bool llps_tmr_memory_prefault_pages_is_valid(void);
/** @brief Read the guarded prefault page count, returning 0 on invalid guard. */
uint64_t llps_tmr_memory_prefault_pages_read(void);
/** @brief Record whether TMR memory domains were bound. */
void llps_tmr_memory_domains_bound_set(bool value);
/** @brief Record whether TMR memory hardening completed. */
void llps_tmr_memory_hardened_set(bool value);
/** @brief Record whether startup TMR self-tests passed. */
void llps_tmr_startup_self_test_passed_set(bool value);
/** @brief Record startup TMR self-test coverage bits. */
void llps_tmr_startup_self_test_set_coverage(uint32_t coverage);
/** @brief Validate startup TMR self-test coverage inverse guard. */
bool llps_tmr_startup_self_test_coverage_is_valid(void);
/** @brief Record the observed TMR memory domain fingerprint. */
void llps_tmr_memory_domain_observation_fingerprint_set(
    uint32_t fingerprint);
/** @brief Validate the observed domain fingerprint inverse guard. */
bool llps_tmr_memory_domain_observation_fingerprint_is_valid(void);
/** @brief Record observed TMR domain IDs for all banks. */
void llps_tmr_memory_observed_domains_set(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]);
/** @brief Validate observed TMR domain ID inverse guards. */
bool llps_tmr_memory_observed_domains_are_valid(void);
/** @brief Validate all guarded runtime safety latches. */
bool llps_runtime_safety_latches_are_valid(void);

#endif /* LLPS_RUNTIME_LATCHES_H */
