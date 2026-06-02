/**
 * @file src/session/llps_runtime_latches.c
 * @brief Session metadata redundancy, counters, latches, and TMR banks.
 *
 * @details
 * Session modules keep redundant metadata handling close to the state they
 * protect.
 */

#include "llps_runtime_latches.h"

#include "llps_guard.h"

#include <stddef.h>
#include <stdint.h>

bool g_process_memory_locked = false;
uint32_t g_process_memory_locked_inverse = UINT32_MAX;
bool g_tmr_memory_locked = false;
uint32_t g_tmr_memory_locked_inverse = UINT32_MAX;
bool g_tmr_memory_prefaulted = false;
uint32_t g_tmr_memory_prefaulted_inverse = UINT32_MAX;
bool g_tmr_memory_domains_bound = false;
uint32_t g_tmr_memory_domains_bound_inverse = UINT32_MAX;
bool g_tmr_memory_hardened = false;
uint32_t g_tmr_memory_hardened_inverse = UINT32_MAX;
bool g_tmr_startup_self_test_passed = false;
uint32_t g_tmr_startup_self_test_passed_inverse = UINT32_MAX;
uint32_t g_tmr_startup_self_test_coverage = 0u;
uint32_t g_tmr_startup_self_test_coverage_inverse = UINT32_MAX;
uint64_t g_tmr_memory_prefault_pages = 0u;
uint64_t g_tmr_memory_prefault_pages_inverse = UINT64_MAX;
uint32_t g_tmr_memory_domain_observation_fingerprint = 0u;
uint32_t g_tmr_memory_domain_observation_fingerprint_inverse = UINT32_MAX;
uint32_t g_tmr_memory_observed_domain_ids[LLPS_SESSION_TMR_BANK_COUNT] =
    { LLPS_TMR_MEMORY_DOMAIN_UNKNOWN,
      LLPS_TMR_MEMORY_DOMAIN_UNKNOWN,
      LLPS_TMR_MEMORY_DOMAIN_UNKNOWN };
uint32_t
    g_tmr_memory_observed_domain_ids_inverse[LLPS_SESSION_TMR_BANK_COUNT] =
        { ~LLPS_TMR_MEMORY_DOMAIN_UNKNOWN,
          ~LLPS_TMR_MEMORY_DOMAIN_UNKNOWN,
          ~LLPS_TMR_MEMORY_DOMAIN_UNKNOWN };

void llps_process_memory_locked_set(const bool value) {
    llps_guarded_bool_set(&g_process_memory_locked,
                          &g_process_memory_locked_inverse,
                          value);
}

void llps_tmr_memory_locked_set(const bool value) {
    llps_guarded_bool_set(&g_tmr_memory_locked,
                          &g_tmr_memory_locked_inverse,
                          value);
}

void llps_tmr_memory_prefaulted_set(const bool value) {
    llps_guarded_bool_set(&g_tmr_memory_prefaulted,
                          &g_tmr_memory_prefaulted_inverse,
                          value);
}

void llps_tmr_memory_prefault_pages_set(const uint64_t pages) {
    g_tmr_memory_prefault_pages = pages;
    g_tmr_memory_prefault_pages_inverse = ~pages;
}

bool llps_tmr_memory_prefault_pages_is_valid(void) {
    return g_tmr_memory_prefault_pages_inverse ==
           ~g_tmr_memory_prefault_pages;
}

uint64_t llps_tmr_memory_prefault_pages_read(void) {
    return llps_tmr_memory_prefault_pages_is_valid() ?
           g_tmr_memory_prefault_pages :
           0u;
}

void llps_tmr_memory_domains_bound_set(const bool value) {
    llps_guarded_bool_set(&g_tmr_memory_domains_bound,
                          &g_tmr_memory_domains_bound_inverse,
                          value);
}

void llps_tmr_memory_hardened_set(const bool value) {
    llps_guarded_bool_set(&g_tmr_memory_hardened,
                          &g_tmr_memory_hardened_inverse,
                          value);
}

void llps_tmr_startup_self_test_passed_set(const bool value) {
    llps_guarded_bool_set(&g_tmr_startup_self_test_passed,
                          &g_tmr_startup_self_test_passed_inverse,
                          value);
}

void llps_tmr_startup_self_test_set_coverage(const uint32_t coverage) {
    g_tmr_startup_self_test_coverage = coverage;
    g_tmr_startup_self_test_coverage_inverse = ~coverage;
}

bool llps_tmr_startup_self_test_coverage_is_valid(void) {
    return g_tmr_startup_self_test_coverage_inverse ==
           ~g_tmr_startup_self_test_coverage;
}

void llps_tmr_memory_domain_observation_fingerprint_set(
    const uint32_t fingerprint) {
    g_tmr_memory_domain_observation_fingerprint = fingerprint;
    g_tmr_memory_domain_observation_fingerprint_inverse = ~fingerprint;
}

bool llps_tmr_memory_domain_observation_fingerprint_is_valid(void) {
    return g_tmr_memory_domain_observation_fingerprint_inverse ==
           ~g_tmr_memory_domain_observation_fingerprint;
}

void llps_tmr_memory_observed_domains_set(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        const uint32_t domain_id =
            (domain_ids != NULL) ?
            domain_ids[i] :
            LLPS_TMR_MEMORY_DOMAIN_UNKNOWN;

        g_tmr_memory_observed_domain_ids[i] = domain_id;
        g_tmr_memory_observed_domain_ids_inverse[i] = ~domain_id;
    }
}

bool llps_tmr_memory_observed_domains_are_valid(void) {
    for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (g_tmr_memory_observed_domain_ids_inverse[i] !=
            ~g_tmr_memory_observed_domain_ids[i]) {
            return false;
        }
    }

    return true;
}

bool llps_runtime_safety_latches_are_valid(void) {
    return llps_guarded_bool_is_valid(g_process_memory_locked,
                                      g_process_memory_locked_inverse) &&
           llps_guarded_bool_is_valid(g_tmr_memory_locked,
                                      g_tmr_memory_locked_inverse) &&
           llps_guarded_bool_is_valid(g_tmr_memory_prefaulted,
                                      g_tmr_memory_prefaulted_inverse) &&
           llps_tmr_memory_prefault_pages_is_valid() &&
           llps_guarded_bool_is_valid(g_tmr_memory_domains_bound,
                                      g_tmr_memory_domains_bound_inverse) &&
           llps_guarded_bool_is_valid(g_tmr_memory_hardened,
                                      g_tmr_memory_hardened_inverse) &&
           llps_guarded_bool_is_valid(g_tmr_startup_self_test_passed,
                                      g_tmr_startup_self_test_passed_inverse) &&
           llps_tmr_startup_self_test_coverage_is_valid() &&
           llps_tmr_memory_domain_observation_fingerprint_is_valid() &&
           llps_tmr_memory_observed_domains_are_valid();
}
