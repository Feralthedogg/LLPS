/**
 * @file src/platform/llps_edac.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_edac.h"

#include "llps.h"
#include "llps_crc.h"

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void llps_edac_observation_clear(llps_edac_observation_t * const observation) {
    if (observation != NULL) {
        (void)memset(observation, 0, sizeof(*observation));
    }
}

uint32_t llps_edac_observed_flags(const bool ecc_present,
                                  const bool ecc_clean) {
    uint32_t flags = 0u;

    if (ecc_present) {
        flags |= LLPS_PLATFORM_EVIDENCE_ECC_MEMORY;
    }
    if (ecc_present && ecc_clean) {
        flags |= LLPS_PLATFORM_EVIDENCE_ECC_CLEAN;
    }

    return flags;
}

void llps_edac_synthesize_ecc(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint64_t controller_corrected_error_count,
    const uint64_t controller_uncorrected_error_count,
    const uint64_t dimm_corrected_error_count,
    const uint64_t dimm_uncorrected_error_count,
    bool * const out_ecc_present,
    bool * const out_counters_clean,
    uint32_t * const out_observation_fingerprint,
    llps_edac_observation_t * const out_observation) {
    static const char source_label[] = "software-ecc";
    static const char corrected_mode_label[] = "SECDED";
    llps_edac_observation_t observation;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if ((out_ecc_present == NULL) ||
        (out_counters_clean == NULL) ||
        (out_observation_fingerprint == NULL)) {
        return;
    }

    llps_edac_observation_clear(&observation);
    *out_ecc_present = false;
    *out_counters_clean = false;
    *out_observation_fingerprint = 0u;

    if ((controller_count == 0u) ||
        (controller_count > LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) ||
        (dimm_count == 0u) ||
        (dimm_count > LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX) ||
        (controller_count > dimm_count) ||
        (scrub_rate == 0u) ||
        (scrub_rate > LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX) ||
        (scrub_rate > (UINT64_MAX / (uint64_t)controller_count))) {
        llps_edac_observation_clear(out_observation);
        return;
    }

    observation.controller_count = controller_count;
    observation.dimm_count = dimm_count;
    observation.scrub_rate_count = controller_count;
    observation.controller_counter_coverage = 1u;
    observation.dimm_mode_coverage = 1u;
    observation.dimm_counter_coverage = 1u;
    observation.scrub_rate_coverage = 1u;
    observation.corrected_error_count = controller_corrected_error_count;
    observation.uncorrected_error_count = controller_uncorrected_error_count;
    observation.dimm_corrected_error_count = dimm_corrected_error_count;
    observation.dimm_uncorrected_error_count = dimm_uncorrected_error_count;
    observation.scrub_rate_sum = scrub_rate * (uint64_t)controller_count;

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 source_label,
                                                 sizeof(source_label));
    fingerprint = llps_crc32_update_u32(fingerprint, controller_count);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_count);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        observation.controller_count);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        observation.scrub_rate_count);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        observation.controller_counter_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        observation.dimm_mode_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        observation.dimm_counter_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        observation.scrub_rate_coverage);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        observation.corrected_error_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        observation.uncorrected_error_count);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        observation.dimm_corrected_error_count);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        observation.dimm_uncorrected_error_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        observation.scrub_rate_sum);
    for (uint32_t controller = 0u;
         controller < controller_count;
         ++controller) {
        const uint32_t controller_dimm_count =
            (dimm_count / controller_count) +
            ((controller < (dimm_count % controller_count)) ? 1u : 0u);
        const uint64_t controller_ce =
            (controller_corrected_error_count / controller_count) +
            ((controller <
              (uint32_t)(controller_corrected_error_count %
                         controller_count)) ? 1u : 0u);
        const uint64_t controller_ue =
            (controller_uncorrected_error_count / controller_count) +
            ((controller <
              (uint32_t)(controller_uncorrected_error_count %
                         controller_count)) ? 1u : 0u);

        fingerprint = llps_crc32_update_u32(fingerprint, controller);
        fingerprint = llps_crc32_update_u32(fingerprint,
                                            controller_dimm_count);
        fingerprint = llps_crc32_update_u64(fingerprint, scrub_rate);
        fingerprint = llps_crc32_update_u64(fingerprint, controller_ce);
        fingerprint = llps_crc32_update_u64(fingerprint, controller_ue);
    }
    for (uint32_t dimm = 0u; dimm < dimm_count; ++dimm) {
        const uint32_t controller = dimm % controller_count;
        const uint32_t slot = dimm / controller_count;
        const uint64_t dimm_ce =
            (dimm_corrected_error_count / dimm_count) +
            ((dimm <
              (uint32_t)(dimm_corrected_error_count %
                         dimm_count)) ? 1u : 0u);
        const uint64_t dimm_ue =
            (dimm_uncorrected_error_count / dimm_count) +
            ((dimm <
              (uint32_t)(dimm_uncorrected_error_count %
                         dimm_count)) ? 1u : 0u);

        fingerprint = llps_crc32_update_u32(fingerprint, dimm);
        fingerprint = llps_crc32_update_u32(fingerprint, controller);
        fingerprint = llps_crc32_update_u32(fingerprint, slot);
        fingerprint = llps_crc32_update_cstr_bounded(
            fingerprint,
            corrected_mode_label,
            sizeof(corrected_mode_label));
        fingerprint = llps_crc32_update_u64(fingerprint, dimm_ce);
        fingerprint = llps_crc32_update_u64(fingerprint, dimm_ue);
    }

    *out_ecc_present = true;
    *out_counters_clean =
        (controller_corrected_error_count == 0u) &&
        (controller_uncorrected_error_count == 0u) &&
        (dimm_corrected_error_count == 0u) &&
        (dimm_uncorrected_error_count == 0u);
    *out_observation_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    if (out_observation != NULL) {
        *out_observation = observation;
    }
}

static uint32_t llps_edac_bool_to_u32(const bool value) {
    return value ? 1u : 0u;
}

static bool llps_edac_name_is_memory_controller(const char * const name) {
    size_t i = 0u;

    if (name == NULL) {
        return false;
    }

    if ((name[0] != 'm') || (name[1] != 'c') ||
        (name[2] < '0') || (name[2] > '9')) {
        return false;
    }

    for (i = 3u; i < LLPS_EDAC_PATH_BYTES; ++i) {
        const char c = name[i];

        if (c == '\0') {
            return true;
        }

        if ((c < '0') || (c > '9')) {
            return false;
        }
    }

    return false;
}

static bool llps_edac_name_is_dimm(const char * const name) {
    size_t i = 0u;

    if (name == NULL) {
        return false;
    }

    if ((name[0] != 'd') ||
        (name[1] != 'i') ||
        (name[2] != 'm') ||
        (name[3] != 'm') ||
        (name[4] < '0') ||
        (name[4] > '9')) {
        return false;
    }

    for (i = 5u; i < LLPS_EDAC_PATH_BYTES; ++i) {
        const char c = name[i];

        if (c == '\0') {
            return true;
        }

        if ((c < '0') || (c > '9')) {
            return false;
        }
    }

    return false;
}

static bool llps_edac_join_counter_path(char * const out_path,
                                        const size_t out_path_cap,
                                        const char * const root,
                                        const char * const controller,
                                        const char * const counter_name) {
    int n = 0;

    if ((out_path == NULL) ||
        (out_path_cap == 0u) ||
        (root == NULL) ||
        (controller == NULL) ||
        (counter_name == NULL)) {
        return false;
    }

    n = snprintf(out_path,
                 out_path_cap,
                 "%s/%s/%s",
                 root,
                 controller,
                 counter_name);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_edac_join_dimm_attr_path(char * const out_path,
                                          const size_t out_path_cap,
                                          const char * const root,
                                          const char * const controller,
                                          const char * const dimm,
                                          const char * const attr_name) {
    int n = 0;

    if ((out_path == NULL) ||
        (out_path_cap == 0u) ||
        (root == NULL) ||
        (controller == NULL) ||
        (dimm == NULL) ||
        (attr_name == NULL)) {
        return false;
    }

    n = snprintf(out_path,
                 out_path_cap,
                 "%s/%s/%s/%s",
                 root,
                 controller,
                 dimm,
                 attr_name);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static char llps_edac_ascii_lower_char(const char c) {
    if ((c >= 'A') && (c <= 'Z')) {
        return (char)(c + ('a' - 'A'));
    }

    return c;
}

static bool llps_edac_ascii_is_alnum(const char c) {
    const char lower = llps_edac_ascii_lower_char(c);

    return ((lower >= 'a') && (lower <= 'z')) ||
           ((lower >= '0') && (lower <= '9'));
}

static bool llps_edac_mode_text_matches_word(const char * const text,
                                             const size_t start,
                                             const char * const word,
                                             const size_t word_len) {
    if ((text == NULL) || (word == NULL) || (word_len == 0u)) {
        return false;
    }

    for (size_t i = 0u; i < word_len; ++i) {
        if ((start + i) >= LLPS_EDAC_MODE_TEXT_BYTES) {
            return false;
        }

        if (text[start + i] == '\0') {
            return false;
        }

        if (llps_edac_ascii_lower_char(text[start + i]) != word[i]) {
            return false;
        }
    }

    return true;
}

static bool llps_edac_mode_text_matches_token(const char * const text,
                                              const size_t start,
                                              const char * const token,
                                              const size_t token_len) {
    const size_t end = start + token_len;

    if (!llps_edac_mode_text_matches_word(text, start, token, token_len)) {
        return false;
    }

    if ((start > 0u) && llps_edac_ascii_is_alnum(text[start - 1u])) {
        return false;
    }

    if ((end < LLPS_EDAC_MODE_TEXT_BYTES) &&
        (text[end] != '\0') &&
        llps_edac_ascii_is_alnum(text[end])) {
        return false;
    }

    return true;
}

static bool llps_edac_mode_text_is_ecc(const char * const text) {
    bool saw_correcting_ecc = false;
    bool saw_reject_token = false;
    size_t i = 0u;

    if (text == NULL) {
        return false;
    }

    for (i = 0u; i < LLPS_EDAC_MODE_TEXT_BYTES; ++i) {
        const char c = llps_edac_ascii_lower_char(text[i]);

        if (c == '\0') {
            break;
        }

        if (llps_edac_mode_text_matches_token(text, i, "none", 4u) ||
            llps_edac_mode_text_matches_token(text, i, "unknown", 7u) ||
            llps_edac_mode_text_matches_token(text, i, "off", 3u) ||
            llps_edac_mode_text_matches_token(text, i, "disable", 7u) ||
            llps_edac_mode_text_matches_token(text, i, "disabled", 8u) ||
            llps_edac_mode_text_matches_token(text, i, "no", 2u) ||
            llps_edac_mode_text_matches_token(text, i, "non", 3u) ||
            llps_edac_mode_text_matches_token(text, i, "parity", 6u)) {
            saw_reject_token = true;
        }
        if (llps_edac_mode_text_matches_token(text, i, "ecc", 3u) ||
            llps_edac_mode_text_matches_token(text, i, "secded", 6u) ||
            llps_edac_mode_text_matches_token(text, i, "sddc", 4u) ||
            llps_edac_mode_text_matches_token(text, i, "s4ecd4ed", 8u) ||
            llps_edac_mode_text_matches_token(text, i, "s8ecd8ed", 8u) ||
            llps_edac_mode_text_matches_token(text, i, "chipkill", 8u)) {
            saw_correcting_ecc = true;
        }

    }

    return saw_correcting_ecc && !saw_reject_token;
}

static bool llps_edac_read_mode_text(const char * const path,
                                     char text[LLPS_EDAC_MODE_TEXT_BYTES]) {
    FILE *fp = NULL;
    bool read_ok = false;

    if ((path == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_EDAC_MODE_TEXT_BYTES);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_EDAC_MODE_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_edac_parse_counter_text(const char * const text,
                                         uint64_t * const out_value) {
    uint64_t value = 0u;
    bool saw_digit = false;

    if ((text == NULL) || (out_value == NULL)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_EDAC_COUNTER_TEXT_BYTES; ++i) {
        const char c = text[i];

        if ((c >= '0') && (c <= '9')) {
            const uint64_t digit = (uint64_t)((uint32_t)c - (uint32_t)'0');

            if (value > ((UINT64_MAX - digit) / 10u)) {
                return false;
            }
            value = (value * 10u) + digit;
            saw_digit = true;
            continue;
        }

        if ((c == '\0') || (c == '\n') || (c == '\r') ||
            (c == ' ') || (c == '\t')) {
            *out_value = value;
            return saw_digit;
        }

        return false;
    }

    return false;
}

static bool llps_edac_read_counter(const char * const path,
                                   uint64_t * const out_value) {
    FILE *fp = NULL;
    char text[LLPS_EDAC_COUNTER_TEXT_BYTES];
    bool parsed = false;

    if ((path == NULL) || (out_value == NULL)) {
        return false;
    }

    (void)memset(text, 0, sizeof(text));
    fp = fopen(path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)sizeof(text), fp) != NULL) {
        parsed = llps_edac_parse_counter_text(text, out_value);
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return parsed;
}

typedef struct {
    bool found_controller;
    bool counters_clean;
    bool saw_ecc_mode;
    bool ecc_modes_ok;
    bool scrub_rates_ok;
    bool controller_counters_complete;
    bool dimm_modes_complete;
    bool dimm_counters_complete;
    bool root_available;
    uint32_t controller_mix;
    uint64_t controller_sum;
    uint32_t controller_count;
    uint32_t dimm_count;
    uint32_t scrub_rate_count;
    uint64_t corrected_error_count;
    uint64_t uncorrected_error_count;
    uint64_t dimm_corrected_error_count;
    uint64_t dimm_uncorrected_error_count;
    uint64_t scrub_rate_sum;
    uint32_t controller_counter_coverage;
    uint32_t dimm_mode_coverage;
    uint32_t dimm_counter_coverage;
    uint32_t scrub_rate_coverage;
} llps_edac_probe_state_t;

typedef struct {
    bool ce_ok;
    bool ue_ok;
    bool scrub_rate_ok;
    bool controller_modes_complete;
    bool controller_modes_ecc;
    bool controller_dimm_counters_complete;
    bool controller_dimm_counters_clean;
    uint64_t ce_count;
    uint64_t ue_count;
    uint64_t scrub_rate;
    uint32_t controller_mode_fingerprint;
    uint32_t controller_dimm_count;
    uint64_t controller_dimm_ce_count;
    uint64_t controller_dimm_ue_count;
    uint32_t controller_observation;
} llps_edac_controller_probe_t;

static void llps_edac_probe_controller_ecc_mode(
    const char * const root,
    const char * const controller,
    bool * const out_modes_complete,
    bool * const out_modes_ecc,
    bool * const out_dimm_counters_complete,
    bool * const out_dimm_counters_clean,
    uint32_t * const out_mode_fingerprint,
    uint32_t * const out_dimm_count,
    uint64_t * const out_dimm_corrected_error_count,
    uint64_t * const out_dimm_uncorrected_error_count) {
    DIR *dir = NULL;
    const struct dirent *entry = NULL;
    char controller_path[LLPS_EDAC_PATH_BYTES];
    int n = 0;
    bool modes_complete = false;
    bool modes_ecc = true;
    bool dimm_counters_complete = false;
    bool dimm_counters_clean = true;
    uint32_t readable_mode_count = 0u;
    uint32_t readable_dimm_counter_count = 0u;
    uint32_t mode_mix = 0u;
    uint64_t mode_sum = 0u;
    uint32_t dimm_count = 0u;
    uint64_t dimm_corrected_error_count = 0u;
    uint64_t dimm_uncorrected_error_count = 0u;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if ((root == NULL) ||
        (controller == NULL) ||
        (out_modes_complete == NULL) ||
        (out_modes_ecc == NULL) ||
        (out_dimm_counters_complete == NULL) ||
        (out_dimm_counters_clean == NULL) ||
        (out_mode_fingerprint == NULL) ||
        (out_dimm_count == NULL) ||
        (out_dimm_corrected_error_count == NULL) ||
        (out_dimm_uncorrected_error_count == NULL)) {
        return;
    }

    *out_modes_complete = false;
    *out_modes_ecc = false;
    *out_dimm_counters_complete = false;
    *out_dimm_counters_clean = false;
    *out_mode_fingerprint = 0u;
    *out_dimm_count = 0u;
    *out_dimm_corrected_error_count = 0u;
    *out_dimm_uncorrected_error_count = 0u;

    n = snprintf(controller_path, sizeof(controller_path), "%s/%s", root, controller);
    if ((n < 0) || ((size_t)n >= sizeof(controller_path))) {
        return;
    }

    dir = opendir(controller_path);
    if (dir == NULL) {
        return;
    }

    for (uint32_t dimm_scan = 0u; dimm_scan < UINT32_MAX; ++dimm_scan) {
        char mode_path[LLPS_EDAC_PATH_BYTES];
        char dimm_ce_path[LLPS_EDAC_PATH_BYTES];
        char dimm_ue_path[LLPS_EDAC_PATH_BYTES];
        char mode_text[LLPS_EDAC_MODE_TEXT_BYTES];
        uint64_t dimm_ce_count = 0u;
        uint64_t dimm_ue_count = 0u;
        bool mode_ok = false;
        bool mode_ecc = false;
        bool dimm_ce_ok = false;
        bool dimm_ue_ok = false;
        uint32_t dimm_observation = 0u;

        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }

        if (!llps_edac_name_is_dimm(entry->d_name)) {
            continue;
        }

        ++dimm_count;
        (void)memset(mode_text, 0, sizeof(mode_text));
        mode_ok = llps_edac_join_dimm_attr_path(mode_path,
                                                sizeof(mode_path),
                                                root,
                                                controller,
                                                entry->d_name,
                                                "dimm_edac_mode") &&
                  llps_edac_read_mode_text(mode_path, mode_text);
        if (mode_ok) {
            mode_ecc = llps_edac_mode_text_is_ecc(mode_text);
            ++readable_mode_count;
        }
        if (!mode_ecc) {
            modes_ecc = false;
        }

        dimm_ce_ok = llps_edac_join_dimm_attr_path(dimm_ce_path,
                                                   sizeof(dimm_ce_path),
                                                   root,
                                                   controller,
                                                   entry->d_name,
                                                   "dimm_ce_count") &&
                     llps_edac_read_counter(dimm_ce_path, &dimm_ce_count);
        dimm_ue_ok = llps_edac_join_dimm_attr_path(dimm_ue_path,
                                                   sizeof(dimm_ue_path),
                                                   root,
                                                   controller,
                                                   entry->d_name,
                                                   "dimm_ue_count") &&
                     llps_edac_read_counter(dimm_ue_path, &dimm_ue_count);
        if (dimm_ce_ok && dimm_ue_ok) {
            ++readable_dimm_counter_count;
        } else {
            dimm_counters_clean = false;
        }
        if (!dimm_ce_ok || (dimm_ce_count != 0u)) {
            dimm_counters_clean = false;
        }
        if (!dimm_ue_ok || (dimm_ue_count != 0u)) {
            dimm_counters_clean = false;
        }
        if (dimm_ce_ok) {
            if ((UINT64_MAX - dimm_corrected_error_count) < dimm_ce_count) {
                dimm_counters_clean = false;
                dimm_corrected_error_count = UINT64_MAX;
            } else {
                dimm_corrected_error_count += dimm_ce_count;
            }
        }
        if (dimm_ue_ok) {
            if ((UINT64_MAX - dimm_uncorrected_error_count) < dimm_ue_count) {
                dimm_counters_clean = false;
                dimm_uncorrected_error_count = UINT64_MAX;
            } else {
                dimm_uncorrected_error_count += dimm_ue_count;
            }
        }

        fingerprint = LLPS_SESSION_CRC_INIT;
        fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                     entry->d_name,
                                                     LLPS_EDAC_PATH_BYTES);
        fingerprint = llps_crc32_update_u32(fingerprint, mode_ok ? 1u : 0u);
        fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                     mode_text,
                                                     sizeof(mode_text));
        fingerprint = llps_crc32_update_u32(fingerprint, mode_ecc ? 1u : 0u);
        fingerprint = llps_crc32_update_u32(fingerprint,
                                            dimm_ce_ok ? 1u : 0u);
        fingerprint = llps_crc32_update_u64(fingerprint, dimm_ce_count);
        fingerprint = llps_crc32_update_u32(fingerprint,
                                            dimm_ue_ok ? 1u : 0u);
        fingerprint = llps_crc32_update_u64(fingerprint, dimm_ue_count);
        dimm_observation = fingerprint ^ LLPS_SESSION_CRC_XOROUT;
        mode_mix ^= dimm_observation;
        if ((UINT64_MAX - mode_sum) < (uint64_t)dimm_observation) {
            mode_sum = UINT64_MAX;
            modes_ecc = false;
        } else {
            mode_sum += (uint64_t)dimm_observation;
        }
    }

    (void)closedir(dir);

    modes_complete = (dimm_count != 0u) && (readable_mode_count == dimm_count);
    dimm_counters_complete =
        (dimm_count != 0u) && (readable_dimm_counter_count == dimm_count);
    *out_modes_complete = modes_complete;
    *out_modes_ecc = modes_complete && modes_ecc;
    *out_dimm_counters_complete = dimm_counters_complete;
    *out_dimm_counters_clean =
        dimm_counters_complete && dimm_counters_clean;
    fingerprint = LLPS_SESSION_CRC_INIT;
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        modes_complete ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        (modes_complete && modes_ecc) ?
                                        1u :
                                        0u);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_count);
    fingerprint = llps_crc32_update_u32(fingerprint, readable_mode_count);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        dimm_counters_complete ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        (dimm_counters_complete && dimm_counters_clean) ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        readable_dimm_counter_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        dimm_corrected_error_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        dimm_uncorrected_error_count);
    fingerprint = llps_crc32_update_u32(fingerprint, mode_mix);
    fingerprint = llps_crc32_update_u64(fingerprint, mode_sum);
    *out_mode_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    *out_dimm_count = dimm_count;
    *out_dimm_corrected_error_count = dimm_corrected_error_count;
    *out_dimm_uncorrected_error_count = dimm_uncorrected_error_count;
}

static uint32_t llps_edac_missing_fingerprint(const char * const root) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 root,
                                                 LLPS_EDAC_PATH_BYTES);
    for (uint32_t i = 0u; i < 13u; ++i) {
        fingerprint = llps_crc32_update_u32(fingerprint, 0u);
    }
    for (uint32_t i = 0u; i < 5u; ++i) {
        fingerprint = llps_crc32_update_u64(fingerprint, 0u);
    }
    fingerprint = llps_crc32_update_u32(fingerprint, 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, 0u);

    return llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
}

static bool llps_edac_probe_outputs_are_valid(
    const bool * const out_ecc_present,
    const bool * const out_counters_clean,
    const uint32_t * const out_observation_fingerprint) {
    return (out_ecc_present != NULL) &&
           (out_counters_clean != NULL) &&
           (out_observation_fingerprint != NULL);
}

static void llps_edac_probe_outputs_init(
    bool * const out_ecc_present,
    bool * const out_counters_clean,
    uint32_t * const out_observation_fingerprint,
    llps_edac_observation_t * const out_observation) {
    *out_ecc_present = false;
    *out_counters_clean = false;
    *out_observation_fingerprint = 0u;
    llps_edac_observation_clear(out_observation);
}

static void llps_edac_probe_state_init(
    llps_edac_probe_state_t * const state) {
    if (state != NULL) {
        (void)memset(state, 0, sizeof(*state));
        state->counters_clean = true;
        state->ecc_modes_ok = true;
        state->scrub_rates_ok = true;
        state->controller_counters_complete = true;
        state->dimm_modes_complete = true;
        state->dimm_counters_complete = true;
    }
}

static void llps_edac_controller_probe_init(
    llps_edac_controller_probe_t * const probe) {
    if (probe != NULL) {
        (void)memset(probe, 0, sizeof(*probe));
    }
}

static void llps_edac_read_controller_counters(
    const char * const root,
    const char * const controller,
    llps_edac_controller_probe_t * const probe) {
    char ce_path[LLPS_EDAC_PATH_BYTES];
    char ue_path[LLPS_EDAC_PATH_BYTES];
    char scrub_rate_path[LLPS_EDAC_PATH_BYTES];

    if ((root == NULL) || (controller == NULL) || (probe == NULL)) {
        return;
    }

    probe->ce_ok = llps_edac_join_counter_path(ce_path,
                                               sizeof(ce_path),
                                               root,
                                               controller,
                                               "ce_count") &&
                   llps_edac_read_counter(ce_path, &probe->ce_count);
    probe->ue_ok = llps_edac_join_counter_path(ue_path,
                                               sizeof(ue_path),
                                               root,
                                               controller,
                                               "ue_count") &&
                   llps_edac_read_counter(ue_path, &probe->ue_count);
    probe->scrub_rate_ok = llps_edac_join_counter_path(
                               scrub_rate_path,
                               sizeof(scrub_rate_path),
                               root,
                               controller,
                               "sdram_scrub_rate") &&
                           llps_edac_read_counter(scrub_rate_path,
                                                  &probe->scrub_rate);
}

static void llps_edac_accumulate_controller_counter_status(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if (!probe->ce_ok || !probe->ue_ok) {
        state->controller_counters_complete = false;
    }
    if (!probe->ce_ok || !probe->ue_ok ||
        (probe->ce_count != 0u) || (probe->ue_count != 0u)) {
        state->counters_clean = false;
    }
}

static void llps_edac_accumulate_scrub_rate(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if (!probe->scrub_rate_ok || (probe->scrub_rate == 0u)) {
        state->scrub_rates_ok = false;
        return;
    }
    if (state->scrub_rate_count == UINT32_MAX) {
        state->scrub_rates_ok = false;
    } else {
        ++state->scrub_rate_count;
    }
    if ((UINT64_MAX - state->scrub_rate_sum) < probe->scrub_rate) {
        state->scrub_rate_sum = UINT64_MAX;
        state->scrub_rates_ok = false;
    } else {
        state->scrub_rate_sum += probe->scrub_rate;
    }
}

static void llps_edac_accumulate_controller_error_counts(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if (probe->ce_ok) {
        if ((UINT64_MAX - state->corrected_error_count) < probe->ce_count) {
            state->counters_clean = false;
            state->corrected_error_count = UINT64_MAX;
        } else {
            state->corrected_error_count += probe->ce_count;
        }
    }
    if (probe->ue_ok) {
        if ((UINT64_MAX - state->uncorrected_error_count) < probe->ue_count) {
            state->counters_clean = false;
            state->uncorrected_error_count = UINT64_MAX;
        } else {
            state->uncorrected_error_count += probe->ue_count;
        }
    }
}

static void llps_edac_accumulate_controller_counters(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    llps_edac_accumulate_controller_counter_status(state, probe);
    llps_edac_accumulate_scrub_rate(state, probe);
    llps_edac_accumulate_controller_error_counts(state, probe);
}

static void llps_edac_probe_controller_modes(
    const char * const root,
    const char * const controller,
    llps_edac_controller_probe_t * const probe) {
    if ((root == NULL) || (controller == NULL) || (probe == NULL)) {
        return;
    }
    llps_edac_probe_controller_ecc_mode(
        root,
        controller,
        &probe->controller_modes_complete,
        &probe->controller_modes_ecc,
        &probe->controller_dimm_counters_complete,
        &probe->controller_dimm_counters_clean,
        &probe->controller_mode_fingerprint,
        &probe->controller_dimm_count,
        &probe->controller_dimm_ce_count,
        &probe->controller_dimm_ue_count);
}

static void llps_edac_accumulate_dimm_count(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if ((UINT32_MAX - state->dimm_count) < probe->controller_dimm_count) {
        state->dimm_count = UINT32_MAX;
        state->dimm_modes_complete = false;
        state->dimm_counters_complete = false;
        state->ecc_modes_ok = false;
    } else {
        state->dimm_count += probe->controller_dimm_count;
    }
}

static void llps_edac_accumulate_dimm_error_counts(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if ((UINT64_MAX - state->dimm_corrected_error_count) <
        probe->controller_dimm_ce_count) {
        state->dimm_corrected_error_count = UINT64_MAX;
        state->counters_clean = false;
    } else {
        state->dimm_corrected_error_count += probe->controller_dimm_ce_count;
    }
    if ((UINT64_MAX - state->dimm_uncorrected_error_count) <
        probe->controller_dimm_ue_count) {
        state->dimm_uncorrected_error_count = UINT64_MAX;
        state->counters_clean = false;
    } else {
        state->dimm_uncorrected_error_count += probe->controller_dimm_ue_count;
    }
}

static void llps_edac_accumulate_controller_modes(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    if (probe->controller_modes_complete) {
        state->saw_ecc_mode = true;
    } else {
        state->dimm_modes_complete = false;
        state->ecc_modes_ok = false;
    }
    if (!probe->controller_modes_ecc) {
        state->ecc_modes_ok = false;
    }
    if (!probe->controller_dimm_counters_complete) {
        state->dimm_counters_complete = false;
    }
    if (!probe->controller_dimm_counters_complete ||
        !probe->controller_dimm_counters_clean) {
        state->counters_clean = false;
    }
    llps_edac_accumulate_dimm_count(state, probe);
    llps_edac_accumulate_dimm_error_counts(state, probe);
}

static uint32_t llps_edac_controller_observation(
    const char * const controller,
    const llps_edac_controller_probe_t * const probe) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 controller,
                                                 LLPS_EDAC_PATH_BYTES);
    fingerprint = llps_crc32_update_u32(fingerprint, probe->ce_ok ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->ce_count);
    fingerprint = llps_crc32_update_u32(fingerprint, probe->ue_ok ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->ue_count);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        probe->scrub_rate_ok ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(fingerprint, probe->scrub_rate);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe->controller_modes_complete ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe->controller_modes_ecc ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe->controller_dimm_counters_complete ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe->controller_dimm_counters_clean ? 1u : 0u);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        probe->controller_dimm_ce_count);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        probe->controller_dimm_ue_count);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        probe->controller_mode_fingerprint);
    return fingerprint ^ LLPS_SESSION_CRC_XOROUT;
}

static void llps_edac_accumulate_controller_observation(
    llps_edac_probe_state_t * const state,
    const llps_edac_controller_probe_t * const probe) {
    if ((state == NULL) || (probe == NULL)) {
        return;
    }
    state->controller_mix ^= probe->controller_observation;
    if ((UINT64_MAX - state->controller_sum) <
        (uint64_t)probe->controller_observation) {
        state->controller_sum = UINT64_MAX;
        state->counters_clean = false;
        state->ecc_modes_ok = false;
    } else {
        state->controller_sum += (uint64_t)probe->controller_observation;
    }
}

static void llps_edac_scan_controller(
    const char * const root,
    const char * const controller,
    llps_edac_probe_state_t * const state) {
    llps_edac_controller_probe_t probe;

    if ((root == NULL) || (controller == NULL) || (state == NULL)) {
        return;
    }

    llps_edac_controller_probe_init(&probe);
    state->found_controller = true;
    llps_edac_read_controller_counters(root, controller, &probe);
    llps_edac_accumulate_controller_counters(state, &probe);
    llps_edac_probe_controller_modes(root, controller, &probe);
    llps_edac_accumulate_controller_modes(state, &probe);
    probe.controller_observation =
        llps_edac_controller_observation(controller, &probe);
    llps_edac_accumulate_controller_observation(state, &probe);
    ++state->controller_count;
}

static void llps_edac_scan_root(const char * const root,
                                DIR * const dir,
                                llps_edac_probe_state_t * const state) {
    const struct dirent *entry = NULL;

    if ((root == NULL) || (dir == NULL) || (state == NULL)) {
        return;
    }
    for (uint32_t controller_scan = 0u;
         controller_scan < UINT32_MAX;
         ++controller_scan) {
        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }
        if (llps_edac_name_is_memory_controller(entry->d_name)) {
            llps_edac_scan_controller(root, entry->d_name, state);
        }
    }
}

static void llps_edac_finalize_coverage(
    llps_edac_probe_state_t * const state) {
    if (state == NULL) {
        return;
    }
    state->controller_counter_coverage = llps_edac_bool_to_u32(
        state->found_controller && state->controller_counters_complete);
    state->dimm_mode_coverage = llps_edac_bool_to_u32(
        state->found_controller &&
        (state->dimm_count != 0u) &&
        state->dimm_modes_complete);
    state->dimm_counter_coverage = llps_edac_bool_to_u32(
        state->found_controller &&
        (state->dimm_count != 0u) &&
        state->dimm_counters_complete);
    state->scrub_rate_coverage = llps_edac_bool_to_u32(
        state->found_controller &&
        state->scrub_rates_ok &&
        (state->scrub_rate_count == state->controller_count));
}

static bool llps_edac_state_ecc_present(
    const llps_edac_probe_state_t * const state) {
    return (state != NULL) &&
           (state->dimm_mode_coverage != 0u) &&
           state->ecc_modes_ok &&
           (state->scrub_rate_coverage != 0u);
}

static bool llps_edac_state_counters_clean(
    const llps_edac_probe_state_t * const state) {
    return llps_edac_state_ecc_present(state) &&
           (state->controller_counter_coverage != 0u) &&
           (state->dimm_counter_coverage != 0u) &&
           state->counters_clean;
}

static uint32_t llps_edac_final_fingerprint(
    const char * const root,
    const llps_edac_probe_state_t * const state) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 root,
                                                 LLPS_EDAC_PATH_BYTES);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->root_available ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->found_controller ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->counters_clean ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->saw_ecc_mode ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->ecc_modes_ok ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->scrub_rates_ok ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        state->controller_counter_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->dimm_mode_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->dimm_counter_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        state->scrub_rate_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint, state->controller_count);
    fingerprint = llps_crc32_update_u32(fingerprint, state->dimm_count);
    fingerprint = llps_crc32_update_u32(fingerprint, state->scrub_rate_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        state->corrected_error_count);
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        state->uncorrected_error_count);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        state->dimm_corrected_error_count);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        state->dimm_uncorrected_error_count);
    fingerprint = llps_crc32_update_u64(fingerprint, state->scrub_rate_sum);
    fingerprint = llps_crc32_update_u32(fingerprint, state->controller_mix);
    fingerprint = llps_crc32_update_u64(fingerprint, state->controller_sum);
    return llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
}

static void llps_edac_fill_observation(
    llps_edac_observation_t * const out_observation,
    const llps_edac_probe_state_t * const state) {
    if ((out_observation == NULL) || (state == NULL)) {
        return;
    }
    out_observation->controller_count = state->controller_count;
    out_observation->dimm_count = state->dimm_count;
    out_observation->scrub_rate_count = state->scrub_rate_count;
    out_observation->controller_counter_coverage =
        state->controller_counter_coverage;
    out_observation->dimm_mode_coverage = state->dimm_mode_coverage;
    out_observation->dimm_counter_coverage = state->dimm_counter_coverage;
    out_observation->scrub_rate_coverage = state->scrub_rate_coverage;
    out_observation->corrected_error_count = state->corrected_error_count;
    out_observation->uncorrected_error_count = state->uncorrected_error_count;
    out_observation->dimm_corrected_error_count =
        state->dimm_corrected_error_count;
    out_observation->dimm_uncorrected_error_count =
        state->dimm_uncorrected_error_count;
    out_observation->scrub_rate_sum = state->scrub_rate_sum;
}

void llps_edac_probe_ecc(const char * const root,
                         bool * const out_ecc_present,
                         bool * const out_counters_clean,
                         uint32_t * const out_observation_fingerprint,
                         llps_edac_observation_t * const out_observation) {
    DIR *dir = NULL;
    llps_edac_probe_state_t state;

    if (!llps_edac_probe_outputs_are_valid(out_ecc_present,
                                           out_counters_clean,
                                           out_observation_fingerprint)) {
        return;
    }

    llps_edac_probe_outputs_init(out_ecc_present,
                                 out_counters_clean,
                                 out_observation_fingerprint,
                                 out_observation);

    if (root == NULL) {
        *out_observation_fingerprint = llps_edac_missing_fingerprint(root);
        return;
    }

    llps_edac_probe_state_init(&state);
    dir = opendir(root);
    if (dir == NULL) {
        *out_observation_fingerprint = llps_edac_missing_fingerprint(root);
        return;
    }

    state.root_available = true;
    llps_edac_scan_root(root, dir, &state);
    (void)closedir(dir);
    llps_edac_finalize_coverage(&state);
    *out_ecc_present = llps_edac_state_ecc_present(&state);
    *out_counters_clean = llps_edac_state_counters_clean(&state);
    *out_observation_fingerprint =
        llps_edac_final_fingerprint(root, &state);
    llps_edac_fill_observation(out_observation, &state);
}
