/**
 * @file src/platform/llps_numa.c
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#include "llps_numa.h"

#include "llps_crc.h"
#include "llps_domain.h"

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool llps_numa_make_single_node_mask(
    const uint32_t domain_id,
    unsigned long node_mask[LLPS_NUMA_NODE_MASK_WORDS],
    unsigned long * const maxnode_ref) {
    const uint32_t word_index = domain_id / LLPS_NUMA_NODE_MASK_WORD_BITS;
    const uint32_t bit_index = domain_id % LLPS_NUMA_NODE_MASK_WORD_BITS;

    if ((node_mask == NULL) || (maxnode_ref == NULL) ||
        (word_index >= LLPS_NUMA_NODE_MASK_WORDS)) {
        return false;
    }

    for (size_t i = 0u; i < LLPS_NUMA_NODE_MASK_WORDS; ++i) {
        node_mask[i] = 0UL;
    }
    node_mask[word_index] = 1UL << bit_index;
    *maxnode_ref = (unsigned long)domain_id + 1UL;

    return true;
}

void llps_numa_synthesize_physical_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint64_t memtotal_kib_per_domain,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    bool * const out_domains_observed,
    uint32_t * const out_observation_fingerprint,
    uint32_t * const out_topology_coverage,
    uint32_t * const out_observed_count,
    uint64_t * const out_memtotal_kib,
    uint64_t * const out_distance_entries,
    uint64_t * const out_distance_sum,
    uint32_t * const out_distance_pair_coverage,
    uint64_t * const out_distance_01,
    uint64_t * const out_distance_02,
    uint64_t * const out_distance_12) {
    static const char source_label[] = "software-numa";
    const uint64_t local_distance =
        (configured_local_distance != 0u) ?
        configured_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t remote_distance =
        (configured_remote_distance != 0u) ?
        configured_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;
    uint64_t total_memtotal_kib = 0u;
    uint64_t total_distance_sum = 0u;

    if ((out_domains_observed == NULL) ||
        (out_observation_fingerprint == NULL) ||
        (out_topology_coverage == NULL) ||
        (out_observed_count == NULL) ||
        (out_memtotal_kib == NULL) ||
        (out_distance_entries == NULL) ||
        (out_distance_sum == NULL) ||
        (out_distance_pair_coverage == NULL) ||
        (out_distance_01 == NULL) ||
        (out_distance_02 == NULL) ||
        (out_distance_12 == NULL)) {
        return;
    }

    *out_domains_observed = false;
    *out_observation_fingerprint = 0u;
    *out_topology_coverage = 0u;
    *out_observed_count = 0u;
    *out_memtotal_kib = 0u;
    *out_distance_entries = 0u;
    *out_distance_sum = 0u;
    *out_distance_pair_coverage = 0u;
    *out_distance_01 = 0u;
    *out_distance_02 = 0u;
    *out_distance_12 = 0u;

    if (!llps_domain_ids_are_distinct(domain_ids) ||
        (memtotal_kib_per_domain == 0u) ||
        (memtotal_kib_per_domain >
         LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX)) {
        return;
    }

    total_memtotal_kib =
        memtotal_kib_per_domain * (uint64_t)LLPS_SESSION_TMR_BANK_COUNT;
    if ((local_distance == 0u) ||
        (remote_distance <= local_distance) ||
        (local_distance > LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ||
        (remote_distance > LLPS_SOFTWARE_NUMA_DISTANCE_MAX)) {
        return;
    }

    total_distance_sum =
        ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT * local_distance) +
        ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT *
         ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT - 1u) *
         remote_distance);

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 source_label,
                                                 sizeof(source_label));
    fingerprint = llps_crc32_update_u64(fingerprint,
                                        memtotal_kib_per_domain);
    fingerprint = llps_crc32_update_u64(fingerprint, local_distance);
    fingerprint = llps_crc32_update_u64(fingerprint, remote_distance);
    fingerprint = llps_crc32_update_u64(fingerprint, total_memtotal_kib);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN);
    fingerprint = llps_crc32_update_u64(fingerprint, total_distance_sum);
    for (size_t row = 0u; row < LLPS_SESSION_TMR_BANK_COUNT; ++row) {
        fingerprint = llps_crc32_update_u32(fingerprint, domain_ids[row]);
        for (size_t column = 0u;
             column < LLPS_SESSION_TMR_BANK_COUNT;
             ++column) {
            fingerprint = llps_crc32_update_u64(
                fingerprint,
                (row == column) ? local_distance : remote_distance);
        }
    }

    *out_domains_observed = true;
    *out_observation_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    *out_topology_coverage = LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK;
    *out_observed_count = LLPS_SESSION_TMR_BANK_COUNT;
    *out_memtotal_kib = total_memtotal_kib;
    *out_distance_entries = LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN;
    *out_distance_sum = total_distance_sum;
    *out_distance_pair_coverage = LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL;
    *out_distance_01 = remote_distance;
    *out_distance_02 = remote_distance;
    *out_distance_12 = remote_distance;
}

static bool llps_numa_join_node_path(char * const out_path,
                                     const size_t out_path_cap,
                                     const char * const root,
                                     const uint32_t domain_id) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path, out_path_cap, "%s/node%u", root,
                 (unsigned)domain_id);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_join_node_meminfo_path(char * const out_path,
                                             const size_t out_path_cap,
                                             const char * const root,
                                             const uint32_t domain_id) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path,
                 out_path_cap,
                 "%s/node%u/meminfo",
                 root,
                 (unsigned)domain_id);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_join_node_distance_path(char * const out_path,
                                              const size_t out_path_cap,
                                              const char * const root,
                                              const uint32_t domain_id) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path,
                 out_path_cap,
                 "%s/node%u/distance",
                 root,
                 (unsigned)domain_id);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_join_online_path(char * const out_path,
                                       const size_t out_path_cap,
                                       const char * const root) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path, out_path_cap, "%s/online", root);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_join_has_memory_path(char * const out_path,
                                           const size_t out_path_cap,
                                           const char * const root) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path, out_path_cap, "%s/has_memory", root);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_join_has_normal_memory_path(char * const out_path,
                                                  const size_t out_path_cap,
                                                  const char * const root) {
    int n = 0;

    if ((out_path == NULL) || (out_path_cap == 0u) || (root == NULL)) {
        return false;
    }

    n = snprintf(out_path, out_path_cap, "%s/has_normal_memory", root);
    if (n < 0) {
        return false;
    }

    return (size_t)n < out_path_cap;
}

static bool llps_numa_read_online_text(
    const char * const root,
    char text[LLPS_NUMA_ONLINE_TEXT_BYTES]) {
    FILE *fp = NULL;
    char online_path[LLPS_NUMA_PATH_BYTES];
    bool read_ok = false;

    if ((root == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_NUMA_ONLINE_TEXT_BYTES);
    if (!llps_numa_join_online_path(online_path, sizeof(online_path), root)) {
        return false;
    }

    fp = fopen(online_path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_NUMA_ONLINE_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_numa_read_has_memory_text(
    const char * const root,
    char text[LLPS_NUMA_HAS_MEMORY_TEXT_BYTES]) {
    FILE *fp = NULL;
    char has_memory_path[LLPS_NUMA_PATH_BYTES];
    bool read_ok = false;

    if ((root == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_NUMA_HAS_MEMORY_TEXT_BYTES);
    if (!llps_numa_join_has_memory_path(has_memory_path,
                                        sizeof(has_memory_path),
                                        root)) {
        return false;
    }

    fp = fopen(has_memory_path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_NUMA_HAS_MEMORY_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_numa_read_has_normal_memory_text(
    const char * const root,
    char text[LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES]) {
    FILE *fp = NULL;
    char has_normal_memory_path[LLPS_NUMA_PATH_BYTES];
    bool read_ok = false;

    if ((root == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES);
    if (!llps_numa_join_has_normal_memory_path(has_normal_memory_path,
                                               sizeof(has_normal_memory_path),
                                               root)) {
        return false;
    }

    fp = fopen(has_normal_memory_path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_numa_read_node_meminfo_text(
    const char * const root,
    const uint32_t domain_id,
    char text[LLPS_NUMA_MEMINFO_TEXT_BYTES]) {
    FILE *fp = NULL;
    char meminfo_path[LLPS_NUMA_PATH_BYTES];
    bool read_ok = false;

    if ((root == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_NUMA_MEMINFO_TEXT_BYTES);
    if (!llps_numa_join_node_meminfo_path(meminfo_path,
                                          sizeof(meminfo_path),
                                          root,
                                          domain_id)) {
        return false;
    }

    fp = fopen(meminfo_path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_NUMA_MEMINFO_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_numa_read_node_distance_text(
    const char * const root,
    const uint32_t domain_id,
    char text[LLPS_NUMA_DISTANCE_TEXT_BYTES]) {
    FILE *fp = NULL;
    char distance_path[LLPS_NUMA_PATH_BYTES];
    bool read_ok = false;

    if ((root == NULL) || (text == NULL)) {
        return false;
    }

    (void)memset(text, 0, LLPS_NUMA_DISTANCE_TEXT_BYTES);
    if (!llps_numa_join_node_distance_path(distance_path,
                                           sizeof(distance_path),
                                           root,
                                           domain_id)) {
        return false;
    }

    fp = fopen(distance_path, "r");
    if (fp == NULL) {
        return false;
    }

    if (fgets(text, (int)LLPS_NUMA_DISTANCE_TEXT_BYTES, fp) != NULL) {
        read_ok = true;
    }

    if (fclose(fp) != 0) {
        return false;
    }

    return read_ok;
}

static bool llps_numa_parse_u32(const char * const text,
                                size_t * const index,
                                uint32_t * const out_value) {
    uint32_t value = 0u;
    bool saw_digit = false;

    if ((text == NULL) || (index == NULL) || (out_value == NULL)) {
        return false;
    }

    for (size_t scan = 0u;
         (*index < LLPS_NUMA_ONLINE_TEXT_BYTES) &&
         (scan < LLPS_NUMA_ONLINE_TEXT_BYTES);
         ++scan) {
        const char c = text[*index];

        if ((c < '0') || (c > '9')) {
            break;
        }

        if (value > ((UINT32_MAX - (uint32_t)(c - '0')) / 10u)) {
            return false;
        }
        value = (value * 10u) + (uint32_t)(c - '0');
        saw_digit = true;
        ++(*index);
    }

    if (!saw_digit) {
        return false;
    }

    *out_value = value;
    return true;
}

static bool llps_numa_meminfo_text_matches_literal(
    const char * const text,
    const size_t start,
    const char * const literal,
    const size_t literal_len) {
    if ((text == NULL) || (literal == NULL) || (literal_len == 0u)) {
        return false;
    }

    for (size_t i = 0u; i < literal_len; ++i) {
        if ((start + i) >= LLPS_NUMA_MEMINFO_TEXT_BYTES) {
            return false;
        }
        if (text[start + i] != literal[i]) {
            return false;
        }
    }

    return true;
}

static void llps_numa_meminfo_skip_spaces(const char * const text,
                                          size_t * const index) {
    if ((text == NULL) || (index == NULL)) {
        return;
    }

    for (size_t scan = 0u;
         (*index < LLPS_NUMA_MEMINFO_TEXT_BYTES) &&
         (scan < LLPS_NUMA_MEMINFO_TEXT_BYTES);
         ++scan) {
        const char c = text[*index];

        if ((c != ' ') && (c != '\t')) {
            break;
        }
        ++(*index);
    }
}

static bool llps_numa_meminfo_parse_u64(const char * const text,
                                        size_t * const index,
                                        uint64_t * const out_value) {
    uint64_t value = 0u;
    bool saw_digit = false;

    if ((text == NULL) || (index == NULL) || (out_value == NULL)) {
        return false;
    }

    for (size_t scan = 0u;
         (*index < LLPS_NUMA_MEMINFO_TEXT_BYTES) &&
         (scan < LLPS_NUMA_MEMINFO_TEXT_BYTES);
         ++scan) {
        const char c = text[*index];

        if ((c < '0') || (c > '9')) {
            break;
        }
        if (value > ((UINT64_MAX - (uint64_t)(c - '0')) / 10u)) {
            return false;
        }
        value = (value * 10u) + (uint64_t)(c - '0');
        saw_digit = true;
        ++(*index);
    }

    if (!saw_digit) {
        return false;
    }

    *out_value = value;
    return true;
}

static bool llps_numa_meminfo_text_memtotal_kib(
    const char * const text,
    const uint32_t domain_id,
    uint64_t * const out_memtotal_kib) {
    size_t i = 0u;
    uint32_t observed_domain_id = 0u;
    uint64_t memtotal_kib = 0u;

    if ((text == NULL) || (out_memtotal_kib == NULL)) {
        return false;
    }

    *out_memtotal_kib = 0u;
    if (!llps_numa_meminfo_text_matches_literal(text, i, "Node", 4u)) {
        return false;
    }
    i += 4u;
    llps_numa_meminfo_skip_spaces(text, &i);
    if (!llps_numa_parse_u32(text, &i, &observed_domain_id)) {
        return false;
    }
    if (observed_domain_id != domain_id) {
        return false;
    }
    llps_numa_meminfo_skip_spaces(text, &i);
    if (!llps_numa_meminfo_text_matches_literal(text, i, "MemTotal:", 9u)) {
        return false;
    }
    i += 9u;
    llps_numa_meminfo_skip_spaces(text, &i);
    if (!llps_numa_meminfo_parse_u64(text, &i, &memtotal_kib)) {
        return false;
    }
    if (memtotal_kib == 0u) {
        return false;
    }
    llps_numa_meminfo_skip_spaces(text, &i);
    if (!llps_numa_meminfo_text_matches_literal(text, i, "kB", 2u)) {
        return false;
    }

    *out_memtotal_kib = memtotal_kib;
    return true;
}

static bool llps_numa_distance_prepare_outputs(
    const uint32_t self_domain_id,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t out_distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_self_domain_index) {
    if ((domain_ids == NULL) || (out_distance_to_domains == NULL) ||
        (out_self_domain_index == NULL)) {
        return false;
    }

    *out_self_domain_index = LLPS_SESSION_TMR_BANK_COUNT;
    for (size_t domain_index = 0u;
         domain_index < LLPS_SESSION_TMR_BANK_COUNT;
         ++domain_index) {
        out_distance_to_domains[domain_index] = 0u;
        if (domain_ids[domain_index] == self_domain_id) {
            *out_self_domain_index = (uint32_t)domain_index;
        }
    }
    return *out_self_domain_index < LLPS_SESSION_TMR_BANK_COUNT;
}

static bool llps_numa_distance_scan_next(
    const char * const text,
    size_t * const io_i,
    uint32_t * const out_distance,
    bool * const out_has_distance,
    bool * const out_done) {
    uint32_t distance = 0u;
    bool saw_digit = false;

    if ((text == NULL) || (io_i == NULL) || (out_distance == NULL) ||
        (out_has_distance == NULL) || (out_done == NULL)) {
        return false;
    }

    *out_has_distance = false;
    *out_done = false;
    const char c = text[*io_i];
    if (c == '\0') {
        *out_done = true;
        return true;
    }
    if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r')) {
        ++(*io_i);
        return true;
    }

    for (size_t digit_scan = 0u;
         (*io_i < LLPS_NUMA_DISTANCE_TEXT_BYTES) &&
         (digit_scan < LLPS_NUMA_DISTANCE_TEXT_BYTES);
         ++digit_scan) {
        const char digit = text[*io_i];

        if ((digit < '0') || (digit > '9')) {
            break;
        }
        if (distance > ((UINT32_MAX - (uint32_t)(digit - '0')) / 10u)) {
            return false;
        }
        distance = (distance * 10u) + (uint32_t)(digit - '0');
        saw_digit = true;
        ++(*io_i);
    }
    if (!saw_digit || (distance == 0u)) {
        return false;
    }
    if ((*io_i < LLPS_NUMA_DISTANCE_TEXT_BYTES) &&
        (text[*io_i] != '\0') && (text[*io_i] != ' ') &&
        (text[*io_i] != '\t') && (text[*io_i] != '\n') &&
        (text[*io_i] != '\r')) {
        return false;
    }
    *out_distance = distance;
    *out_has_distance = true;
    return true;
}

static bool llps_numa_distance_record_entry(
    const uint32_t distance,
    const uint32_t entry_index,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t out_distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const io_distance_count,
    uint64_t * const io_distance_sum,
    uint32_t * const io_min_distance,
    uint32_t * const io_min_distance_count) {
    if ((*io_distance_count == UINT32_MAX) ||
        ((UINT64_MAX - *io_distance_sum) < (uint64_t)distance)) {
        return false;
    }

    ++(*io_distance_count);
    *io_distance_sum += (uint64_t)distance;
    if (distance < *io_min_distance) {
        *io_min_distance = distance;
        *io_min_distance_count = 1u;
    } else if (distance == *io_min_distance) {
        if (*io_min_distance_count == UINT32_MAX) {
            return false;
        }
        ++(*io_min_distance_count);
    }
    for (size_t domain_index = 0u;
         domain_index < LLPS_SESSION_TMR_BANK_COUNT;
         ++domain_index) {
        if (entry_index == domain_ids[domain_index]) {
            out_distance_to_domains[domain_index] = distance;
        }
    }
    return true;
}

static bool llps_numa_distance_outputs_are_valid(
    const uint32_t distance_count,
    const uint32_t min_distance,
    const uint32_t min_distance_count,
    const uint32_t self_domain_index,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t out_distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((distance_count < LLPS_SESSION_TMR_BANK_COUNT) ||
        (min_distance_count != 1u) ||
        (out_distance_to_domains[self_domain_index] != min_distance)) {
        return false;
    }

    for (size_t domain_index = 0u;
         domain_index < LLPS_SESSION_TMR_BANK_COUNT;
         ++domain_index) {
        if ((domain_ids[domain_index] >= distance_count) ||
            (out_distance_to_domains[domain_index] == 0u) ||
            ((domain_index != (size_t)self_domain_index) &&
             (out_distance_to_domains[domain_index] <=
              out_distance_to_domains[self_domain_index]))) {
            return false;
        }
    }
    return true;
}

static bool llps_numa_distance_scan_all(
    const char * const text,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t out_distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const io_distance_count,
    uint64_t * const io_distance_sum,
    uint32_t * const io_min_distance,
    uint32_t * const io_min_distance_count) {
    size_t i = 0u;

    for (size_t scan = 0u;
         (i < LLPS_NUMA_DISTANCE_TEXT_BYTES) &&
         (scan < LLPS_NUMA_DISTANCE_TEXT_BYTES);
         ++scan) {
        uint32_t distance = 0u;
        const uint32_t entry_index = *io_distance_count;
        bool has_distance = false;
        bool done = false;

        if (!llps_numa_distance_scan_next(text,
                                          &i,
                                          &distance,
                                          &has_distance,
                                          &done)) {
            return false;
        }
        if (done) {
            break;
        }
        if (!has_distance) {
            continue;
        }
        if (!llps_numa_distance_record_entry(distance,
                                             entry_index,
                                             domain_ids,
                                             out_distance_to_domains,
                                             io_distance_count,
                                             io_distance_sum,
                                             io_min_distance,
                                             io_min_distance_count)) {
            return false;
        }
    }
    return true;
}

static bool llps_numa_distance_text_parse(
    const char * const text,
    const uint32_t self_domain_id,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_distance_count,
    uint64_t * const out_distance_sum,
    uint32_t out_distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT]) {
    uint32_t distance_count = 0u;
    uint64_t distance_sum = 0u;
    uint32_t min_distance = UINT32_MAX;
    uint32_t min_distance_count = 0u;
    uint32_t self_domain_index = LLPS_SESSION_TMR_BANK_COUNT;

    if ((text == NULL) ||
        (domain_ids == NULL) ||
        (out_distance_count == NULL) ||
        (out_distance_sum == NULL) ||
        (out_distance_to_domains == NULL)) {
        return false;
    }

    *out_distance_count = 0u;
    *out_distance_sum = 0u;
    if (!llps_numa_distance_prepare_outputs(self_domain_id,
                                            domain_ids,
                                            out_distance_to_domains,
                                            &self_domain_index)) {
        return false;
    }

    if (!llps_numa_distance_scan_all(text,
                                     domain_ids,
                                     out_distance_to_domains,
                                     &distance_count,
                                     &distance_sum,
                                     &min_distance,
                                     &min_distance_count)) {
        return false;
    }

    if (!llps_numa_distance_outputs_are_valid(distance_count,
                                              min_distance,
                                              min_distance_count,
                                              self_domain_index,
                                              domain_ids,
                                              out_distance_to_domains)) {
        return false;
    }

    *out_distance_count = distance_count;
    *out_distance_sum = distance_sum;
    return true;
}

static bool llps_numa_online_parse_range(const char * const text,
                                         size_t * const io_i,
                                         uint32_t * const out_first,
                                         uint32_t * const out_last) {
    if ((text == NULL) || (io_i == NULL) ||
        (out_first == NULL) || (out_last == NULL)) {
        return false;
    }

    if (!llps_numa_parse_u32(text, io_i, out_first)) {
        return false;
    }
    *out_last = *out_first;
    if ((*io_i < LLPS_NUMA_ONLINE_TEXT_BYTES) && (text[*io_i] == '-')) {
        ++(*io_i);
        if (!llps_numa_parse_u32(text, io_i, out_last)) {
            return false;
        }
        if (*out_last < *out_first) {
            return false;
        }
    }
    return true;
}

static bool llps_numa_online_skip_range_tail(const char * const text,
                                             size_t * const io_i) {
    if ((text == NULL) || (io_i == NULL)) {
        return false;
    }

    for (size_t tail_scan = 0u;
         (*io_i < LLPS_NUMA_ONLINE_TEXT_BYTES) &&
         (tail_scan < LLPS_NUMA_ONLINE_TEXT_BYTES);
         ++tail_scan) {
        const char tail = text[*io_i];

        if ((tail == '\0') || (tail == ',')) {
            break;
        }
        if ((tail != ' ') && (tail != '\t') &&
            (tail != '\n') && (tail != '\r')) {
            return false;
        }
        ++(*io_i);
    }
    return true;
}

static bool llps_numa_online_text_contains_domain(
    const char * const text,
    const uint32_t domain_id) {
    size_t i = 0u;

    if (text == NULL) {
        return false;
    }

    for (size_t scan = 0u;
         (i < LLPS_NUMA_ONLINE_TEXT_BYTES) &&
         (scan < LLPS_NUMA_ONLINE_TEXT_BYTES);
         ++scan) {
        uint32_t first = 0u;
        uint32_t last = 0u;
        const char c = text[i];

        if (c == '\0') {
            break;
        }

        if ((c == ',') || (c == ' ') || (c == '\t') ||
            (c == '\n') || (c == '\r')) {
            ++i;
            continue;
        }

        if (!llps_numa_online_parse_range(text, &i, &first, &last)) {
            return false;
        }

        if ((domain_id >= first) && (domain_id <= last)) {
            return true;
        }

        if (!llps_numa_online_skip_range_tail(text, &i)) {
            return false;
        }
    }

    return false;
}

static bool llps_numa_node_dir_exists(const char * const root,
                                      const uint32_t domain_id) {
    DIR *dir = NULL;
    char node_path[LLPS_NUMA_PATH_BYTES];

    if (!llps_numa_join_node_path(node_path, sizeof(node_path), root,
                                  domain_id)) {
        return false;
    }

    dir = opendir(node_path);
    if (dir == NULL) {
        return false;
    }

    (void)closedir(dir);
    return true;
}

void llps_numa_probe_physical_memory_domains(
    const char * const root,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool * const out_domains_observed,
    uint32_t * const out_observation_fingerprint,
    uint32_t * const out_topology_coverage,
    uint32_t * const out_observed_count,
    uint64_t * const out_memtotal_kib,
    uint64_t * const out_distance_entries,
    uint64_t * const out_distance_sum,
    uint32_t * const out_distance_pair_coverage,
    uint64_t * const out_distance_01,
    uint64_t * const out_distance_02,
    uint64_t * const out_distance_12) {
    char online_text[LLPS_NUMA_ONLINE_TEXT_BYTES];
    char has_memory_text[LLPS_NUMA_HAS_MEMORY_TEXT_BYTES];
    char has_normal_memory_text[LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES];
    bool root_available = false;
    bool online_available = false;
    bool has_memory_available = false;
    bool has_normal_memory_available = false;
    bool all_dirs_exist = true;
    bool all_domains_online = true;
    bool all_domains_have_memory = true;
    bool all_domains_have_normal_memory = true;
    bool all_domains_have_meminfo = true;
    bool all_domains_have_distance = true;
    bool all_domains_have_symmetric_distance = true;
    uint32_t topology_coverage = 0u;
    uint32_t observed_count = 0u;
    uint32_t domain_mix = 0u;
    uint32_t distance_matrix[LLPS_SESSION_TMR_BANK_COUNT]
                            [LLPS_SESSION_TMR_BANK_COUNT];
    uint64_t total_memtotal_kib = 0u;
    uint64_t total_distance_entries = 0u;
    uint64_t total_distance_sum = 0u;
    uint32_t distance_pair_coverage = 0u;
    uint64_t distance_01 = 0u;
    uint64_t distance_02 = 0u;
    uint64_t distance_12 = 0u;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if ((out_domains_observed == NULL) ||
        (out_observation_fingerprint == NULL) ||
        (out_topology_coverage == NULL) ||
        (out_observed_count == NULL) ||
        (out_memtotal_kib == NULL) ||
        (out_distance_entries == NULL) ||
        (out_distance_sum == NULL) ||
        (out_distance_pair_coverage == NULL) ||
        (out_distance_01 == NULL) ||
        (out_distance_02 == NULL) ||
        (out_distance_12 == NULL)) {
        return;
    }

    *out_domains_observed = false;
    *out_observation_fingerprint = 0u;
    *out_topology_coverage = 0u;
    *out_observed_count = 0u;
    *out_memtotal_kib = 0u;
    *out_distance_entries = 0u;
    *out_distance_sum = 0u;
    *out_distance_pair_coverage = 0u;
    *out_distance_01 = 0u;
    *out_distance_02 = 0u;
    *out_distance_12 = 0u;
    (void)memset(online_text, 0, sizeof(online_text));
    (void)memset(has_memory_text, 0, sizeof(has_memory_text));
    (void)memset(has_normal_memory_text, 0, sizeof(has_normal_memory_text));
    (void)memset(distance_matrix, 0, sizeof(distance_matrix));

    if ((root != NULL) && llps_domain_ids_are_distinct(domain_ids)) {
        DIR * const root_dir = opendir(root);

        if (root_dir != NULL) {
            root_available = true;
            (void)closedir(root_dir);
            online_available = llps_numa_read_online_text(root, online_text);
            has_memory_available =
                llps_numa_read_has_memory_text(root, has_memory_text);
            has_normal_memory_available =
                llps_numa_read_has_normal_memory_text(
                    root,
                    has_normal_memory_text);
        }

        for (size_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            const uint32_t domain_id = domain_ids[i];
            char meminfo_text[LLPS_NUMA_MEMINFO_TEXT_BYTES];
            char distance_text[LLPS_NUMA_DISTANCE_TEXT_BYTES];
            uint64_t memtotal_kib = 0u;
            uint32_t distance_count = 0u;
            uint64_t distance_sum = 0u;
            uint32_t distance_to_domains[LLPS_SESSION_TMR_BANK_COUNT] =
                { 0u, 0u, 0u };
            const bool dir_exists =
                root_available &&
                llps_numa_node_dir_exists(root, domain_id);
            const bool online =
                online_available &&
                llps_numa_online_text_contains_domain(online_text, domain_id);
            const bool has_memory =
                has_memory_available &&
                llps_numa_online_text_contains_domain(has_memory_text,
                                                      domain_id);
            const bool has_normal_memory =
                has_normal_memory_available &&
                llps_numa_online_text_contains_domain(
                    has_normal_memory_text,
                    domain_id);
            bool meminfo_available = false;
            bool meminfo_valid = false;
            bool distance_available = false;
            bool distance_valid = false;
            bool domain_observed = false;
            uint32_t domain_fingerprint = LLPS_SESSION_CRC_INIT;

            (void)memset(meminfo_text, 0, sizeof(meminfo_text));
            (void)memset(distance_text, 0, sizeof(distance_text));
            meminfo_available =
                root_available &&
                llps_numa_read_node_meminfo_text(root,
                                                 domain_id,
                                                 meminfo_text);
            meminfo_valid =
                meminfo_available &&
                llps_numa_meminfo_text_memtotal_kib(meminfo_text,
                                                    domain_id,
                                                    &memtotal_kib);
            distance_available =
                root_available &&
                llps_numa_read_node_distance_text(root,
                                                  domain_id,
                                                  distance_text);
            distance_valid =
                distance_available &&
                llps_numa_distance_text_parse(distance_text,
                                             domain_id,
                                             domain_ids,
                                             &distance_count,
                                             &distance_sum,
                                             distance_to_domains);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint, domain_id);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      dir_exists ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      online ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      has_memory ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      has_normal_memory ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      meminfo_available ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      meminfo_valid ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u64(domain_fingerprint, memtotal_kib);
            domain_fingerprint =
                llps_crc32_update_cstr_bounded(domain_fingerprint,
                                               meminfo_text,
                                               LLPS_NUMA_MEMINFO_TEXT_BYTES);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      distance_available ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint,
                                      distance_valid ? 1u : 0u);
            domain_fingerprint =
                llps_crc32_update_u32(domain_fingerprint, distance_count);
            domain_fingerprint =
                llps_crc32_update_u64(domain_fingerprint, distance_sum);
            for (size_t distance_index = 0u;
                 distance_index < LLPS_SESSION_TMR_BANK_COUNT;
                 ++distance_index) {
                domain_fingerprint = llps_crc32_update_u32(
                    domain_fingerprint,
                    distance_to_domains[distance_index]);
            }
            domain_fingerprint =
                llps_crc32_update_cstr_bounded(domain_fingerprint,
                                               distance_text,
                                               LLPS_NUMA_DISTANCE_TEXT_BYTES);
            domain_mix ^= (domain_fingerprint ^ LLPS_SESSION_CRC_XOROUT);
            if (meminfo_valid) {
                if ((UINT64_MAX - total_memtotal_kib) < memtotal_kib) {
                    total_memtotal_kib = UINT64_MAX;
                    all_domains_have_meminfo = false;
                } else {
                    total_memtotal_kib += memtotal_kib;
                }
            }
            if (distance_valid) {
                for (size_t distance_index = 0u;
                     distance_index < LLPS_SESSION_TMR_BANK_COUNT;
                     ++distance_index) {
                    distance_matrix[i][distance_index] =
                        distance_to_domains[distance_index];
                }
                if (((UINT64_MAX - total_distance_entries) <
                     (uint64_t)distance_count) ||
                    ((UINT64_MAX - total_distance_sum) < distance_sum)) {
                    total_distance_entries = UINT64_MAX;
                    total_distance_sum = UINT64_MAX;
                    all_domains_have_distance = false;
                } else {
                    total_distance_entries += (uint64_t)distance_count;
                    total_distance_sum += distance_sum;
                }
            }

            if (!dir_exists) {
                all_dirs_exist = false;
            }
            if (!online) {
                all_domains_online = false;
            }
            if (!has_memory) {
                all_domains_have_memory = false;
            }
            if (!has_normal_memory) {
                all_domains_have_normal_memory = false;
            }
            if (!meminfo_valid) {
                all_domains_have_meminfo = false;
            }
            if (!distance_valid) {
                all_domains_have_distance = false;
            }

            domain_observed =
                dir_exists && online && has_memory && has_normal_memory &&
                meminfo_valid && distance_valid;
            if (domain_observed) {
                ++observed_count;
            }
        }
    } else {
        all_dirs_exist = false;
        all_domains_online = false;
        all_domains_have_memory = false;
        all_domains_have_normal_memory = false;
        all_domains_have_meminfo = false;
        all_domains_have_distance = false;
        all_domains_have_symmetric_distance = false;
    }

    if (all_domains_have_distance) {
        for (size_t lhs = 0u; lhs < LLPS_SESSION_TMR_BANK_COUNT; ++lhs) {
            for (size_t rhs = lhs + 1u;
                 rhs < LLPS_SESSION_TMR_BANK_COUNT;
                 ++rhs) {
                const uint32_t pair_distance = distance_matrix[lhs][rhs];

                if ((distance_matrix[lhs][rhs] == 0u) ||
                    (distance_matrix[rhs][lhs] == 0u) ||
                    (distance_matrix[lhs][rhs] != distance_matrix[rhs][lhs])) {
                    all_domains_have_symmetric_distance = false;
                } else if ((lhs == 0u) && (rhs == 1u)) {
                    distance_pair_coverage |=
                        LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_01;
                    distance_01 = (uint64_t)pair_distance;
                } else if ((lhs == 0u) && (rhs == 2u)) {
                    distance_pair_coverage |=
                        LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_02;
                    distance_02 = (uint64_t)pair_distance;
                } else if ((lhs == 1u) && (rhs == 2u)) {
                    distance_pair_coverage |=
                        LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_12;
                    distance_12 = (uint64_t)pair_distance;
                } else {
                    all_domains_have_symmetric_distance = false;
                }
            }
        }
    } else {
        all_domains_have_symmetric_distance = false;
    }

    if (root_available) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ROOT_AVAILABLE;
    }
    if (online_available) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ONLINE_AVAILABLE;
    }
    if (has_memory_available) {
        topology_coverage |=
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_MEMORY_AVAILABLE;
    }
    if (has_normal_memory_available) {
        topology_coverage |=
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_NORMAL_MEMORY_AVAILABLE;
    }
    if (all_dirs_exist) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_DIRS_EXIST;
    }
    if (all_domains_online) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ONLINE;
    }
    if (all_domains_have_memory) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_MEMORY;
    }
    if (all_domains_have_normal_memory) {
        topology_coverage |=
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_NORMAL_MEMORY;
    }
    if (all_domains_have_meminfo) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_MEMINFO;
    }
    if (all_domains_have_distance) {
        topology_coverage |= LLPS_PHYSICAL_DOMAIN_TOPOLOGY_DISTANCE;
    }
    if (all_domains_have_symmetric_distance) {
        topology_coverage |=
            LLPS_PHYSICAL_DOMAIN_TOPOLOGY_SYMMETRIC_DISTANCE;
    }

    fingerprint = llps_crc32_update_cstr_bounded(fingerprint,
                                                 root,
                                                 LLPS_NUMA_PATH_BYTES);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        root_available ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        online_available ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        has_memory_available ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        has_normal_memory_available ? 1u : 0u);
    fingerprint = llps_crc32_update_cstr_bounded(
        fingerprint,
        online_text,
        LLPS_NUMA_ONLINE_TEXT_BYTES);
    fingerprint = llps_crc32_update_cstr_bounded(
        fingerprint,
        has_memory_text,
        LLPS_NUMA_HAS_MEMORY_TEXT_BYTES);
    fingerprint = llps_crc32_update_cstr_bounded(
        fingerprint,
        has_normal_memory_text,
        LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        all_dirs_exist ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        all_domains_online ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        all_domains_have_memory ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        all_domains_have_normal_memory ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        all_domains_have_meminfo ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        all_domains_have_distance ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(
        fingerprint,
        all_domains_have_symmetric_distance ? 1u : 0u);
    fingerprint = llps_crc32_update_u32(fingerprint, topology_coverage);
    fingerprint = llps_crc32_update_u32(fingerprint, observed_count);
    fingerprint = llps_crc32_update_u64(fingerprint, total_memtotal_kib);
    fingerprint = llps_crc32_update_u64(fingerprint, total_distance_entries);
    fingerprint = llps_crc32_update_u64(fingerprint, total_distance_sum);
    fingerprint = llps_crc32_update_u32(fingerprint, distance_pair_coverage);
    fingerprint = llps_crc32_update_u64(fingerprint, distance_01);
    fingerprint = llps_crc32_update_u64(fingerprint, distance_02);
    fingerprint = llps_crc32_update_u64(fingerprint, distance_12);
    for (size_t row = 0u; row < LLPS_SESSION_TMR_BANK_COUNT; ++row) {
        for (size_t column = 0u;
             column < LLPS_SESSION_TMR_BANK_COUNT;
             ++column) {
            fingerprint = llps_crc32_update_u32(fingerprint,
                                                distance_matrix[row][column]);
        }
    }
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        LLPS_SESSION_TMR_BANK_COUNT);
    fingerprint = llps_crc32_update_u32(fingerprint, domain_mix);

    *out_domains_observed =
        ((topology_coverage & LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) ==
         LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK) &&
        (observed_count == LLPS_SESSION_TMR_BANK_COUNT) &&
        (total_memtotal_kib != 0u) &&
        (total_distance_entries >= LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN) &&
        (total_distance_sum != 0u) &&
        (distance_pair_coverage ==
         LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL) &&
        (distance_01 != 0u) &&
        (distance_02 != 0u) &&
        (distance_12 != 0u);
    *out_observation_fingerprint =
        llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    *out_topology_coverage = topology_coverage;
    *out_observed_count = observed_count;
    *out_memtotal_kib = total_memtotal_kib;
    *out_distance_entries = total_distance_entries;
    *out_distance_sum = total_distance_sum;
    *out_distance_pair_coverage = distance_pair_coverage;
    *out_distance_01 = distance_01;
    *out_distance_02 = distance_02;
    *out_distance_12 = distance_12;
}
