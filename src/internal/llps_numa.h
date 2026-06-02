/**
 * @file src/internal/llps_numa.h
 * @brief Host platform evidence collection and normalization.
 *
 * @details
 * Platform evidence code is kept out of the LLAM scheduler path unless
 * explicitly requested by readiness policy.
 */

#ifndef LLPS_NUMA_H
#define LLPS_NUMA_H

#include "llps.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LLPS_NUMA_SYSFS_ROOT              "/sys/devices/system/node"
#define LLPS_NUMA_ONLINE_TEXT_BYTES       (128u)
#define LLPS_NUMA_HAS_MEMORY_TEXT_BYTES   (128u)
#define LLPS_NUMA_HAS_NORMAL_MEMORY_TEXT_BYTES (128u)
#define LLPS_NUMA_MEMINFO_TEXT_BYTES      (256u)
#define LLPS_NUMA_DISTANCE_TEXT_BYTES     (256u)
#define LLPS_NUMA_PATH_BYTES              (256u)
#define LLPS_NUMA_NODE_MASK_WORDS         (8u)
#define LLPS_NUMA_NODE_MASK_WORD_BITS     ((uint32_t)(sizeof(unsigned long) * 8u))

#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ROOT_AVAILABLE (1u << 0u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ONLINE_AVAILABLE (1u << 1u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_MEMORY_AVAILABLE (1u << 2u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_NORMAL_MEMORY_AVAILABLE (1u << 3u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_DIRS_EXIST (1u << 4u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_ONLINE (1u << 5u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_MEMORY (1u << 6u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_HAS_NORMAL_MEMORY (1u << 7u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_MEMINFO (1u << 8u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_DISTANCE (1u << 9u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_SYMMETRIC_DISTANCE (1u << 10u)
#define LLPS_PHYSICAL_DOMAIN_TOPOLOGY_REQUIRED_MASK (0x7ffu)
#define LLPS_PHYSICAL_DOMAIN_DISTANCE_ENTRY_MIN \
    ((uint64_t)LLPS_SESSION_TMR_BANK_COUNT * \
     (uint64_t)LLPS_SESSION_TMR_BANK_COUNT)
#define LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_01 (1u << 0u)
#define LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_02 (1u << 1u)
#define LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_12 (1u << 2u)
#define LLPS_PHYSICAL_DOMAIN_DISTANCE_PAIR_MASK_ALL (0x7u)

bool llps_numa_make_single_node_mask(
    uint32_t domain_id,
    unsigned long node_mask[LLPS_NUMA_NODE_MASK_WORDS],
    unsigned long *maxnode_ref);

void llps_numa_probe_physical_memory_domains(
    const char *root,
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    bool *out_domains_observed,
    uint32_t *out_observation_fingerprint,
    uint32_t *out_topology_coverage,
    uint32_t *out_observed_count,
    uint64_t *out_memtotal_kib,
    uint64_t *out_distance_entries,
    uint64_t *out_distance_sum,
    uint32_t *out_distance_pair_coverage,
    uint64_t *out_distance_01,
    uint64_t *out_distance_02,
    uint64_t *out_distance_12);
/** @brief Build operator-configured synthetic NUMA topology evidence. */
void llps_numa_synthesize_physical_memory_domains(
    const uint32_t domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint64_t memtotal_kib_per_domain,
    uint64_t configured_local_distance,
    uint64_t configured_remote_distance,
    bool *out_domains_observed,
    uint32_t *out_observation_fingerprint,
    uint32_t *out_topology_coverage,
    uint32_t *out_observed_count,
    uint64_t *out_memtotal_kib,
    uint64_t *out_distance_entries,
    uint64_t *out_distance_sum,
    uint32_t *out_distance_pair_coverage,
    uint64_t *out_distance_01,
    uint64_t *out_distance_02,
    uint64_t *out_distance_12);

#endif /* LLPS_NUMA_H */
