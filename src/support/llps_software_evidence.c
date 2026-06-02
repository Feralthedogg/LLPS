/**
 * @file src/support/llps_software_evidence.c
 * @brief Self-tested synthetic platform evidence helpers.
 */

#include "llps_software_evidence.h"

#include "llps_crc.h"
#include "llps_domain.h"
#include "llps_edac.h"
#include "llps_secded.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LLPS_SOFTWARE_DIMM_BANK_MAGIC       (0xD1AAB11Du)
#define LLPS_SOFTWARE_DIMM_TEST_VALUE       UINT64_C(0x1122334455667788)
#define LLPS_SOFTWARE_DIMM_TEST_GENERATION  (1u)
#define LLPS_SOFTWARE_DIMM_TEST_SCRUB       (1u)
#define LLPS_SOFTWARE_SECDED_DATA_BITS      (64u)
#define LLPS_SOFTWARE_SECDED_ECC_BITS       (8u)
#define LLPS_SOFTWARE_SECDED_CODE_BITS \
    (LLPS_SOFTWARE_SECDED_DATA_BITS + LLPS_SOFTWARE_SECDED_ECC_BITS)

typedef struct {
    uint32_t magic;
    uint32_t bank_id;
    uint64_t value;
    uint64_t value_inverse;
    uint8_t ecc;
    uint8_t ecc_inverse;
    uint32_t generation;
    uint32_t generation_inverse;
    uint32_t scrub_generation;
    uint32_t scrub_generation_inverse;
    uint32_t crc;
    uint32_t crc_inverse;
} llps_software_dimm_bank_t;

bool llps_platform_evidence_mode_is_valid(const uint32_t mode) {
    return (mode == LLPS_PLATFORM_EVIDENCE_MODE_REAL) ||
           (mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) ||
           (mode == LLPS_PLATFORM_EVIDENCE_MODE_HYBRID);
}

bool llps_platform_evidence_mode_uses_software(const uint32_t mode) {
    return (mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) ||
           (mode == LLPS_PLATFORM_EVIDENCE_MODE_HYBRID);
}

const char *llps_platform_evidence_mode_text(const uint32_t mode) {
    switch (mode) {
    case LLPS_PLATFORM_EVIDENCE_MODE_REAL:
        return "real";
    case LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC:
        return "synthetic";
    case LLPS_PLATFORM_EVIDENCE_MODE_HYBRID:
        return "hybrid";
    default:
        return "invalid";
    }
}

const char *llps_platform_evidence_scope_text(const uint32_t mode) {
    switch (mode) {
    case LLPS_PLATFORM_EVIDENCE_MODE_REAL:
        return "real-linux-observation";
    case LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC:
        return "software-platform-model";
    case LLPS_PLATFORM_EVIDENCE_MODE_HYBRID:
        return "hybrid-linux-and-software-model";
    default:
        return "invalid";
    }
}

const char *llps_software_fault_injection_mode_text(const uint32_t mode) {
    switch (mode) {
    case LLPS_SOFTWARE_FAULT_INJECTION_OFF:
        return "off";
    case LLPS_SOFTWARE_FAULT_INJECTION_SINGLE:
        return "single";
    case LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE:
        return "double";
    case LLPS_SOFTWARE_FAULT_INJECTION_FULL:
        return "full";
    default:
        return "invalid";
    }
}

const char *llps_ecc_evidence_scope_text(
    const uint32_t mode,
    const bool software_ecc_enabled) {
    if (llps_platform_evidence_mode_uses_software(mode) &&
        software_ecc_enabled) {
        return "software-ecc-model";
    }
    if ((mode == LLPS_PLATFORM_EVIDENCE_MODE_REAL) ||
        (mode == LLPS_PLATFORM_EVIDENCE_MODE_HYBRID)) {
        return "linux-edac-observation";
    }
    if (mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
        return "none";
    }
    return "invalid";
}

const char *llps_physical_memory_evidence_scope_text(
    const uint32_t mode,
    const bool software_numa_enabled) {
    if (llps_platform_evidence_mode_uses_software(mode) &&
        software_numa_enabled) {
        return "software-numa-model";
    }
    if ((mode == LLPS_PLATFORM_EVIDENCE_MODE_REAL) ||
        (mode == LLPS_PLATFORM_EVIDENCE_MODE_HYBRID)) {
        return "linux-numa-observation";
    }
    if (mode == LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC) {
        return "none";
    }
    return "invalid";
}

const char *llps_independent_tmr_evidence_scope_text(const uint32_t mode) {
    switch (mode) {
    case LLPS_PLATFORM_EVIDENCE_MODE_REAL:
        return "operator-attested-hardware-domains";
    case LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC:
        return "software-domain-model";
    case LLPS_PLATFORM_EVIDENCE_MODE_HYBRID:
        return "operator-attested-or-software-domain-model";
    default:
        return "invalid";
    }
}

static bool llps_software_fault_injection_mode_is_valid(
    const uint32_t mode) {
    return mode <= LLPS_SOFTWARE_FAULT_INJECTION_MAX;
}

static uint32_t llps_software_fault_injection_mask_for_mode(
    const uint32_t mode,
    const uint32_t observed_coverage) {
    switch (mode) {
    case LLPS_SOFTWARE_FAULT_INJECTION_OFF:
        return 0u;
    case LLPS_SOFTWARE_FAULT_INJECTION_SINGLE:
        return LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_SINGLE_REPAIR |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB_CORRUPTION |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_RUNTIME_PATROL;
    case LLPS_SOFTWARE_FAULT_INJECTION_DOUBLE:
        return LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_FAIL_CLOSED |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_BIT_SWEEP |
               LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_STALE_METADATA_FAIL_CLOSED;
    case LLPS_SOFTWARE_FAULT_INJECTION_FULL:
        return observed_coverage;
    default:
        return 0u;
    }
}

static uint32_t llps_software_dimm_bank_crc(
    const llps_software_dimm_bank_t * const bank) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (bank == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, bank->magic);
    crc = llps_crc32_update_u32(crc, bank->bank_id);
    crc = llps_crc32_update_u64(crc, bank->value);
    crc = llps_crc32_update_u64(crc, bank->value_inverse);
    crc = llps_crc32_update_byte(crc, bank->ecc);
    crc = llps_crc32_update_byte(crc, bank->ecc_inverse);
    crc = llps_crc32_update_u32(crc, bank->generation);
    crc = llps_crc32_update_u32(crc, bank->generation_inverse);
    crc = llps_crc32_update_u32(crc, bank->scrub_generation);
    crc = llps_crc32_update_u32(crc, bank->scrub_generation_inverse);

    return crc ^ LLPS_SESSION_CRC_XOROUT;
}

static void llps_software_dimm_bank_seal(
    llps_software_dimm_bank_t * const bank,
    const uint32_t bank_id,
    const uint64_t value,
    const uint32_t generation,
    const uint32_t scrub_generation) {
    if (bank == NULL) {
        return;
    }

    bank->magic = LLPS_SOFTWARE_DIMM_BANK_MAGIC;
    bank->bank_id = bank_id;
    bank->value = value;
    bank->value_inverse = ~value;
    bank->ecc = llps_secded_encode_u64(value, 64u);
    bank->ecc_inverse = (uint8_t)(~bank->ecc);
    bank->generation = generation;
    bank->generation_inverse = ~generation;
    bank->scrub_generation = scrub_generation;
    bank->scrub_generation_inverse = ~scrub_generation;
    bank->crc = llps_software_dimm_bank_crc(bank);
    bank->crc_inverse = ~bank->crc;
}

static bool llps_software_dimm_bank_is_valid(
    const llps_software_dimm_bank_t * const bank,
    const uint32_t expected_bank_id) {
    if (bank == NULL) {
        return false;
    }

    return (bank->magic == LLPS_SOFTWARE_DIMM_BANK_MAGIC) &&
           (bank->bank_id == expected_bank_id) &&
           (bank->value_inverse == ~bank->value) &&
           (bank->ecc_inverse == (uint8_t)(~bank->ecc)) &&
           (bank->generation_inverse == ~bank->generation) &&
           (bank->scrub_generation_inverse == ~bank->scrub_generation) &&
           llps_secded_is_valid_u64(bank->value, 64u, bank->ecc) &&
           (bank->crc_inverse == ~bank->crc) &&
           (bank->crc == llps_software_dimm_bank_crc(bank));
}

static bool llps_software_dimm_scrub(
    const llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (banks == NULL) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (!llps_software_dimm_bank_is_valid(&banks[i], i)) {
            return false;
        }
    }

    return true;
}

static bool llps_software_dimm_bank_payload_equal(
    const llps_software_dimm_bank_t * const lhs,
    const llps_software_dimm_bank_t * const rhs) {
    if ((lhs == NULL) || (rhs == NULL)) {
        return false;
    }

    return (lhs->value == rhs->value) &&
           (lhs->generation == rhs->generation) &&
           (lhs->scrub_generation == rhs->scrub_generation);
}

static bool llps_software_ecc_dimm_count_is_valid(const uint32_t dimm_count) {
    return (dimm_count != 0u) &&
           (dimm_count <= LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX);
}

static bool llps_software_ecc_controller_count_is_valid(
    const uint32_t controller_count,
    const uint32_t dimm_count) {
    return (controller_count != 0u) &&
           (controller_count <= LLPS_SOFTWARE_ECC_CONTROLLER_COUNT_MAX) &&
           (controller_count <= dimm_count);
}

static bool llps_software_ecc_scrub_rate_is_valid(const uint64_t scrub_rate) {
    return (scrub_rate != 0u) &&
           (scrub_rate <= LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX);
}

static bool llps_software_numa_profile_is_valid(
    const bool software_numa_enabled,
    const uint64_t software_numa_memtotal_kib,
    const uint64_t software_numa_local_distance,
    const uint64_t software_numa_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (!software_numa_enabled) {
        return true;
    }

    return (software_numa_memtotal_kib != 0u) &&
           (software_numa_memtotal_kib <=
            LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB_MAX) &&
           ((software_numa_local_distance == 0u) ==
            (software_numa_remote_distance == 0u)) &&
           (software_numa_local_distance <=
            LLPS_SOFTWARE_NUMA_DISTANCE_MAX) &&
           (software_numa_remote_distance <=
            LLPS_SOFTWARE_NUMA_DISTANCE_MAX) &&
           ((software_numa_local_distance == 0u) ||
            (software_numa_remote_distance >
             software_numa_local_distance)) &&
           llps_domain_ids_are_distinct(physical_memory_domain_ids);
}

static uint32_t llps_software_evidence_required_coverage(
    const bool software_ecc_enabled,
    const bool software_numa_enabled) {
    uint32_t coverage = LLPS_SOFTWARE_EVIDENCE_SELF_TEST_REQUIRED_COVERAGE;

    if (software_ecc_enabled) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP |
                    LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING |
                    LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING;
    }
    if (software_numa_enabled) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY |
                    LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING;
    }

    return coverage;
}

static uint32_t llps_software_dimm_value(const uint32_t dimm_index) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    crc = llps_crc32_update_u64(crc, LLPS_SOFTWARE_DIMM_TEST_VALUE);
    crc = llps_crc32_update_u32(crc, dimm_index);
    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}

static bool llps_software_dimm_vote_and_repair(
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT]) {
    uint32_t valid_count = 0u;
    uint32_t majority_index = UINT32_MAX;

    if (banks == NULL) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (llps_software_dimm_bank_is_valid(&banks[i], i)) {
            ++valid_count;
        }
    }

    if (valid_count < 2u) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        uint32_t matches = 0u;

        if (!llps_software_dimm_bank_is_valid(&banks[i], i)) {
            continue;
        }

        for (uint32_t j = 0u; j < LLPS_SESSION_TMR_BANK_COUNT; ++j) {
            if (llps_software_dimm_bank_is_valid(&banks[j], j) &&
                llps_software_dimm_bank_payload_equal(&banks[i], &banks[j])) {
                ++matches;
            }
        }

        if (matches >= 2u) {
            majority_index = i;
            break;
        }
    }

    if (majority_index == UINT32_MAX) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        if (!llps_software_dimm_bank_is_valid(&banks[i], i) ||
            !llps_software_dimm_bank_payload_equal(&banks[i],
                                                   &banks[majority_index])) {
            llps_software_dimm_bank_seal(&banks[i],
                                         i,
                                         banks[majority_index].value,
                                         banks[majority_index].generation,
                                         banks[majority_index].scrub_generation);
        }
    }

    return true;
}

static void llps_software_dimm_init_all(
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT]) {
    if (banks == NULL) {
        return;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        llps_software_dimm_bank_seal(&banks[i],
                                     i,
                                     LLPS_SOFTWARE_DIMM_TEST_VALUE,
                                     LLPS_SOFTWARE_DIMM_TEST_GENERATION,
                                     LLPS_SOFTWARE_DIMM_TEST_SCRUB);
    }
}

static bool llps_software_dimm_scrub_rejects_corruption(void) {
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT];

    llps_software_dimm_init_all(banks);
    banks[0].value ^= UINT64_C(1) << 7u;
    if (llps_software_dimm_scrub(banks)) {
        return false;
    }

    llps_software_dimm_init_all(banks);
    banks[1].ecc = (uint8_t)(banks[1].ecc ^ 1u);
    if (llps_software_dimm_scrub(banks)) {
        return false;
    }

    llps_software_dimm_init_all(banks);
    banks[2].crc ^= 1u;
    if (llps_software_dimm_scrub(banks)) {
        return false;
    }

    return true;
}

static bool llps_software_dimm_stale_metadata_fails_closed(void) {
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT];

    llps_software_dimm_init_all(banks);
    llps_software_dimm_bank_seal(&banks[1],
                                 1u,
                                 LLPS_SOFTWARE_DIMM_TEST_VALUE,
                                 LLPS_SOFTWARE_DIMM_TEST_GENERATION + 1u,
                                 LLPS_SOFTWARE_DIMM_TEST_SCRUB);
    llps_software_dimm_bank_seal(&banks[2],
                                 2u,
                                 LLPS_SOFTWARE_DIMM_TEST_VALUE,
                                 LLPS_SOFTWARE_DIMM_TEST_GENERATION,
                                 LLPS_SOFTWARE_DIMM_TEST_SCRUB + 1u);

    return !llps_software_dimm_vote_and_repair(banks);
}

static void llps_software_dimm_init_all_value(
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT],
    const uint64_t value,
    const uint32_t generation,
    const uint32_t scrub_generation) {
    if (banks == NULL) {
        return;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        llps_software_dimm_bank_seal(&banks[i],
                                     i,
                                     value,
                                     generation,
                                     scrub_generation);
    }
}

static bool llps_software_dimm_secded_case_ok(const uint64_t value,
                                              const uint32_t single_bit,
                                              const uint32_t double_bit_a,
                                              const uint32_t double_bit_b) {
    uint64_t single_data = value;
    uint8_t single_ecc = llps_secded_encode_u64(single_data, 64u);
    uint64_t double_data = value;
    uint8_t double_ecc = llps_secded_encode_u64(double_data, 64u);

    single_data ^= UINT64_C(1) << single_bit;
    if ((llps_secded_repair_u64(&single_data, 64u, &single_ecc) !=
         LLPS_SECDED_CORRECTED) ||
        (single_data != value) ||
        !llps_secded_is_valid_u64(single_data, 64u, single_ecc)) {
        return false;
    }

    double_data ^= UINT64_C(1) << double_bit_a;
    double_data ^= UINT64_C(1) << double_bit_b;
    return llps_secded_repair_u64(&double_data, 64u, &double_ecc) ==
           LLPS_SECDED_UNCORRECTABLE;
}

static uint32_t llps_software_dimm_case_fingerprint(
    uint32_t fingerprint,
    const uint32_t dimm,
    const uint64_t value,
    const uint32_t generation,
    const uint32_t scrub_generation,
    const uint32_t corrupt_bank,
    const llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT]) {
    fingerprint = llps_crc32_update_u32(fingerprint, dimm);
    fingerprint = llps_crc32_update_u64(fingerprint, value);
    fingerprint = llps_crc32_update_u32(fingerprint, generation);
    fingerprint = llps_crc32_update_u32(fingerprint, scrub_generation);
    fingerprint = llps_crc32_update_u32(fingerprint, corrupt_bank);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[0].crc);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[1].crc);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[2].crc);
    return fingerprint;
}

static uint32_t llps_software_dimm_runtime_case_fingerprint(
    uint32_t fingerprint,
    const uint32_t dimm,
    const uint64_t value,
    const uint32_t generation,
    const uint32_t scrub_generation,
    const uint32_t corrupt_bank,
    const uint32_t single_bit,
    const uint32_t double_bit_a,
    const uint32_t double_bit_b,
    const llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT]) {
    fingerprint = llps_crc32_update_u32(fingerprint, dimm);
    fingerprint = llps_crc32_update_u64(fingerprint, value);
    fingerprint = llps_crc32_update_u32(fingerprint, generation);
    fingerprint = llps_crc32_update_u32(fingerprint, scrub_generation);
    fingerprint = llps_crc32_update_u32(fingerprint, corrupt_bank);
    fingerprint = llps_crc32_update_u32(fingerprint, single_bit);
    fingerprint = llps_crc32_update_u32(fingerprint, double_bit_a);
    fingerprint = llps_crc32_update_u32(fingerprint, double_bit_b);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[0].crc);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[1].crc);
    fingerprint = llps_crc32_update_u32(fingerprint, banks[2].crc);
    return fingerprint;
}

static bool llps_software_dimm_configured_sweep_case(
    const uint32_t dimm,
    uint32_t * const io_fingerprint) {
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT];
    const uint64_t value =
        LLPS_SOFTWARE_DIMM_TEST_VALUE ^
        ((uint64_t)llps_software_dimm_value(dimm) << 32u) ^
        (uint64_t)llps_software_dimm_value(dimm + 1u);
    const uint32_t generation = LLPS_SOFTWARE_DIMM_TEST_GENERATION + dimm;
    const uint32_t scrub_generation = LLPS_SOFTWARE_DIMM_TEST_SCRUB + dimm;
    const uint32_t single_bit = (dimm % 61u) + 1u;
    const uint32_t double_bit_a = (dimm % 29u) + 1u;
    const uint32_t double_bit_b = double_bit_a + 31u;
    const uint32_t corrupt_bank = dimm % LLPS_SESSION_TMR_BANK_COUNT;

    if ((io_fingerprint == NULL) ||
        !llps_software_dimm_secded_case_ok(value,
                                           single_bit,
                                           double_bit_a,
                                           double_bit_b)) {
        return false;
    }

    llps_software_dimm_init_all_value(banks, value, generation, scrub_generation);
    banks[corrupt_bank].value ^= UINT64_C(1) << single_bit;
    if (!llps_software_dimm_vote_and_repair(banks) ||
        !llps_software_dimm_scrub(banks)) {
        return false;
    }

    *io_fingerprint = llps_software_dimm_case_fingerprint(*io_fingerprint,
                                                          dimm,
                                                          value,
                                                          generation,
                                                          scrub_generation,
                                                          corrupt_bank,
                                                          banks);
    return true;
}

static bool llps_software_dimm_run_configured_sweep(
    const uint32_t dimm_count,
    uint32_t * const out_fingerprint) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if (out_fingerprint == NULL) {
        return false;
    }
    *out_fingerprint = 0u;

    if (!llps_software_ecc_dimm_count_is_valid(dimm_count)) {
        return false;
    }

    for (uint32_t dimm = 0u; dimm < dimm_count; ++dimm) {
        if (!llps_software_dimm_configured_sweep_case(dimm, &fingerprint)) {
            return false;
        }
    }

    *out_fingerprint = llps_nonzero_fingerprint(
        fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    return true;
}

static bool llps_software_dimm_runtime_patrol_case(
    const uint32_t dimm,
    uint32_t * const io_fingerprint) {
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT];
    const uint64_t value =
        LLPS_SOFTWARE_DIMM_TEST_VALUE ^
        ((uint64_t)llps_software_dimm_value(dimm + 17u) << 32u) ^
        (uint64_t)llps_software_dimm_value(dimm + 31u);
    const uint32_t generation =
        LLPS_SOFTWARE_DIMM_TEST_GENERATION + (dimm * 3u);
    const uint32_t scrub_generation =
        LLPS_SOFTWARE_DIMM_TEST_SCRUB + (dimm * 5u);
    const uint32_t corrupt_bank = dimm % LLPS_SESSION_TMR_BANK_COUNT;
    const uint32_t single_bit = dimm % LLPS_SOFTWARE_SECDED_DATA_BITS;
    const uint32_t double_bit_a = dimm % 31u;
    const uint32_t double_bit_b = double_bit_a + 32u;

    if (io_fingerprint == NULL) {
        return false;
    }

    llps_software_dimm_init_all_value(banks, value, generation, scrub_generation);
    banks[corrupt_bank].value ^= UINT64_C(1) << single_bit;
    if (llps_software_dimm_scrub(banks)) {
        return false;
    }
    if (!llps_software_dimm_vote_and_repair(banks) ||
        !llps_software_dimm_scrub(banks) ||
        !llps_software_dimm_secded_case_ok(value,
                                           single_bit,
                                           double_bit_a,
                                           double_bit_b)) {
        return false;
    }

    *io_fingerprint =
        llps_software_dimm_runtime_case_fingerprint(*io_fingerprint,
                                                    dimm,
                                                    value,
                                                    generation,
                                                    scrub_generation,
                                                    corrupt_bank,
                                                    single_bit,
                                                    double_bit_a,
                                                    double_bit_b,
                                                    banks);
    return true;
}

static bool llps_software_dimm_run_runtime_patrol(
    const bool software_ecc_enabled,
    const uint32_t dimm_count,
    uint32_t * const io_fingerprint) {
    const uint32_t patrol_count =
        software_ecc_enabled ? dimm_count : LLPS_SESSION_TMR_BANK_COUNT;
    uint32_t fingerprint = 0u;

    if ((io_fingerprint == NULL) || (patrol_count == 0u)) {
        return false;
    }

    fingerprint = *io_fingerprint;
    for (uint32_t dimm = 0u; dimm < patrol_count; ++dimm) {
        if (!llps_software_dimm_runtime_patrol_case(dimm, &fingerprint)) {
            return false;
        }
    }

    *io_fingerprint = fingerprint;
    return true;
}

static bool llps_software_ecc_topology_controller_crc(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    uint32_t * const io_fingerprint) {
    if (io_fingerprint == NULL) {
        return false;
    }

    for (uint32_t controller = 0u;
         controller < controller_count;
         ++controller) {
        const uint32_t controller_dimm_count =
            (dimm_count / controller_count) +
            ((controller < (dimm_count % controller_count)) ? 1u : 0u);

        if (controller_dimm_count == 0u) {
            return false;
        }

        *io_fingerprint = llps_crc32_update_u32(*io_fingerprint, controller);
        *io_fingerprint = llps_crc32_update_u32(*io_fingerprint,
                                                controller_dimm_count);
        *io_fingerprint = llps_crc32_update_u64(*io_fingerprint, scrub_rate);
    }

    return true;
}

static void llps_software_ecc_topology_dimm_crc(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    uint32_t * const io_fingerprint) {
    if (io_fingerprint == NULL) {
        return;
    }

    for (uint32_t dimm = 0u; dimm < dimm_count; ++dimm) {
        const uint32_t controller = dimm % controller_count;
        const uint32_t slot = dimm / controller_count;
        const uint64_t value =
            LLPS_SOFTWARE_DIMM_TEST_VALUE ^
            ((uint64_t)llps_software_dimm_value(dimm) << 32u) ^
            (uint64_t)llps_software_dimm_value(controller + slot + 1u);
        const uint8_t ecc = llps_secded_encode_u64(value, 64u);

        *io_fingerprint = llps_crc32_update_u32(*io_fingerprint, dimm);
        *io_fingerprint = llps_crc32_update_u32(*io_fingerprint, controller);
        *io_fingerprint = llps_crc32_update_u32(*io_fingerprint, slot);
        *io_fingerprint = llps_crc32_update_u64(*io_fingerprint, value);
        *io_fingerprint = llps_crc32_update_byte(*io_fingerprint, ecc);
    }
}

static bool llps_software_ecc_run_topology_self_test(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    uint32_t * const out_fingerprint) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if (out_fingerprint == NULL) {
        return false;
    }
    *out_fingerprint = 0u;

    if (!llps_software_ecc_controller_count_is_valid(controller_count,
                                                     dimm_count) ||
        !llps_software_ecc_dimm_count_is_valid(dimm_count) ||
        !llps_software_ecc_scrub_rate_is_valid(scrub_rate)) {
        return false;
    }

    fingerprint = llps_crc32_update_u32(
        fingerprint,
        LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    fingerprint = llps_crc32_update_u32(fingerprint, controller_count);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_count);
    fingerprint = llps_crc32_update_u64(fingerprint, scrub_rate);
    fingerprint = llps_crc32_update_u64(
        fingerprint,
        scrub_rate * (uint64_t)controller_count);

    if (!llps_software_ecc_topology_controller_crc(controller_count,
                                                   dimm_count,
                                                   scrub_rate,
                                                   &fingerprint)) {
        return false;
    }
    llps_software_ecc_topology_dimm_crc(controller_count,
                                        dimm_count,
                                        &fingerprint);

    *out_fingerprint = llps_nonzero_fingerprint(
        fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    return true;
}

static bool llps_software_ecc_topology_variant_differs(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint32_t reference_fingerprint) {
    uint32_t fingerprint = 0u;

    return llps_software_ecc_run_topology_self_test(controller_count,
                                                    dimm_count,
                                                    scrub_rate,
                                                    &fingerprint) &&
           (fingerprint != reference_fingerprint);
}

static bool llps_software_ecc_topology_alternate_controller_ok(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint32_t reference_fingerprint) {
    const uint32_t alternate_controller_count =
        (controller_count < dimm_count) ?
        (controller_count + 1u) :
        (controller_count - 1u);

    return (alternate_controller_count != 0u) &&
           llps_software_ecc_topology_variant_differs(
               alternate_controller_count,
               dimm_count,
               scrub_rate,
               reference_fingerprint);
}

static bool llps_software_ecc_topology_invalid_cases_rejected(
    const uint32_t dimm_count,
    const uint64_t scrub_rate) {
    uint32_t fingerprint = 0u;

    if (llps_software_ecc_run_topology_self_test(0u,
                                                 dimm_count,
                                                 scrub_rate,
                                                 &fingerprint)) {
        return false;
    }

    return !llps_software_ecc_run_topology_self_test(dimm_count + 1u,
                                                     dimm_count,
                                                     scrub_rate,
                                                     &fingerprint);
}

static bool llps_software_ecc_topology_binding_self_test(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint32_t reference_fingerprint) {
    const uint32_t alternate_dimm_count =
        (dimm_count < LLPS_SOFTWARE_ECC_DIMM_COUNT_MAX) ?
        (dimm_count + 1u) :
        (dimm_count - 1u);
    const uint64_t alternate_scrub_rate =
        (scrub_rate < LLPS_SOFTWARE_ECC_SCRUB_RATE_MAX) ?
        (scrub_rate + 1u) :
        (scrub_rate - 1u);

    if ((reference_fingerprint == 0u) ||
        (alternate_dimm_count == dimm_count) ||
        (alternate_dimm_count < controller_count) ||
        (alternate_scrub_rate == scrub_rate)) {
        return false;
    }

    if (!llps_software_ecc_topology_variant_differs(controller_count,
                                                    alternate_dimm_count,
                                                    scrub_rate,
                                                    reference_fingerprint)) {
        return false;
    }

    if (!llps_software_ecc_topology_variant_differs(controller_count,
                                                    dimm_count,
                                                    alternate_scrub_rate,
                                                    reference_fingerprint)) {
        return false;
    }

    if (dimm_count > 1u) {
        if (!llps_software_ecc_topology_alternate_controller_ok(
                controller_count,
                dimm_count,
                scrub_rate,
                reference_fingerprint)) {
            return false;
        }
    }

    return llps_software_ecc_topology_invalid_cases_rejected(dimm_count,
                                                             scrub_rate);
}

static bool llps_software_ecc_counter_case(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint64_t controller_corrected_error_count,
    const uint64_t controller_uncorrected_error_count,
    const uint64_t dimm_corrected_error_count,
    const uint64_t dimm_uncorrected_error_count,
    const uint32_t clean_fingerprint,
    uint32_t * const out_fingerprint) {
    llps_edac_observation_t observation;
    bool ecc_present = false;
    bool counters_clean = true;
    uint32_t fingerprint = 0u;

    if (out_fingerprint == NULL) {
        return false;
    }
    *out_fingerprint = 0u;

    llps_edac_synthesize_ecc(controller_count,
                             dimm_count,
                             scrub_rate,
                             controller_corrected_error_count,
                             controller_uncorrected_error_count,
                             dimm_corrected_error_count,
                             dimm_uncorrected_error_count,
                             &ecc_present,
                             &counters_clean,
                             &fingerprint,
                             &observation);

    if (!ecc_present ||
        counters_clean ||
        (fingerprint == 0u) ||
        (fingerprint == clean_fingerprint) ||
        (observation.corrected_error_count !=
         controller_corrected_error_count) ||
        (observation.uncorrected_error_count !=
         controller_uncorrected_error_count) ||
        (observation.dimm_corrected_error_count !=
         dimm_corrected_error_count) ||
        (observation.dimm_uncorrected_error_count !=
         dimm_uncorrected_error_count) ||
        ((llps_edac_observed_flags(ecc_present, counters_clean) &
          LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u)) {
        return false;
    }

    *out_fingerprint = fingerprint;
    return true;
}

static bool llps_software_ecc_clean_observation_ok(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    uint32_t * const out_clean_fingerprint) {
    llps_edac_observation_t clean_observation;
    bool ecc_present = false;
    bool counters_clean = false;

    if (out_clean_fingerprint == NULL) {
        return false;
    }
    *out_clean_fingerprint = 0u;
    llps_edac_synthesize_ecc(controller_count,
                             dimm_count,
                             scrub_rate,
                             0u,
                             0u,
                             0u,
                             0u,
                             &ecc_present,
                             &counters_clean,
                             out_clean_fingerprint,
                             &clean_observation);
    return ecc_present &&
           counters_clean &&
           (*out_clean_fingerprint != 0u) &&
           (clean_observation.controller_count == controller_count) &&
           (clean_observation.dimm_count == dimm_count) &&
           (clean_observation.scrub_rate_sum ==
            (scrub_rate * (uint64_t)controller_count)) &&
           ((llps_edac_observed_flags(ecc_present, counters_clean) &
             LLPS_PLATFORM_EVIDENCE_ECC_CLEAN) != 0u);
}

static bool llps_software_ecc_counter_cases_ok(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint32_t clean_fingerprint,
    uint32_t * const controller_ce_fingerprint,
    uint32_t * const controller_ue_fingerprint,
    uint32_t * const dimm_ce_fingerprint,
    uint32_t * const dimm_ue_fingerprint) {
    return llps_software_ecc_counter_case(controller_count,
                                          dimm_count,
                                          scrub_rate,
                                          UINT64_C(1),
                                          0u,
                                          0u,
                                          0u,
                                          clean_fingerprint,
                                          controller_ce_fingerprint) &&
           llps_software_ecc_counter_case(controller_count,
                                          dimm_count,
                                          scrub_rate,
                                          0u,
                                          UINT64_C(1),
                                          0u,
                                          0u,
                                          clean_fingerprint,
                                          controller_ue_fingerprint) &&
           llps_software_ecc_counter_case(controller_count,
                                          dimm_count,
                                          scrub_rate,
                                          0u,
                                          0u,
                                          UINT64_C(1),
                                          0u,
                                          clean_fingerprint,
                                          dimm_ce_fingerprint) &&
           llps_software_ecc_counter_case(controller_count,
                                          dimm_count,
                                          scrub_rate,
                                          0u,
                                          0u,
                                          0u,
                                          UINT64_C(1),
                                          clean_fingerprint,
                                          dimm_ue_fingerprint);
}

static bool llps_software_ecc_invalid_counter_rejected(
    const uint32_t dimm_count,
    const uint64_t scrub_rate) {
    llps_edac_observation_t observation;
    bool ecc_present = false;
    bool counters_clean = false;
    uint32_t invalid_fingerprint = 0u;

    llps_edac_synthesize_ecc(0u,
                             dimm_count,
                             scrub_rate,
                             0u,
                             0u,
                             0u,
                             0u,
                             &ecc_present,
                             &counters_clean,
                             &invalid_fingerprint,
                             &observation);
    return !ecc_present && !counters_clean && (invalid_fingerprint == 0u);
}

static uint32_t llps_software_ecc_counter_binding_fingerprint(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    const uint32_t clean_fingerprint,
    const uint32_t controller_ce_fingerprint,
    const uint32_t controller_ue_fingerprint,
    const uint32_t dimm_ce_fingerprint,
    const uint32_t dimm_ue_fingerprint) {
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    fingerprint = llps_crc32_update_u32(fingerprint, controller_count);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_count);
    fingerprint = llps_crc32_update_u64(fingerprint, scrub_rate);
    fingerprint = llps_crc32_update_u32(fingerprint, clean_fingerprint);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        controller_ce_fingerprint);
    fingerprint = llps_crc32_update_u32(fingerprint,
                                        controller_ue_fingerprint);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_ce_fingerprint);
    fingerprint = llps_crc32_update_u32(fingerprint, dimm_ue_fingerprint);
    return llps_nonzero_fingerprint(fingerprint ^ LLPS_SESSION_CRC_XOROUT);
}

static bool llps_software_ecc_counter_binding_self_test(
    const uint32_t controller_count,
    const uint32_t dimm_count,
    const uint64_t scrub_rate,
    uint32_t * const out_fingerprint) {
    uint32_t clean_fingerprint = 0u;
    uint32_t controller_ce_fingerprint = 0u;
    uint32_t controller_ue_fingerprint = 0u;
    uint32_t dimm_ce_fingerprint = 0u;
    uint32_t dimm_ue_fingerprint = 0u;

    if (out_fingerprint == NULL) {
        return false;
    }
    *out_fingerprint = 0u;

    if (!llps_software_ecc_controller_count_is_valid(controller_count,
                                                     dimm_count) ||
        !llps_software_ecc_dimm_count_is_valid(dimm_count) ||
        !llps_software_ecc_scrub_rate_is_valid(scrub_rate)) {
        return false;
    }

    if (!llps_software_ecc_clean_observation_ok(controller_count,
                                                dimm_count,
                                                scrub_rate,
                                                &clean_fingerprint)) {
        return false;
    }

    if (!llps_software_ecc_counter_cases_ok(controller_count,
                                            dimm_count,
                                            scrub_rate,
                                            clean_fingerprint,
                                            &controller_ce_fingerprint,
                                            &controller_ue_fingerprint,
                                            &dimm_ce_fingerprint,
                                            &dimm_ue_fingerprint)) {
        return false;
    }

    if (!llps_software_ecc_invalid_counter_rejected(dimm_count, scrub_rate)) {
        return false;
    }

    *out_fingerprint =
        llps_software_ecc_counter_binding_fingerprint(
            controller_count,
            dimm_count,
            scrub_rate,
            clean_fingerprint,
            controller_ce_fingerprint,
            controller_ue_fingerprint,
            dimm_ce_fingerprint,
            dimm_ue_fingerprint);
    return true;
}

static void llps_software_secded_flip_codeword_bit(
    uint64_t * const data,
    uint8_t * const ecc,
    const uint32_t bit_index) {
    if ((data == NULL) || (ecc == NULL)) {
        return;
    }

    if (bit_index < LLPS_SOFTWARE_SECDED_DATA_BITS) {
        *data ^= (UINT64_C(1) << bit_index);
    } else {
        const uint32_t ecc_bit =
            bit_index - LLPS_SOFTWARE_SECDED_DATA_BITS;

        if (ecc_bit < LLPS_SOFTWARE_SECDED_ECC_BITS) {
            *ecc = (uint8_t)(*ecc ^ (uint8_t)((uint32_t)1u << ecc_bit));
        }
    }
}

static bool llps_software_secded_single_bit_sweep(
    const uint32_t first_bit,
    const uint32_t end_bit,
    uint32_t * const io_fingerprint) {
    uint32_t fingerprint = 0u;

    if ((io_fingerprint == NULL) ||
        (first_bit >= end_bit) ||
        (end_bit > LLPS_SOFTWARE_SECDED_CODE_BITS)) {
        return false;
    }

    fingerprint = *io_fingerprint;
    for (uint32_t bit = first_bit; bit < end_bit; ++bit) {
        uint64_t data = LLPS_SOFTWARE_DIMM_TEST_VALUE;
        uint8_t ecc = llps_secded_encode_u64(data, 64u);

        llps_software_secded_flip_codeword_bit(&data, &ecc, bit);
        if ((llps_secded_repair_u64(&data, 64u, &ecc) !=
             LLPS_SECDED_CORRECTED) ||
            (data != LLPS_SOFTWARE_DIMM_TEST_VALUE) ||
            !llps_secded_is_valid_u64(data, 64u, ecc)) {
            return false;
        }

        fingerprint = llps_crc32_update_u32(fingerprint, bit);
        fingerprint = llps_crc32_update_u64(fingerprint, data);
        fingerprint = llps_crc32_update_byte(fingerprint, ecc);
    }

    *io_fingerprint = fingerprint;
    return true;
}

static bool llps_software_secded_double_bit_sweep(
    uint32_t * const io_fingerprint) {
    uint32_t fingerprint = 0u;

    if (io_fingerprint == NULL) {
        return false;
    }

    fingerprint = *io_fingerprint;
    for (uint32_t first = 0u;
         first < LLPS_SOFTWARE_SECDED_CODE_BITS;
         ++first) {
        for (uint32_t second = first + 1u;
             second < LLPS_SOFTWARE_SECDED_CODE_BITS;
             ++second) {
            uint64_t data = LLPS_SOFTWARE_DIMM_TEST_VALUE;
            uint8_t ecc = llps_secded_encode_u64(data, 64u);

            llps_software_secded_flip_codeword_bit(&data, &ecc, first);
            llps_software_secded_flip_codeword_bit(&data, &ecc, second);
            if (llps_secded_repair_u64(&data, 64u, &ecc) !=
                LLPS_SECDED_UNCORRECTABLE) {
                return false;
            }

            fingerprint = llps_crc32_update_u32(fingerprint, first);
            fingerprint = llps_crc32_update_u32(fingerprint, second);
            fingerprint = llps_crc32_update_u64(fingerprint, data);
            fingerprint = llps_crc32_update_byte(fingerprint, ecc);
        }
    }

    *io_fingerprint = fingerprint;
    return true;
}

static uint32_t llps_software_secded_run_exhaustive_self_test(
    uint32_t * const out_fingerprint) {
    uint32_t coverage = 0u;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if (out_fingerprint != NULL) {
        *out_fingerprint = 0u;
    }

    if (llps_software_secded_single_bit_sweep(
            0u,
            LLPS_SOFTWARE_SECDED_DATA_BITS,
            &fingerprint)) {
        coverage |=
            LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DATA_BIT_SWEEP;
    }

    if (llps_software_secded_single_bit_sweep(
            LLPS_SOFTWARE_SECDED_DATA_BITS,
            LLPS_SOFTWARE_SECDED_CODE_BITS,
            &fingerprint)) {
        coverage |=
            LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_ECC_BIT_SWEEP;
    }

    if (llps_software_secded_double_bit_sweep(&fingerprint)) {
        coverage |=
            LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_BIT_SWEEP;
    }

    fingerprint = llps_crc32_update_u32(fingerprint, coverage);
    if (out_fingerprint != NULL) {
        *out_fingerprint = llps_nonzero_fingerprint(
            fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    }

    return coverage;
}

static bool llps_software_numa_run_topology_self_test(
    const uint64_t software_numa_memtotal_kib,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_fingerprint) {
    const uint64_t local_distance =
        (configured_local_distance != 0u) ?
        configured_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t remote_distance =
        (configured_remote_distance != 0u) ?
        configured_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    uint32_t fingerprint = LLPS_SESSION_CRC_INIT;

    if (out_fingerprint == NULL) {
        return false;
    }
    *out_fingerprint = 0u;

    if (!llps_software_numa_profile_is_valid(true,
                                             software_numa_memtotal_kib,
                                             configured_local_distance,
                                             configured_remote_distance,
                                             physical_memory_domain_ids)) {
        return false;
    }

    fingerprint = llps_crc32_update_u64(fingerprint,
                                        software_numa_memtotal_kib);
    fingerprint = llps_crc32_update_u64(fingerprint, local_distance);
    fingerprint = llps_crc32_update_u64(fingerprint, remote_distance);
    for (uint32_t row = 0u; row < LLPS_SESSION_TMR_BANK_COUNT; ++row) {
        fingerprint = llps_crc32_update_u32(fingerprint,
                                            physical_memory_domain_ids[row]);
        for (uint32_t column = 0u;
             column < LLPS_SESSION_TMR_BANK_COUNT;
             ++column) {
            fingerprint = llps_crc32_update_u64(
                fingerprint,
                (row == column) ? local_distance : remote_distance);
        }
    }

    *out_fingerprint = llps_nonzero_fingerprint(
        fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    return true;
}

static bool llps_software_numa_variant_differs(
    const uint64_t software_numa_memtotal_kib,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t reference_fingerprint) {
    uint32_t fingerprint = 0u;

    return llps_software_numa_run_topology_self_test(
               software_numa_memtotal_kib,
               configured_local_distance,
               configured_remote_distance,
               physical_memory_domain_ids,
               &fingerprint) &&
           (fingerprint != reference_fingerprint);
}

static void llps_software_numa_prepare_alternate_domains(
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t alternate_domains[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t alias_domains[LLPS_SESSION_TMR_BANK_COUNT]) {
    if ((physical_memory_domain_ids == NULL) ||
        (alternate_domains == NULL) ||
        (alias_domains == NULL)) {
        return;
    }

    for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
        alternate_domains[i] = physical_memory_domain_ids[i];
        alias_domains[i] = physical_memory_domain_ids[i];
    }
    alternate_domains[0] = physical_memory_domain_ids[1];
    alternate_domains[1] = physical_memory_domain_ids[0];
    alias_domains[2] = alias_domains[1];
}

static bool llps_software_numa_invalid_cases_rejected(
    const uint64_t software_numa_memtotal_kib,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t alias_domains[LLPS_SESSION_TMR_BANK_COUNT]) {
    uint32_t fingerprint = 0u;

    if (llps_software_numa_run_topology_self_test(
            0u,
            configured_local_distance,
            configured_remote_distance,
            physical_memory_domain_ids,
            &fingerprint)) {
        return false;
    }

    return !llps_software_numa_run_topology_self_test(
        software_numa_memtotal_kib,
        configured_local_distance,
        configured_remote_distance,
        alias_domains,
        &fingerprint);
}

typedef struct {
    uint64_t alternate_memtotal;
    uint64_t alternate_local_distance;
    uint64_t alternate_remote_distance;
} llps_software_numa_binding_variants_t;

static bool llps_software_numa_binding_variants_init(
    const uint64_t software_numa_memtotal_kib,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    llps_software_numa_binding_variants_t * const out_variants) {
    const uint64_t local_distance =
        (configured_local_distance != 0u) ?
        configured_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t remote_distance =
        (configured_remote_distance != 0u) ?
        configured_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    const uint64_t alternate_remote_distance =
        (remote_distance < LLPS_SOFTWARE_NUMA_DISTANCE_MAX) ?
        (remote_distance + 1u) :
        remote_distance;

    if (out_variants == NULL) {
        return false;
    }

    out_variants->alternate_memtotal =
        (software_numa_memtotal_kib > 1u) ?
        (software_numa_memtotal_kib - 1u) :
        (software_numa_memtotal_kib + 1u);
    out_variants->alternate_remote_distance = alternate_remote_distance;
    out_variants->alternate_local_distance =
        (alternate_remote_distance != remote_distance) ?
        local_distance :
        (local_distance - 1u);
    return (out_variants->alternate_memtotal != software_numa_memtotal_kib) &&
           (out_variants->alternate_local_distance <
            out_variants->alternate_remote_distance);
}

static bool llps_software_numa_profile_binding_self_test(
    const uint64_t software_numa_memtotal_kib,
    const uint64_t configured_local_distance,
    const uint64_t configured_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const uint32_t reference_fingerprint) {
    llps_software_numa_binding_variants_t variants;
    uint32_t alternate_domains[LLPS_SESSION_TMR_BANK_COUNT];
    uint32_t alias_domains[LLPS_SESSION_TMR_BANK_COUNT];

    if ((physical_memory_domain_ids == NULL) ||
        (reference_fingerprint == 0u) ||
        !llps_software_numa_binding_variants_init(
            software_numa_memtotal_kib,
            configured_local_distance,
            configured_remote_distance,
            &variants)) {
        return false;
    }

    llps_software_numa_prepare_alternate_domains(physical_memory_domain_ids,
                                                 alternate_domains,
                                                 alias_domains);

    if (!llps_software_numa_variant_differs(variants.alternate_memtotal,
                                            configured_local_distance,
                                            configured_remote_distance,
                                            physical_memory_domain_ids,
                                            reference_fingerprint)) {
        return false;
    }

    if (!llps_software_numa_variant_differs(software_numa_memtotal_kib,
                                            variants.alternate_local_distance,
                                            variants.alternate_remote_distance,
                                            physical_memory_domain_ids,
                                            reference_fingerprint)) {
        return false;
    }

    if (!llps_software_numa_variant_differs(software_numa_memtotal_kib,
                                            configured_local_distance,
                                            configured_remote_distance,
                                            alternate_domains,
                                            reference_fingerprint)) {
        return false;
    }

    return llps_software_numa_invalid_cases_rejected(
        software_numa_memtotal_kib,
        configured_local_distance,
        configured_remote_distance,
        physical_memory_domain_ids,
        alias_domains);
}

static uint32_t llps_software_evidence_fingerprint(
    const uint32_t mode,
    const bool software_ecc_enabled,
    const uint32_t software_ecc_controller_count,
    const uint32_t software_ecc_dimm_count,
    const uint64_t software_ecc_scrub_rate,
    const bool software_numa_enabled,
    const uint64_t software_numa_memtotal_kib,
    const uint64_t software_numa_local_distance,
    const uint64_t software_numa_remote_distance,
    const uint32_t software_fault_injection_mode,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    const llps_software_evidence_observation_t * const observation,
    const uint32_t self_test_fingerprint) {
    const uint64_t effective_local_distance =
        (software_numa_local_distance != 0u) ?
        software_numa_local_distance :
        LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE_DEFAULT;
    const uint64_t effective_remote_distance =
        (software_numa_remote_distance != 0u) ?
        software_numa_remote_distance :
        LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE_DEFAULT;
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if (observation == NULL) {
        return 0u;
    }

    crc = llps_crc32_update_u32(crc, mode);
    crc = llps_crc32_update_u32(crc, observation->schema_version);
    crc = llps_crc32_update_u32(crc, software_ecc_enabled ? 1u : 0u);
    crc = llps_crc32_update_u32(crc, software_ecc_controller_count);
    crc = llps_crc32_update_u32(crc, software_ecc_dimm_count);
    crc = llps_crc32_update_u64(crc, software_ecc_scrub_rate);
    crc = llps_crc32_update_u32(crc, software_numa_enabled ? 1u : 0u);
    crc = llps_crc32_update_u64(crc, software_numa_memtotal_kib);
    crc = llps_crc32_update_u64(crc, effective_local_distance);
    crc = llps_crc32_update_u64(crc, effective_remote_distance);
    crc = llps_crc32_update_u32(crc, software_fault_injection_mode);
    if (physical_memory_domain_ids != NULL) {
        for (uint32_t i = 0u; i < LLPS_SESSION_TMR_BANK_COUNT; ++i) {
            crc = llps_crc32_update_u32(crc, physical_memory_domain_ids[i]);
        }
    }
    crc = llps_crc32_update_u32(crc, observation->coverage);
    crc = llps_crc32_update_u32(crc, observation->required_coverage);
    crc = llps_crc32_update_u32(crc, observation->controller_count);
    crc = llps_crc32_update_u32(crc, observation->bank_count);
    crc = llps_crc32_update_u64(crc, observation->scrub_rate);
    crc = llps_crc32_update_u32(crc, observation->generation);
    crc = llps_crc32_update_u32(crc, observation->scrub_generation);
    crc = llps_crc32_update_u32(crc, observation->fault_injection_coverage);
    crc = llps_crc32_update_u32(crc, observation->fault_injection_mode);
    crc = llps_crc32_update_u32(crc, observation->numa_profile_fingerprint);
    crc = llps_crc32_update_u32(crc, self_test_fingerprint);

    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}

static uint32_t llps_software_evidence_run_self_test(
    const bool software_ecc_enabled,
    const uint32_t software_ecc_controller_count,
    const uint32_t software_ecc_dimm_count,
    const uint64_t software_ecc_scrub_rate,
    const bool software_numa_enabled,
    const uint64_t software_numa_memtotal_kib,
    const uint64_t software_numa_local_distance,
    const uint64_t software_numa_remote_distance,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    uint32_t * const out_numa_profile_fingerprint,
    uint32_t * const out_self_test_fingerprint) {
    llps_software_dimm_bank_t banks[LLPS_SESSION_TMR_BANK_COUNT];
    uint64_t single_data = LLPS_SOFTWARE_DIMM_TEST_VALUE;
    uint8_t single_ecc = llps_secded_encode_u64(single_data, 64u);
    uint64_t double_data = LLPS_SOFTWARE_DIMM_TEST_VALUE;
    uint8_t double_ecc = llps_secded_encode_u64(double_data, 64u);
    uint32_t coverage = 0u;
    uint32_t dimm_sweep_fingerprint = 0u;
    uint32_t dimm_topology_fingerprint = 0u;
    uint32_t edac_counter_fingerprint = 0u;
    uint32_t numa_fingerprint = 0u;
    uint32_t secded_sweep_fingerprint = 0u;
    uint32_t self_test_fingerprint = LLPS_SESSION_CRC_INIT;

    if (out_self_test_fingerprint != NULL) {
        *out_self_test_fingerprint = 0u;
    }
    if (out_numa_profile_fingerprint != NULL) {
        *out_numa_profile_fingerprint = 0u;
    }

    single_data ^= UINT64_C(1) << 17u;
    if ((llps_secded_repair_u64(&single_data, 64u, &single_ecc) ==
         LLPS_SECDED_CORRECTED) &&
        (single_data == LLPS_SOFTWARE_DIMM_TEST_VALUE) &&
        llps_secded_is_valid_u64(single_data, 64u, single_ecc)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_SINGLE_REPAIR;
    }

    double_data ^= (UINT64_C(1) << 5u);
    double_data ^= (UINT64_C(1) << 19u);
    if (llps_secded_repair_u64(&double_data, 64u, &double_ecc) ==
        LLPS_SECDED_UNCORRECTABLE) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_SECDED_DOUBLE_FAIL_CLOSED;
    }

    llps_software_dimm_init_all(banks);
    llps_software_dimm_bank_seal(&banks[0],
                                 0u,
                                 LLPS_SOFTWARE_DIMM_TEST_VALUE ^
                                     UINT64_C(0x0101010101010101),
                                 LLPS_SOFTWARE_DIMM_TEST_GENERATION,
                                 LLPS_SOFTWARE_DIMM_TEST_SCRUB);
    if (llps_software_dimm_vote_and_repair(banks) &&
        llps_software_dimm_scrub(banks) &&
        (banks[0].value == LLPS_SOFTWARE_DIMM_TEST_VALUE)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_SINGLE_REPAIR;
    }

    llps_software_dimm_init_all(banks);
    llps_software_dimm_bank_seal(&banks[0],
                                 0u,
                                 LLPS_SOFTWARE_DIMM_TEST_VALUE ^
                                     UINT64_C(0x1111000000000000),
                                 LLPS_SOFTWARE_DIMM_TEST_GENERATION,
                                 LLPS_SOFTWARE_DIMM_TEST_SCRUB);
    llps_software_dimm_bank_seal(&banks[1],
                                 1u,
                                 LLPS_SOFTWARE_DIMM_TEST_VALUE ^
                                     UINT64_C(0x2222000000000000),
                                 LLPS_SOFTWARE_DIMM_TEST_GENERATION,
                                 LLPS_SOFTWARE_DIMM_TEST_SCRUB);
    if (!llps_software_dimm_vote_and_repair(banks)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TMR_DUAL_FAIL_CLOSED;
    }

    llps_software_dimm_init_all(banks);
    if (llps_software_dimm_scrub(banks)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB;
    }
    if (llps_software_dimm_scrub_rejects_corruption()) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_SCRUB_CORRUPTION;
    }
    if (llps_software_dimm_stale_metadata_fails_closed()) {
        coverage |=
            LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_STALE_METADATA_FAIL_CLOSED;
    }

    coverage |= llps_software_secded_run_exhaustive_self_test(
        &secded_sweep_fingerprint);

    if (software_ecc_enabled &&
        llps_software_ecc_controller_count_is_valid(
            software_ecc_controller_count,
            software_ecc_dimm_count) &&
        llps_software_ecc_scrub_rate_is_valid(software_ecc_scrub_rate) &&
        llps_software_dimm_run_configured_sweep(software_ecc_dimm_count,
                                                &dimm_sweep_fingerprint)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_COUNT_SWEEP;
        if (llps_software_ecc_run_topology_self_test(
                software_ecc_controller_count,
                software_ecc_dimm_count,
                software_ecc_scrub_rate,
                &dimm_topology_fingerprint) &&
            llps_software_ecc_topology_binding_self_test(
                software_ecc_controller_count,
                software_ecc_dimm_count,
                software_ecc_scrub_rate,
                dimm_topology_fingerprint)) {
            coverage |=
                LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_TOPOLOGY_BINDING;
        }
        if (llps_software_ecc_counter_binding_self_test(
                software_ecc_controller_count,
                software_ecc_dimm_count,
                software_ecc_scrub_rate,
                &edac_counter_fingerprint)) {
            coverage |=
                LLPS_SOFTWARE_EVIDENCE_SELF_TEST_ECC_COUNTER_BINDING;
        }
    }

    if (software_numa_enabled &&
        llps_software_numa_run_topology_self_test(
            software_numa_memtotal_kib,
            software_numa_local_distance,
            software_numa_remote_distance,
            physical_memory_domain_ids,
            &numa_fingerprint)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_TOPOLOGY;
        if (out_numa_profile_fingerprint != NULL) {
            *out_numa_profile_fingerprint = numa_fingerprint;
        }
        if (llps_software_numa_profile_binding_self_test(
                software_numa_memtotal_kib,
                software_numa_local_distance,
                software_numa_remote_distance,
                physical_memory_domain_ids,
                numa_fingerprint)) {
            coverage |=
                LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING;
        }
    }

    if (llps_software_dimm_run_runtime_patrol(software_ecc_enabled,
                                              software_ecc_dimm_count,
                                              &dimm_sweep_fingerprint)) {
        coverage |= LLPS_SOFTWARE_EVIDENCE_SELF_TEST_DIMM_RUNTIME_PATROL;
    }

    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint,
                              LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint, coverage);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint,
                              software_ecc_controller_count);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint, dimm_sweep_fingerprint);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint,
                              dimm_topology_fingerprint);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint,
                              edac_counter_fingerprint);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint, numa_fingerprint);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint,
                              (out_numa_profile_fingerprint != NULL) ?
                              *out_numa_profile_fingerprint :
                              0u);
    self_test_fingerprint =
        llps_crc32_update_u32(self_test_fingerprint, secded_sweep_fingerprint);
    if (out_self_test_fingerprint != NULL) {
        *out_self_test_fingerprint = llps_nonzero_fingerprint(
            self_test_fingerprint ^ LLPS_SESSION_CRC_XOROUT);
    }

    return coverage;
}

void llps_software_evidence_observe(
    const uint32_t mode,
    const bool software_ecc_enabled,
    const uint32_t software_ecc_controller_count,
    const uint32_t software_ecc_dimm_count,
    const uint64_t software_ecc_scrub_rate,
    const bool software_numa_enabled,
    const uint64_t software_numa_memtotal_kib,
    const uint64_t software_numa_local_distance,
    const uint64_t software_numa_remote_distance,
    const uint32_t software_fault_injection_mode,
    const uint32_t physical_memory_domain_ids[LLPS_SESSION_TMR_BANK_COUNT],
    llps_software_evidence_observation_t * const out_observation) {
    const bool required =
        llps_platform_evidence_mode_uses_software(mode) &&
        (software_ecc_enabled || software_numa_enabled);
    const bool inputs_valid =
        (!software_ecc_enabled ||
         (llps_software_ecc_dimm_count_is_valid(software_ecc_dimm_count) &&
          llps_software_ecc_controller_count_is_valid(
              software_ecc_controller_count,
              software_ecc_dimm_count) &&
          llps_software_ecc_scrub_rate_is_valid(software_ecc_scrub_rate))) &&
        llps_software_fault_injection_mode_is_valid(
            software_fault_injection_mode) &&
        llps_software_numa_profile_is_valid(software_numa_enabled,
                                            software_numa_memtotal_kib,
                                            software_numa_local_distance,
                                            software_numa_remote_distance,
                                            physical_memory_domain_ids);
    uint32_t self_test_fingerprint = 0u;
    uint32_t numa_profile_fingerprint = 0u;

    if (out_observation == NULL) {
        return;
    }

    out_observation->required = required;
    out_observation->passed = false;
    out_observation->schema_version = required ?
        LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION :
        0u;
    out_observation->coverage = 0u;
    out_observation->required_coverage = required ?
        llps_software_evidence_required_coverage(software_ecc_enabled,
                                                 software_numa_enabled) :
        0u;
    out_observation->controller_count =
        (required && software_ecc_enabled) ? software_ecc_controller_count : 0u;
    out_observation->bank_count =
        (required && software_ecc_enabled) ? software_ecc_dimm_count : 0u;
    out_observation->scrub_rate =
        (required && software_ecc_enabled) ? software_ecc_scrub_rate : 0u;
    out_observation->generation = required ?
        LLPS_SOFTWARE_DIMM_TEST_GENERATION :
        0u;
    out_observation->scrub_generation = required ?
        LLPS_SOFTWARE_DIMM_TEST_SCRUB :
        0u;
    out_observation->fault_injection_coverage = 0u;
    out_observation->fault_injection_mode = required ?
        software_fault_injection_mode :
        LLPS_SOFTWARE_FAULT_INJECTION_OFF;
    out_observation->fingerprint = 0u;
    out_observation->numa_profile_fingerprint = 0u;

    if (!required || !inputs_valid) {
        return;
    }

    out_observation->coverage = llps_software_evidence_run_self_test(
        software_ecc_enabled,
        software_ecc_controller_count,
        software_ecc_dimm_count,
        software_ecc_scrub_rate,
        software_numa_enabled,
        software_numa_memtotal_kib,
        software_numa_local_distance,
        software_numa_remote_distance,
        physical_memory_domain_ids,
        &numa_profile_fingerprint,
        &self_test_fingerprint);
    out_observation->numa_profile_fingerprint = numa_profile_fingerprint;
    out_observation->fault_injection_coverage =
        out_observation->coverage &
        llps_software_fault_injection_mask_for_mode(
            software_fault_injection_mode,
            out_observation->coverage);
    out_observation->passed =
        (out_observation->coverage &
         out_observation->required_coverage) ==
        out_observation->required_coverage;
    out_observation->fingerprint =
        llps_software_evidence_fingerprint(mode,
                                           software_ecc_enabled,
                                           software_ecc_controller_count,
                                           software_ecc_dimm_count,
                                           software_ecc_scrub_rate,
                                           software_numa_enabled,
                                           software_numa_memtotal_kib,
                                           software_numa_local_distance,
                                           software_numa_remote_distance,
                                           software_fault_injection_mode,
                                           physical_memory_domain_ids,
                                           out_observation,
                                           self_test_fingerprint);
}

bool llps_software_evidence_observation_is_ready(
    const llps_software_evidence_observation_t * const observation) {
    if (observation == NULL) {
        return false;
    }

    if (!observation->required) {
        return true;
    }

    return observation->passed &&
           (observation->schema_version ==
            LLPS_SOFTWARE_EVIDENCE_SCHEMA_VERSION) &&
           llps_software_fault_injection_mode_is_valid(
               observation->fault_injection_mode) &&
           (observation->fingerprint != 0u) &&
           ((observation->coverage & observation->required_coverage) ==
            observation->required_coverage) &&
           (((observation->required_coverage &
              LLPS_SOFTWARE_EVIDENCE_SELF_TEST_NUMA_PROFILE_BINDING) == 0u) ||
            (observation->numa_profile_fingerprint != 0u));
}
