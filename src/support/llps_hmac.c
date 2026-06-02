/**
 * @file src/support/llps_hmac.c
 * @brief Bounded HMAC-SHA-256 helpers for evidence authentication.
 */

#define _POSIX_C_SOURCE 200809L

#include "llps_hmac.h"

#include "llps_crc.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define LLPS_SHA256_BLOCK_BYTES (64u)
#define LLPS_SHA256_DIGEST_BYTES LLPS_PLATFORM_EVIDENCE_MAC_BYTES
#define LLPS_EVIDENCE_MAC_MESSAGE_BYTES (188u)

typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buffer[LLPS_SHA256_BLOCK_BYTES];
    uint32_t buffer_len;
} llps_sha256_ctx_t;

static const uint32_t llps_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t llps_sha256_rotr(const uint32_t value,
                                 const uint32_t bits) {
    return (value >> bits) | (value << (32u - bits));
}

static uint32_t llps_sha256_ch(const uint32_t x,
                               const uint32_t y,
                               const uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

static uint32_t llps_sha256_maj(const uint32_t x,
                                const uint32_t y,
                                const uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t llps_sha256_big_sigma0(const uint32_t x) {
    return llps_sha256_rotr(x, 2u) ^
           llps_sha256_rotr(x, 13u) ^
           llps_sha256_rotr(x, 22u);
}

static uint32_t llps_sha256_big_sigma1(const uint32_t x) {
    return llps_sha256_rotr(x, 6u) ^
           llps_sha256_rotr(x, 11u) ^
           llps_sha256_rotr(x, 25u);
}

static uint32_t llps_sha256_small_sigma0(const uint32_t x) {
    return llps_sha256_rotr(x, 7u) ^
           llps_sha256_rotr(x, 18u) ^
           (x >> 3u);
}

static uint32_t llps_sha256_small_sigma1(const uint32_t x) {
    return llps_sha256_rotr(x, 17u) ^
           llps_sha256_rotr(x, 19u) ^
           (x >> 10u);
}

static void llps_sha256_init(llps_sha256_ctx_t * const ctx) {
    if (ctx == NULL) {
        return;
    }

    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_len = 0u;
    ctx->buffer_len = 0u;
    for (uint32_t i = 0u; i < LLPS_SHA256_BLOCK_BYTES; ++i) {
        ctx->buffer[i] = 0u;
    }
}

static uint32_t llps_sha256_load_be32(const uint8_t data[4]) {
    return (((uint32_t)data[0]) << 24u) |
           (((uint32_t)data[1]) << 16u) |
           (((uint32_t)data[2]) << 8u) |
           ((uint32_t)data[3]);
}

static void llps_sha256_transform(llps_sha256_ctx_t * const ctx,
                                  const uint8_t block[LLPS_SHA256_BLOCK_BYTES]) {
    uint32_t w[64];
    uint32_t work[8];

    if ((ctx == NULL) || (block == NULL)) {
        return;
    }

    for (uint32_t i = 0u; i < 16u; ++i) {
        w[i] = llps_sha256_load_be32(&block[i * 4u]);
    }
    for (uint32_t i = 16u; i < 64u; ++i) {
        w[i] = llps_sha256_small_sigma1(w[i - 2u]) + w[i - 7u] +
               llps_sha256_small_sigma0(w[i - 15u]) + w[i - 16u];
    }
    for (uint32_t i = 0u; i < 8u; ++i) {
        work[i] = ctx->state[i];
    }

    for (uint32_t i = 0u; i < 64u; ++i) {
        const uint32_t t1 =
            work[7] + llps_sha256_big_sigma1(work[4]) +
            llps_sha256_ch(work[4], work[5], work[6]) +
            llps_sha256_k[i] + w[i];
        const uint32_t t2 =
            llps_sha256_big_sigma0(work[0]) +
            llps_sha256_maj(work[0], work[1], work[2]);

        work[7] = work[6];
        work[6] = work[5];
        work[5] = work[4];
        work[4] = work[3] + t1;
        work[3] = work[2];
        work[2] = work[1];
        work[1] = work[0];
        work[0] = t1 + t2;
    }

    for (uint32_t i = 0u; i < 8u; ++i) {
        ctx->state[i] += work[i];
    }
}

static void llps_sha256_update(llps_sha256_ctx_t * const ctx,
                               const uint8_t * const data,
                               const size_t len) {
    if ((ctx == NULL) || ((data == NULL) && (len != 0u))) {
        return;
    }

    for (size_t i = 0u; i < len; ++i) {
        ctx->buffer[ctx->buffer_len] = data[i];
        ++ctx->buffer_len;
        if (ctx->buffer_len == LLPS_SHA256_BLOCK_BYTES) {
            llps_sha256_transform(ctx, ctx->buffer);
            ctx->bit_len += (uint64_t)LLPS_SHA256_BLOCK_BYTES * 8u;
            ctx->buffer_len = 0u;
        }
    }
}

static void llps_sha256_final(llps_sha256_ctx_t * const ctx,
                              uint8_t digest[LLPS_SHA256_DIGEST_BYTES]) {
    uint32_t i = 0u;

    if ((ctx == NULL) || (digest == NULL)) {
        return;
    }

    i = ctx->buffer_len;
    ctx->buffer[i] = 0x80u;
    ++i;

    if (i > 56u) {
        for (; i < LLPS_SHA256_BLOCK_BYTES; ++i) {
            ctx->buffer[i] = 0u;
        }
        llps_sha256_transform(ctx, ctx->buffer);
        i = 0u;
    }

    for (; i < 56u; ++i) {
        ctx->buffer[i] = 0u;
    }

    ctx->bit_len += (uint64_t)ctx->buffer_len * 8u;
    for (i = 0u; i < 8u; ++i) {
        ctx->buffer[63u - i] =
            (uint8_t)((ctx->bit_len >> (8u * i)) & UINT64_C(0xff));
    }
    llps_sha256_transform(ctx, ctx->buffer);

    for (i = 0u; i < 8u; ++i) {
        digest[(i * 4u)] = (uint8_t)((ctx->state[i] >> 24u) & 0xffu);
        digest[(i * 4u) + 1u] =
            (uint8_t)((ctx->state[i] >> 16u) & 0xffu);
        digest[(i * 4u) + 2u] =
            (uint8_t)((ctx->state[i] >> 8u) & 0xffu);
        digest[(i * 4u) + 3u] = (uint8_t)(ctx->state[i] & 0xffu);
    }
}

static void llps_sha256_hash(const uint8_t * const data,
                             const size_t len,
                             uint8_t digest[LLPS_SHA256_DIGEST_BYTES]) {
    llps_sha256_ctx_t ctx;

    llps_sha256_init(&ctx);
    llps_sha256_update(&ctx, data, len);
    llps_sha256_final(&ctx, digest);
}

bool llps_hmac_sha256(
    const uint8_t * const key,
    const size_t key_len,
    const uint8_t * const message,
    const size_t message_len,
    uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES]) {
    uint8_t key_block[LLPS_SHA256_BLOCK_BYTES];
    uint8_t inner_digest[LLPS_SHA256_DIGEST_BYTES];
    uint8_t ipad[LLPS_SHA256_BLOCK_BYTES];
    uint8_t opad[LLPS_SHA256_BLOCK_BYTES];
    llps_sha256_ctx_t ctx;

    if ((key == NULL) || (key_len == 0u) ||
        ((message == NULL) && (message_len != 0u)) ||
        (out_mac == NULL)) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_SHA256_BLOCK_BYTES; ++i) {
        key_block[i] = 0u;
    }

    if (key_len > LLPS_SHA256_BLOCK_BYTES) {
        llps_sha256_hash(key, key_len, key_block);
    } else {
        for (size_t i = 0u; i < key_len; ++i) {
            key_block[i] = key[i];
        }
    }

    for (uint32_t i = 0u; i < LLPS_SHA256_BLOCK_BYTES; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5cu);
    }

    llps_sha256_init(&ctx);
    llps_sha256_update(&ctx, ipad, sizeof(ipad));
    llps_sha256_update(&ctx, message, message_len);
    llps_sha256_final(&ctx, inner_digest);

    llps_sha256_init(&ctx);
    llps_sha256_update(&ctx, opad, sizeof(opad));
    llps_sha256_update(&ctx, inner_digest, sizeof(inner_digest));
    llps_sha256_final(&ctx, out_mac);

    return true;
}

uint32_t llps_hmac_key_fingerprint(const uint8_t * const key,
                                   const size_t key_len) {
    uint32_t crc = LLPS_SESSION_CRC_INIT;

    if ((key == NULL) || (key_len == 0u)) {
        return 0u;
    }

    for (size_t i = 0u; i < key_len; ++i) {
        crc = llps_crc32_update_byte(crc, key[i]);
    }

    return llps_nonzero_fingerprint(crc ^ LLPS_SESSION_CRC_XOROUT);
}

static bool llps_hmac_read_key_file(
    const char * const path,
    uint8_t key[LLPS_EVIDENCE_MAC_KEY_BYTES_MAX],
    size_t * const out_key_len) {
    uint8_t read_buffer[LLPS_EVIDENCE_MAC_KEY_BYTES_MAX + 1u];
    size_t total = 0u;
    int flags = O_RDONLY;
    int fd = -1;

    if ((path == NULL) || (path[0] == '\0') ||
        (key == NULL) || (out_key_len == NULL)) {
        return false;
    }

#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(path, flags);
    if (fd < 0) {
        return false;
    }

    for (uint64_t read_cycle = 0u; read_cycle < UINT64_MAX; ++read_cycle) {
        const ssize_t n = read(fd,
                               &read_buffer[total],
                               sizeof(read_buffer) - total);
        if (n < 0) {
            (void)close(fd);
            return false;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
        if (total >= sizeof(read_buffer)) {
            (void)close(fd);
            return false;
        }
    }

    if ((close(fd) != 0) ||
        (total == 0u) ||
        (total > LLPS_EVIDENCE_MAC_KEY_BYTES_MAX)) {
        return false;
    }

    for (size_t i = 0u; i < total; ++i) {
        key[i] = read_buffer[i];
    }
    *out_key_len = total;
    return true;
}

bool llps_hmac_key_fingerprint_file(const char * const path,
                                    uint32_t * const out_fingerprint) {
    uint8_t key[LLPS_EVIDENCE_MAC_KEY_BYTES_MAX];
    size_t key_len = 0u;

    if (out_fingerprint == NULL) {
        return false;
    }

    *out_fingerprint = 0u;
    if (!llps_hmac_read_key_file(path, key, &key_len)) {
        return false;
    }

    *out_fingerprint = llps_hmac_key_fingerprint(key, key_len);
    return *out_fingerprint != 0u;
}

bool llps_hmac_sha256_file_message(
    const char * const path,
    const uint8_t * const message,
    const size_t message_len,
    uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    uint32_t * const out_key_fingerprint) {
    uint8_t key[LLPS_EVIDENCE_MAC_KEY_BYTES_MAX];
    size_t key_len = 0u;
    uint32_t fingerprint = 0u;

    if (((message == NULL) && (message_len != 0u)) ||
        (out_mac == NULL) ||
        (out_key_fingerprint == NULL)) {
        return false;
    }

    *out_key_fingerprint = 0u;
    for (uint32_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        out_mac[i] = 0u;
    }

    if (!llps_hmac_read_key_file(path, key, &key_len)) {
        return false;
    }

    fingerprint = llps_hmac_key_fingerprint(key, key_len);
    if (fingerprint == 0u) {
        return false;
    }

    if (!llps_hmac_sha256(key, key_len, message, message_len, out_mac)) {
        return false;
    }

    *out_key_fingerprint = fingerprint;
    return true;
}

static bool llps_hmac_put_u32(uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES],
                              size_t * const offset,
                              const uint32_t value) {
    if ((message == NULL) ||
        (offset == NULL) ||
        ((*offset + 4u) > LLPS_EVIDENCE_MAC_MESSAGE_BYTES)) {
        return false;
    }

    message[*offset] = (uint8_t)(value & 0xffu);
    message[*offset + 1u] = (uint8_t)((value >> 8u) & 0xffu);
    message[*offset + 2u] = (uint8_t)((value >> 16u) & 0xffu);
    message[*offset + 3u] = (uint8_t)((value >> 24u) & 0xffu);
    *offset += 4u;
    return true;
}

static bool llps_hmac_put_u64(uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES],
                              size_t * const offset,
                              const uint64_t value) {
    if ((message == NULL) ||
        (offset == NULL) ||
        ((*offset + 8u) > LLPS_EVIDENCE_MAC_MESSAGE_BYTES)) {
        return false;
    }

    for (uint32_t i = 0u; i < 8u; ++i) {
        message[*offset + i] =
            (uint8_t)((value >> (8u * i)) & UINT64_C(0xff));
    }
    *offset += 8u;
    return true;
}

static bool llps_hmac_put_evidence_message_software(
    const llps_platform_safety_evidence_t * const evidence,
    uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES],
    size_t * const offset) {
    return llps_hmac_put_u32(message, offset, evidence->magic) &&
           llps_hmac_put_u32(message, offset, evidence->version) &&
           llps_hmac_put_u32(message, offset, evidence->flags) &&
           llps_hmac_put_u32(message, offset, evidence->observed_flags) &&
           llps_hmac_put_u32(message, offset, evidence->attested_flags) &&
           llps_hmac_put_u64(message, offset, evidence->evidence_id) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->platform_evidence_mode) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->software_evidence_schema_version) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->software_evidence_self_test_coverage) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->software_evidence_self_test_required_coverage) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->software_ecc_controller_count) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->software_dimm_bank_count) &&
           llps_hmac_put_u64(message,
                             offset,
                             evidence->software_ecc_scrub_rate) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->software_dimm_observation_fingerprint) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->software_numa_profile_fingerprint);
}

static bool llps_hmac_put_evidence_message_fingerprints(
    const llps_platform_safety_evidence_t * const evidence,
    uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES],
    size_t * const offset) {
    return llps_hmac_put_u32(message,
                             offset,
                             evidence->edac_observation_fingerprint) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->physical_domain_observation_fingerprint) &&
           llps_hmac_put_u32(
               message,
               offset,
               evidence->tmr_memory_domain_observation_fingerprint) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->platform_boot_fingerprint) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->platform_identity_fingerprint) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->executable_image_fingerprint) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->tmr_layout_fingerprint) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->attestation_fingerprint) &&
           llps_hmac_put_u32(message, offset, evidence->observation_digest) &&
           llps_hmac_put_u32(message, offset, evidence->crc) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->evidence_mac_enabled) &&
           llps_hmac_put_u32(message,
                             offset,
                             evidence->evidence_mac_key_fingerprint);
}

static bool llps_hmac_build_evidence_message(
    const llps_platform_safety_evidence_t * const evidence,
    uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES],
    size_t * const out_message_len) {
    size_t offset = 0u;

    if ((evidence == NULL) || (message == NULL) ||
        (out_message_len == NULL)) {
        return false;
    }

    for (uint32_t i = 0u; i < LLPS_EVIDENCE_MAC_MESSAGE_BYTES; ++i) {
        message[i] = 0u;
    }

    if (!llps_hmac_put_evidence_message_software(evidence,
                                                 message,
                                                 &offset) ||
        !llps_hmac_put_evidence_message_fingerprints(evidence,
                                                     message,
                                                     &offset)) {
        return false;
    }

    *out_message_len = offset;
    return true;
}

bool llps_evidence_hmac_sha256_file(
    const char * const path,
    const llps_platform_safety_evidence_t * const evidence,
    uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    uint32_t * const out_key_fingerprint) {
    uint8_t key[LLPS_EVIDENCE_MAC_KEY_BYTES_MAX];
    uint8_t message[LLPS_EVIDENCE_MAC_MESSAGE_BYTES];
    size_t key_len = 0u;
    size_t message_len = 0u;
    uint32_t fingerprint = 0u;

    if ((out_mac == NULL) || (out_key_fingerprint == NULL)) {
        return false;
    }

    *out_key_fingerprint = 0u;
    for (uint32_t i = 0u; i < LLPS_PLATFORM_EVIDENCE_MAC_BYTES; ++i) {
        out_mac[i] = 0u;
    }

    if (!llps_hmac_read_key_file(path, key, &key_len)) {
        return false;
    }
    fingerprint = llps_hmac_key_fingerprint(key, key_len);
    if (fingerprint == 0u) {
        return false;
    }
    if (!llps_hmac_build_evidence_message(evidence,
                                          message,
                                          &message_len)) {
        return false;
    }
    if (!llps_hmac_sha256(key, key_len, message, message_len, out_mac)) {
        return false;
    }

    *out_key_fingerprint = fingerprint;
    return true;
}
