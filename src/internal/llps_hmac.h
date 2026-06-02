/**
 * @file src/internal/llps_hmac.h
 * @brief Bounded HMAC-SHA-256 helpers for evidence authentication.
 */

#ifndef LLPS_HMAC_H
#define LLPS_HMAC_H

#include "llps.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool llps_hmac_sha256(const uint8_t *key,
                      size_t key_len,
                      const uint8_t *message,
                      size_t message_len,
                      uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES]);
uint32_t llps_hmac_key_fingerprint(const uint8_t *key, size_t key_len);
bool llps_hmac_key_fingerprint_file(const char *path,
                                    uint32_t *out_fingerprint);
bool llps_hmac_sha256_file_message(
    const char *path,
    const uint8_t *message,
    size_t message_len,
    uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    uint32_t *out_key_fingerprint);
bool llps_evidence_hmac_sha256_file(
    const char *path,
    const llps_platform_safety_evidence_t *evidence,
    uint8_t out_mac[LLPS_PLATFORM_EVIDENCE_MAC_BYTES],
    uint32_t *out_key_fingerprint);

#endif /* LLPS_HMAC_H */
