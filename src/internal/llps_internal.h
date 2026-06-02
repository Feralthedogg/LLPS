/**
 * @file src/internal/llps_internal.h
 * @brief Private LLPS session, pump, and integrity contracts.
 *
 * @details
 * Private contracts live here so public headers expose only stable API
 * surface.
 */

#ifndef LLPS_INTERNAL_H
#define LLPS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "llps_config.h"
#include "llps.h"

/** @brief Magic written into a free session slot. */
#define LLPS_SESSION_MAGIC_FREE            (0xDEADBEEFu)
/** @brief Magic written into an active session slot. */
#define LLPS_SESSION_MAGIC_ACTIVE          (0xC0FFEE00u)
/** @brief Per-bank session record magic base. */
#define LLPS_SESSION_TMR_RECORD_MAGIC      (0x51A7E004u)
/** @brief Separation pad bytes inside each session TMR record. */
#define LLPS_SESSION_TMR_PAD_BYTES         (64u)
/** @brief Start guard magic for each session TMR region. */
#define LLPS_SESSION_TMR_REGION_MAGIC_HEAD (0xA11CECC1u)
/** @brief End guard magic for each session TMR region. */
#define LLPS_SESSION_TMR_REGION_MAGIC_TAIL (0xECC10B5Eu)
/** @brief Guard pad bytes before and after session TMR records. */
#define LLPS_SESSION_TMR_REGION_PAD_BYTES  (16384u)
/** @brief Alignment requested for TMR banks and protected regions. */
#define LLPS_SESSION_TMR_ALIGNMENT_BYTES   (16384u)
/** @brief Minimum desired address spacing between TMR banks. */
#define LLPS_SESSION_TMR_MIN_DISTANCE_BYTES (16384u)
/** @brief Salt for deterministic pre-guard bytes. */
#define LLPS_SESSION_TMR_GUARD_PRE_SALT    (0xA5u)
/** @brief Salt for deterministic post-guard bytes. */
#define LLPS_SESSION_TMR_GUARD_POST_SALT   (0x5Au)
/** @brief Free-list TMR bank magic base. */
#define LLPS_FREE_LIST_BANK_MAGIC          (0xF3EE1157u)
/** @brief Runtime-config TMR bank magic base. */
#define LLPS_RUNTIME_CFG_BANK_MAGIC        (0xC0A7F16Du)
/** @brief Shutdown control flag TMR bank magic base. */
#define LLPS_CONTROL_FLAG_BANK_MAGIC       (0xC071F1A6u)
/** @brief Maximum IPv4 text length including NUL. */
#define LLPS_CLIENT_IP_TEXT_LEN            (16u)

#if defined(__GNUC__) || defined(__clang__)
#define LLPS_UNLIKELY(expr)                __builtin_expect(!!(expr), 0)
#define LLPS_ALIGNED(bytes)                __attribute__((aligned(bytes)))
#define LLPS_SECTION(name)                 __attribute__((section(name)))
#define LLPS_USED                          __attribute__((used))
#else
#define LLPS_UNLIKELY(expr)                (expr)
#define LLPS_ALIGNED(bytes)
#define LLPS_SECTION(name)
#define LLPS_USED
#endif

#if defined(__APPLE__) && (defined(__GNUC__) || defined(__clang__))
#define LLPS_TMR_SECTION_BANK0             "__DATA,llps_tmr0"
#define LLPS_TMR_SECTION_BANK1             "__DATA,llps_tmr1"
#define LLPS_TMR_SECTION_BANK2             "__DATA,llps_tmr2"
#else
#define LLPS_TMR_SECTION_BANK0             ".llps_tmr0"
#define LLPS_TMR_SECTION_BANK1             ".llps_tmr1"
#define LLPS_TMR_SECTION_BANK2             ".llps_tmr2"
#endif

/**
 * @brief Record a soft contract violation without aborting the process.
 *
 * @details The caller remains responsible for executing a fail-closed fallback
 * suitable for the current session or runtime state.
 */
void llps_contract_violation(const char *file,
                             int line,
                             const char *condition);

/**
 * @brief Validate an internal runtime contract and run fallback on failure.
 */
#define LLPS_EXPECT(condition, fallback_action) \
    do { \
        if (LLPS_UNLIKELY(!(condition))) { \
            llps_contract_violation(__FILE__, __LINE__, #condition); \
            fallback_action; \
        } \
    } while (0)

/** @brief Internal session state hidden from the public API. */
typedef enum {
    ST_FREE = 0, /**< Session slot is available and may be reused. */
    ST_ACTIVE    /**< Session slot owns live client/backend pump state. */
} llps_state_t;

/** @brief Direction assigned to a proxy pump task. */
typedef enum {
    LLPS_DIR_C2S = 0, /**< Client-to-server pump direction. */
    LLPS_DIR_S2C      /**< Server-to-client pump direction. */
} llps_direction_t;

/** @brief Session close reason sealed into local and TMR metadata. */
typedef enum {
    LLPS_CLOSE_REASON_NORMAL = 0,
    LLPS_CLOSE_REASON_IDLE_TIMEOUT,
    LLPS_CLOSE_REASON_PAYLOAD_ECC,
    LLPS_CLOSE_REASON_METADATA_FAULT,
    LLPS_CLOSE_REASON_CONTRACT_VIOLATION,
    LLPS_CLOSE_REASON_CLIENT_PREFACE_TIMEOUT,
    LLPS_CLOSE_REASON_PROTOCOL_HANDSHAKE,
    LLPS_CLOSE_REASON_COUNT
} llps_close_reason_t;

/** @brief Private session record. */
typedef struct llps_session llps_session_t;

/** @brief Arguments copied into each LLAM pump task. */
typedef struct {
    llps_session_t *session;   /**< Owning session metadata. */
    int src_fd;                /**< Source socket for this pump. */
    int dst_fd;                /**< Destination socket for this pump. */
    uint8_t *buf;              /**< Direction-specific transfer buffer. */
    size_t buf_len;            /**< Transfer buffer capacity in bytes. */
    llps_direction_t direction; /**< Human-readable direction tag. */
} llps_pump_args_t;

/**
 * @brief Full private session record.
 *
 * @details
 * Session invariants:
 * - ST_FREE means no task may reference this session or its buffers.
 * - ST_ACTIVE means both fds and both pump arguments are initialized.
 * - c2s_buf is used only by the client -> backend pump.
 * - s2c_buf is used only by the backend -> client pump.
 * - c2s_payload_ecc and s2c_payload_ecc are shadow SECDED codes for the
 *   corresponding transfer buffers when payload_ecc_enabled is set.
 * - c2s_payload_ecc_len and s2c_payload_ecc_len are the last sealed byte
 *   lengths for watchdog patrol scrub of those shadow ECC buffers.
 * - pump_c2s.buf == c2s_buf while active.
 * - pump_s2c.buf == s2c_buf while active.
 * - pump tasks must not close shared fds directly.
 * - On clean EOF, a pump may shutdown(dst_fd, SHUT_WR).
 * - On hard error, a pump may shutdown both fds to wake its sibling pump.
 * - client_fd and backend_fd are closed only by the session owner after both
 *   pump tasks have terminated.
 * - ST_FREE transition and free-list return happen only in llps_close_session().
 */
struct llps_session {
    uint32_t magic_start;       /**< Active/free canary at the record head. */
    uint32_t session_id;        /**< Stable slot index. */
    uint8_t session_id_secded;  /**< SECDED code for session_id. */
    llps_state_t state;         /**< Current session ownership state. */
    uint8_t state_secded;       /**< SECDED code for state. */
    uint32_t state_inverse;     /**< Bitwise inverse of encoded state. */
    uint8_t state_inverse_secded; /**< SECDED code for state_inverse. */
    uint64_t last_activity_ns;  /**< Last successful proxy I/O timestamp. */
    uint8_t last_activity_ns_secded; /**< SECDED code for last_activity_ns. */
    uint64_t request_no;        /**< Monotonic accepted-request identifier. */
    uint8_t request_no_secded;  /**< SECDED code for request_no. */
    uint64_t request_no_inverse; /**< Bitwise inverse of request_no. */
    uint8_t request_no_inverse_secded; /**< SECDED code for request_no_inverse. */
    uint32_t close_reason;      /**< Bounded reason used for close auditing. */
    uint8_t close_reason_secded; /**< SECDED code for close_reason. */
    uint32_t close_reason_inverse; /**< Bitwise inverse of close_reason. */
    uint8_t close_reason_inverse_secded; /**< SECDED code for inverse. */

    int client_fd;              /**< Accepted client socket. */
    uint8_t client_fd_secded;   /**< SECDED code for client_fd. */
    int backend_fd;             /**< Connected backend socket. */
    uint8_t backend_fd_secded;  /**< SECDED code for backend_fd. */
    char client_ip[LLPS_CLIENT_IP_TEXT_LEN]; /**< Client IPv4 text. */
    uint16_t client_port;       /**< Client TCP port. */
    uint8_t client_port_secded; /**< SECDED code for client_port. */
    uint32_t client_port_inverse; /**< Bitwise inverse of client_port. */
    uint8_t client_port_inverse_secded; /**< SECDED code for client_port_inverse. */

    llps_pump_args_t pump_c2s;  /**< Client-to-server pump arguments. */
    llps_pump_args_t pump_s2c;  /**< Server-to-client pump arguments. */

    uint8_t c2s_buf[LLPS_BUFFER_SIZE]; /**< Client-to-server transfer buffer. */
    uint8_t s2c_buf[LLPS_BUFFER_SIZE]; /**< Server-to-client transfer buffer. */
    /** Shadow SECDED codes for c2s_buf payload words. */
    uint8_t c2s_payload_ecc[LLPS_PAYLOAD_ECC_WORD_COUNT];
    /** Shadow SECDED codes for s2c_buf payload words. */
    uint8_t s2c_payload_ecc[LLPS_PAYLOAD_ECC_WORD_COUNT];
    uint32_t c2s_payload_ecc_len; /**< Last sealed c2s payload length. */
    uint8_t c2s_payload_ecc_len_secded; /**< SECDED code for c2s length. */
    uint32_t c2s_payload_ecc_len_inverse; /**< Inverse of c2s length. */
    /** SECDED code for c2s_payload_ecc_len_inverse. */
    uint8_t c2s_payload_ecc_len_inverse_secded;
    uint32_t s2c_payload_ecc_len; /**< Last sealed s2c payload length. */
    uint8_t s2c_payload_ecc_len_secded; /**< SECDED code for s2c length. */
    uint32_t s2c_payload_ecc_len_inverse; /**< Inverse of s2c length. */
    /** SECDED code for s2c_payload_ecc_len_inverse. */
    uint8_t s2c_payload_ecc_len_inverse_secded;

    uint32_t integrity_crc;     /**< CRC over local session metadata. */
    uint32_t integrity_crc_inverse; /**< Bitwise inverse of integrity_crc. */
    uint32_t magic_end;         /**< Active/free canary at the record tail. */
};

/** @brief Maximum static memory budget for the session table. */
#define LLPS_SESSION_TABLE_BUDGET_BYTES \
    (4ULL * 1024ULL * 1024ULL)

_Static_assert(((uint64_t)sizeof(llps_session_t) * LLPS_MAX_CLIENTS) <=
               LLPS_SESSION_TABLE_BUDGET_BYTES,
               "session table budget exceeded");

#endif /* LLPS_INTERNAL_H */
