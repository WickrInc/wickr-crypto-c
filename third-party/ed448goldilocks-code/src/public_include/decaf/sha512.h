/**
 * @file decaf/shake.h
 * @copyright Public domain.
 * @author Mike Hamburg
 * @brief SHA2-512
 */

#ifndef __DECAF_SHA512_H__
#define __DECAF_SHA512_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h> /* for NULL */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif
    
/** Hash context for SHA-512 */
typedef struct decaf_sha512_ctx_s {
    /** @cond internal */
    uint64_t state[8];
    uint8_t block[128];
    uint64_t bytes_processed;
    /* @endcond */
} decaf_sha512_ctx_s, decaf_sha512_ctx_t[1];

/** Initialize a SHA-512 context. */
void decaf_sha512_init(decaf_sha512_ctx_t ctx) DECAF_NONNULL DECAF_API_VIS;

/** Update context by hashing part of a message. */
void decaf_sha512_update(decaf_sha512_ctx_t ctx, const uint8_t *message, size_t message_len) DECAF_NONNULL DECAF_API_VIS;

/** Finalize context and write out hash.
 * @param [inout] ctx The context.  Will be destroyed and re-initialized on return.
 * @param [out] output Place to store the output hash.
 * @param [in] output_len Length in bytes of the output hash.  Must between 0 and 64, inclusive.
 */
void decaf_sha512_final(decaf_sha512_ctx_t ctx, uint8_t *output, size_t output_len) DECAF_NONNULL DECAF_API_VIS;

/** Securely destroy a SHA512 context. */
static inline void decaf_sha512_destroy(decaf_sha512_ctx_t ctx) {
    decaf_bzero(ctx,sizeof(*ctx));
}

/** Hash a message.
 * @param [out] output Place to store the output hash.
 * @param [in] output_len Length in bytes of the output hash.  Must between 0 and 64, inclusive.
 * @param [in] message A message to hash.
 * @param [in] message_len Length in bytes of the input message.
 */
static inline void decaf_sha512_hash(
    uint8_t *output,
    size_t output_len,
    const uint8_t *message,
    size_t message_len
) {
    decaf_sha512_ctx_t ctx;
    decaf_sha512_init(ctx);
    decaf_sha512_update(ctx,message,message_len);
    decaf_sha512_final(ctx,output,output_len);
    decaf_sha512_destroy(ctx);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __DECAF_SHA512_H__ */
