/** @brief A group of prime order p, based on $(iso_to). */

#include <decaf/point_$(gf_bits).h>
#include <decaf/shake.h>
#include <decaf/sha512.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bytes in an EdDSA public key. */
#define DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES $((gf_bits)//8 + 1)

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES (DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES + DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES)

/** Does EdDSA support non-contextual signatures? */
#define DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTLESS_SIGS $(eddsa_no_context)
$("extern const uint8_t * const DECAF_ED" + gf_shortname + "_NO_CONTEXT DECAF_API_VIS;\n" if eddsa_no_context else "")

/** Prehash context (raw), because each EdDSA instance has a different prehash. */
#define decaf_ed$(gf_shortname)_prehash_ctx_s   decaf_$(eddsa_hash)_ctx_s

/** Prehash context, array[1] form. */
#define decaf_ed$(gf_shortname)_prehash_ctx_t   decaf_$(eddsa_hash)_ctx_t
    
/** Prehash update. */
#define decaf_ed$(gf_shortname)_prehash_update  decaf_$(eddsa_hash)_update
    
/** Prehash destroy. */
#define decaf_ed$(gf_shortname)_prehash_destroy decaf_$(eddsa_hash)_destroy

/** EdDSA encoding ratio. */
#define $(C_NS)_EDDSA_ENCODE_RATIO $(eddsa_encode_ratio)

/** EdDSA decoding ratio. */
#define $(C_NS)_EDDSA_DECODE_RATIO ($(cofactor) / $(eddsa_encode_ratio))

/**
 * @brief EdDSA key generation.  This function uses a different (non-Decaf)
 * encoding.
 *
 * @param [out] pubkey The public key.
 * @param [in] privkey The private key.
 */    
void decaf_ed$(gf_shortname)_derive_public_key (
    uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief EdDSA signing.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] message The message to sign.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to sign.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */  
void decaf_ed$(gf_shortname)_sign (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) DECAF_API_VIS __attribute__((nonnull(1,2,3))) DECAF_NOINLINE;

/**
 * @brief EdDSA signing with prehash.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */  
void decaf_ed$(gf_shortname)_sign_prehash (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) DECAF_API_VIS __attribute__((nonnull(1,2,3,4))) DECAF_NOINLINE;
    
/**
 * @brief Prehash initialization, with contexts if supported.
 *
 * @param [out] hash The hash object to be initialized.
 */
void decaf_ed$(gf_shortname)_prehash_init (
    decaf_ed$(gf_shortname)_prehash_ctx_t hash
) DECAF_API_VIS __attribute__((nonnull(1))) DECAF_NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] message The message to verify.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to verify.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
decaf_error_t decaf_ed$(gf_shortname)_verify (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) DECAF_API_VIS __attribute__((nonnull(1,2))) DECAF_NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
decaf_error_t decaf_ed$(gf_shortname)_verify_prehash (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) DECAF_API_VIS __attribute__((nonnull(1,2))) DECAF_NOINLINE;

/**
 * @brief EdDSA point encoding.  Used internally, exposed externally.
 * Multiplies by $(C_NS)_EDDSA_ENCODE_RATIO first.
 *
 * The multiplication is required because the EdDSA encoding represents
 * the cofactor information, but the Decaf encoding ignores it (which
 * is the whole point).  So if you decode from EdDSA and re-encode to
 * EdDSA, the cofactor info must get cleared, because the intermediate
 * representation doesn't track it.
 *
 * The way libdecaf handles this is to multiply by
 * $(C_NS)_EDDSA_DECODE_RATIO when decoding, and by
 * $(C_NS)_EDDSA_ENCODE_RATIO when encoding.  The product of these
 * ratios is always exactly the cofactor $(cofactor), so the cofactor
 * ends up cleared one way or another.  But exactly how that shakes
 * out depends on the base points specified in RFC 8032.
 *
 * The upshot is that if you pass the Decaf/Ristretto base point to
 * this function, you will get $(C_NS)_EDDSA_ENCODE_RATIO times the
 * EdDSA base point.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
void $(c_ns)_point_mul_by_ratio_and_encode_like_eddsa (
    uint8_t enc[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const $(c_ns)_point_t p
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief EdDSA point decoding.  Multiplies by $(C_NS)_EDDSA_DECODE_RATIO,
 * and ignores cofactor information.
 *
 * See notes on $(c_ns)_point_mul_by_ratio_and_encode_like_eddsa
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
decaf_error_t $(c_ns)_point_decode_like_eddsa_and_mul_by_ratio (
    $(c_ns)_point_t p,
    const uint8_t enc[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief EdDSA to ECDH public key conversion
 * Deserialize the point to get y on Edwards curve,
 * Convert it to u coordinate on Montgomery curve.
 *
 * @warning This function does not check that the public key being converted
 * is a valid EdDSA public key (FUTURE?)
 *
 * @param[out] x The ECDH public key as in RFC7748(point on Montgomery curve)
 * @param[in] ed The EdDSA public key(point on Edwards curve)
 */
void decaf_ed$(gf_shortname)_convert_public_key_to_x$(gf_shortname) (
    uint8_t x[DECAF_X$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t ed[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief EdDSA to ECDH private key conversion
 * Using the appropriate hash function, hash the EdDSA private key
 * and keep only the lower bytes to get the ECDH private key
 *
 * @param[out] x The ECDH private key as in RFC7748
 * @param[in] ed The EdDSA private key
 */
void decaf_ed$(gf_shortname)_convert_private_key_to_x$(gf_shortname) (
    uint8_t x[DECAF_X$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t ed[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

#ifdef __cplusplus
} /* extern "C" */
#endif
