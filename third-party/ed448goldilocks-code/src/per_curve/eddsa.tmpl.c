/**
 * @cond internal
 * @brief EdDSA routines.
 */

#include "word.h"
#include <decaf/ed$(gf_bits).h>
#include <decaf/shake.h>
#include <decaf/sha512.h>
#include <string.h>

#define API_NAME "$(c_ns)"
#define API_NS(_id) $(c_ns)_##_id

#define hash_ctx_t   decaf_$(eddsa_hash)_ctx_t
#define hash_init    decaf_$(eddsa_hash)_init
#define hash_update  decaf_$(eddsa_hash)_update
#define hash_final   decaf_$(eddsa_hash)_final
#define hash_destroy decaf_$(eddsa_hash)_destroy
#define hash_hash    decaf_$(eddsa_hash)_hash

#define NO_CONTEXT DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTLESS_SIGS
#define EDDSA_USE_SIGMA_ISOGENY $(eddsa_sigma_iso)
#define COFACTOR $(cofactor)
#define EDDSA_PREHASH_BYTES 64

#if NO_CONTEXT
const uint8_t NO_CONTEXT_POINTS_HERE = 0;
const uint8_t * const DECAF_ED$(gf_shortname)_NO_CONTEXT = &NO_CONTEXT_POINTS_HERE;
#endif

static void clamp (
    uint8_t secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) {
    /* Blarg */
    secret_scalar_ser[0] &= -COFACTOR;
    uint8_t hibit = (1<<$(gf_bits % 8))>>1;
    if (hibit == 0) {
        secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES - 1] = 0;
        secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES - 2] |= 0x80;
    } else {
        secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES - 1] &= hibit-1;
        secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES - 1] |= hibit;
    }
}

static void hash_init_with_dom(
    hash_ctx_t hash,
    uint8_t prehashed,
    uint8_t for_prehash,
    const uint8_t *context,
    uint8_t context_len
) {
    hash_init(hash);

#if NO_CONTEXT
    if (context_len == 0 && context == DECAF_ED$(gf_shortname)_NO_CONTEXT) {
        (void)prehashed;
        (void)for_prehash;
        (void)context;
        (void)context_len;
        return;
    }
#endif
    const char *dom_s = "$(eddsa_dom)";
    const uint8_t dom[2] = {2+word_is_zero(prehashed)+word_is_zero(for_prehash), context_len};
    hash_update(hash,(const unsigned char *)dom_s, strlen(dom_s));
    hash_update(hash,dom,2);
    hash_update(hash,context,context_len);
}

void decaf_ed$(gf_shortname)_prehash_init (
    hash_ctx_t hash
) {
    hash_init(hash);
}

/* In this file because it uses the hash */
void decaf_ed$(gf_shortname)_convert_private_key_to_x$(gf_shortname) (
    uint8_t x[DECAF_X$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t ed[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) {
    /* pass the private key through hash_hash function */
    /* and keep the first DECAF_X$(gf_shortname)_PRIVATE_BYTES bytes */
    hash_hash(
        x,
        DECAF_X$(gf_shortname)_PRIVATE_BYTES,
        ed,
        DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES
    );
}
    
void decaf_ed$(gf_shortname)_derive_public_key (
    uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) {
    /* only this much used for keygen */
    uint8_t secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
    
    hash_hash(
        secret_scalar_ser,
        sizeof(secret_scalar_ser),
        privkey,
        DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES
    );
    clamp(secret_scalar_ser);
        
    API_NS(scalar_t) secret_scalar;
    API_NS(scalar_decode_long)(secret_scalar, secret_scalar_ser, sizeof(secret_scalar_ser));
    
    /* Since we are going to mul_by_cofactor during encoding, divide by it here.
     * However, the EdDSA base point is not the same as the decaf base point if
     * the sigma isogeny is in use: the EdDSA base point is on Etwist_d/(1-d) and
     * the decaf base point is on Etwist_d, and when converted it effectively
     * picks up a factor of 2 from the isogenies.  So we might start at 2 instead of 1. 
     */
    for (unsigned int c=1; c<$(C_NS)_EDDSA_ENCODE_RATIO; c <<= 1) {
        API_NS(scalar_halve)(secret_scalar,secret_scalar);
    }
    
    API_NS(point_t) p;
    API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),secret_scalar);
    
    API_NS(point_mul_by_ratio_and_encode_like_eddsa)(pubkey, p);
        
    /* Cleanup */
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(point_destroy)(p);
    decaf_bzero(secret_scalar_ser, sizeof(secret_scalar_ser));
}

void decaf_ed$(gf_shortname)_sign (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) {
    API_NS(scalar_t) secret_scalar;
    hash_ctx_t hash;
    {
        /* Schedule the secret key */
        struct {
            uint8_t secret_scalar_ser[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
            uint8_t seed[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
        } __attribute__((packed)) expanded;
        hash_hash(
            (uint8_t *)&expanded,
            sizeof(expanded),
            privkey,
            DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES
        );
        clamp(expanded.secret_scalar_ser);   
        API_NS(scalar_decode_long)(secret_scalar, expanded.secret_scalar_ser, sizeof(expanded.secret_scalar_ser));
    
        /* Hash to create the nonce */
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,expanded.seed,sizeof(expanded.seed));
        hash_update(hash,message,message_len);
        decaf_bzero(&expanded, sizeof(expanded));
    }
    
    /* Decode the nonce */
    API_NS(scalar_t) nonce_scalar;
    {
        uint8_t nonce[2*DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
        hash_final(hash,nonce,sizeof(nonce));
        API_NS(scalar_decode_long)(nonce_scalar, nonce, sizeof(nonce));
        decaf_bzero(nonce, sizeof(nonce));
    }
    
    uint8_t nonce_point[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES] = {0};
    {
        /* Scalarmul to create the nonce-point */
        API_NS(scalar_t) nonce_scalar_2;
        API_NS(scalar_halve)(nonce_scalar_2,nonce_scalar);
        for (unsigned int c = 2; c < $(C_NS)_EDDSA_ENCODE_RATIO; c <<= 1) {
            API_NS(scalar_halve)(nonce_scalar_2,nonce_scalar_2);
        }
        
        API_NS(point_t) p;
        API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),nonce_scalar_2);
        API_NS(point_mul_by_ratio_and_encode_like_eddsa)(nonce_point, p);
        API_NS(point_destroy)(p);
        API_NS(scalar_destroy)(nonce_scalar_2);
    }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,nonce_point,sizeof(nonce_point));
        hash_update(hash,pubkey,DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES);
        hash_update(hash,message,message_len);
        uint8_t challenge[2*DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
        hash_final(hash,challenge,sizeof(challenge));
        hash_destroy(hash);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        decaf_bzero(challenge,sizeof(challenge));
    }
    
    API_NS(scalar_mul)(challenge_scalar,challenge_scalar,secret_scalar);
    API_NS(scalar_add)(challenge_scalar,challenge_scalar,nonce_scalar);
    
    decaf_bzero(signature,DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES);
    memcpy(signature,nonce_point,sizeof(nonce_point));
    API_NS(scalar_encode)(&signature[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],challenge_scalar);
    
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(scalar_destroy)(nonce_scalar);
    API_NS(scalar_destroy)(challenge_scalar);
}


void decaf_ed$(gf_shortname)_sign_prehash (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        decaf_ed$(gf_shortname)_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }

    decaf_ed$(gf_shortname)_sign(signature,privkey,pubkey,hash_output,sizeof(hash_output),1,context,context_len);
    decaf_bzero(hash_output,sizeof(hash_output));
}

decaf_error_t decaf_ed$(gf_shortname)_verify (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) { 
    API_NS(point_t) pk_point, r_point;
    decaf_error_t error = API_NS(point_decode_like_eddsa_and_mul_by_ratio)(pk_point,pubkey);
    if (DECAF_SUCCESS != error) { return error; }
    
    error = API_NS(point_decode_like_eddsa_and_mul_by_ratio)(r_point,signature);
    if (DECAF_SUCCESS != error) { return error; }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        hash_ctx_t hash;
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,signature,DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES);
        hash_update(hash,pubkey,DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES);
        hash_update(hash,message,message_len);
        uint8_t challenge[2*DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES];
        hash_final(hash,challenge,sizeof(challenge));
        hash_destroy(hash);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        decaf_bzero(challenge,sizeof(challenge));
    }
    API_NS(scalar_sub)(challenge_scalar, API_NS(scalar_zero), challenge_scalar);
    
    API_NS(scalar_t) response_scalar;
    API_NS(scalar_decode_long)(
        response_scalar,
        &signature[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
        DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES
    );
    
    for (unsigned c=1; c<$(C_NS)_EDDSA_DECODE_RATIO; c<<=1) {
        API_NS(scalar_add)(response_scalar,response_scalar,response_scalar);
    }
    
    
    /* pk_point = -c(x(P)) + (cx + k)G = kG */
    API_NS(base_double_scalarmul_non_secret)(
        pk_point,
        response_scalar,
        pk_point,
        challenge_scalar
    );
    return decaf_succeed_if(API_NS(point_eq(pk_point,r_point)));
}


decaf_error_t decaf_ed$(gf_shortname)_verify_prehash (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    decaf_error_t ret;
    
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        decaf_ed$(gf_shortname)_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }
    
    ret = decaf_ed$(gf_shortname)_verify(signature,pubkey,hash_output,sizeof(hash_output),1,context,context_len);
    
    return ret;
}
