//
//  pq_engine_ext.c
//  wickrcrypto
//
//  Created by Thomas Leavy on 12/21/20.
//

#include "pq_engine_ext.h"
#include "ec_kyber_hybrid.h"
#include "openssl_suite.h"
#include "kyber_engine.h"

static wickr_shared_secret_t *__wickr_pq_engine_ext_ec_shared_secret(const wickr_ec_key_t *local_hbrd, const wickr_ec_key_t *peer_hbrd)
{
    /* Extract the two EC keys that we need to use to generate a shared secret */
    
    wickr_ec_key_t *local_ec_keypair = wickr_ec_key_hybrid_get_ec_keypair(local_hbrd, openssl_ec_key_import);
    
    if (!local_ec_keypair) {
        return NULL;
    }
    
    wickr_ec_key_t *peer_ec_keypair = wickr_ec_key_hybrid_get_ec_keypair(peer_hbrd, openssl_ec_key_import);
    
    if (!peer_ec_keypair) {
        wickr_ec_key_destroy(&local_ec_keypair);
        return NULL;
    }
    
    wickr_shared_secret_t *shared_secret = openssl_gen_shared_secret(local_ec_keypair, peer_ec_keypair, NULL);
    wickr_ec_key_destroy(&local_ec_keypair);
    wickr_ec_key_destroy(&peer_ec_keypair);
    
    return shared_secret;
}

static wickr_shared_secret_t *__wickr_pq_engine_ext_kyber_shared_secret(const wickr_ec_key_t *local_hbrd, const wickr_ec_key_t *peer_hbrd, const wickr_buffer_t *ciphertext)
{
    /* Extract the two kyber keys that we need to use to generate a shared secret */
    
    wickr_kyber_secret_key_t *local_kyber_secret_key = wickr_ec_key_hybrid_get_kyber_pri(local_hbrd);
    
    if (!local_kyber_secret_key) {
        return NULL;
    }
    
    if (ciphertext) {
        wickr_shared_secret_t *res = wickr_kyber_engine_secret_key_decrypt(&wickr_kyber_engine_default, local_kyber_secret_key, ciphertext);
        wickr_kyber_secret_key_destroy(&local_kyber_secret_key);
        return res;
    } else {
        wickr_kyber_pub_key_t *peer_kyber_pub_key = wickr_ec_key_hybrid_get_kyber_pub(peer_hbrd);
        
        if (!peer_kyber_pub_key) {
            wickr_kyber_secret_key_destroy(&local_kyber_secret_key);
            return NULL;
        }
        
        wickr_shared_secret_t *kem_result = wickr_kyber_engine_pub_key_encrypt(&wickr_kyber_engine_default, peer_kyber_pub_key);
        
        wickr_kyber_secret_key_destroy(&local_kyber_secret_key);
        wickr_kyber_pub_key_destroy(&peer_kyber_pub_key);
        
        return kem_result;
    }
}

wickr_shared_secret_t *wickr_pq_engine_ext_gen_shared_secret(const wickr_ec_key_t *local, const wickr_ec_key_t *peer, const wickr_buffer_t *ciphertext)
{
    if (!local || !peer) {
        return NULL;
    }
    
    /* If the type of algo doesn't match there is an error */
    if (local->curve.identifier != peer->curve.identifier) {
        return NULL;
    }
    
    if (local->curve.identifier != EC_CURVE_ID_P521_KYBER1024_HYBRID) {
        return openssl_gen_shared_secret(local, peer, NULL);
    }
    
    wickr_shared_secret_t *ec_shared = __wickr_pq_engine_ext_ec_shared_secret(local, peer);
    
    if (!ec_shared) {
        return NULL;
    }
    
    wickr_shared_secret_t *pq_shared = __wickr_pq_engine_ext_kyber_shared_secret(local, peer, ciphertext);
    
    if (!pq_shared) {
        wickr_shared_secret_destroy(&ec_shared);
        return NULL;
    }
    
    wickr_shared_secret_t *merged = wickr_shared_secret_merge(ec_shared, pq_shared);
    wickr_shared_secret_destroy(&ec_shared);
    wickr_shared_secret_destroy(&pq_shared);
    
    return merged;
}

static wickr_ec_key_t *__wickr_pq_engine_ext_rand_hybrid_key(wickr_ec_curve_t curve, wickr_kyber_mode_t kyber_mode)
{
    wickr_ec_key_t *ec_key = openssl_ec_rand_key(EC_CURVE_NIST_P521);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_kyber_keypair_t *kyber_key = wickr_kyber_engine_random_keypair(&wickr_kyber_engine_default, KYBER_MODE_1024);
    
    if (!kyber_key) {
        wickr_ec_key_destroy(&ec_key);
        return NULL;
    }
    
    wickr_ec_key_t *final_key = wickr_ec_key_hybrid_create_with_components(ec_key, kyber_key);
    
    if (!final_key) {
        wickr_ec_key_destroy(&ec_key);
        wickr_kyber_keypair_destroy(&kyber_key);
    }
    
    return final_key;
}

wickr_ec_key_t *wickr_pq_engine_ext_ec_rand_key(wickr_ec_curve_t curve)
{
    switch (curve.identifier) {
        case EC_CURVE_ID_P521_KYBER1024_HYBRID:
            return __wickr_pq_engine_ext_rand_hybrid_key(EC_CURVE_NIST_P521, KYBER_MODE_1024);
        default:
            return openssl_ec_rand_key(curve);
    }
}

wickr_ec_key_t *wickr_pq_engine_ext_ec_key_import(const wickr_buffer_t *buffer,
                                                  bool is_private)
{
    if (!buffer) {
        return NULL;
    }
    
    if (buffer->length <= HYBRID_KEY_HEADER_SIZE || buffer->bytes[0] != EC_CURVE_ID_P521_KYBER1024_HYBRID) {
        return openssl_ec_key_import(buffer, is_private);
    }
    
    if (is_private) {
        /* Note: Kyber secret keys can't be used to derive public keys, so we can just set the public key to an empty buffer */
        return wickr_ec_key_create(EC_CURVE_P521_KYBER_HYBRID, wickr_buffer_create_empty(1), wickr_buffer_copy(buffer));
    } else {
        return wickr_ec_key_create(EC_CURVE_P521_KYBER_HYBRID, wickr_buffer_copy(buffer), NULL);
    }
}
