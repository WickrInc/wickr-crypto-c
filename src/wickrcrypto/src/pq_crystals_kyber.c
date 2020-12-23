
#include "private/pq_crystals_kyber.h"
#include "kyber/kem.h"

bool pq_crystals_is_supported_mode(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode)
{
#if KYBER_K == 4
    return mode.identifier == KYBER_MODE_1024.identifier;
#else
    return false;
#endif
}

wickr_kyber_keypair_t *pq_crystals_random_keypair(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode)
{
    if (!wickr_kyber_engine_is_supported_mode(engine, mode)) {
        return NULL;
    }
    
    wickr_buffer_t *public_buffer = wickr_buffer_create_empty(mode.public_key_len);
    
    if (!public_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *secret_buffer = wickr_buffer_create_empty(mode.secret_key_len);
    
    if (!secret_buffer) {
        wickr_buffer_destroy(&public_buffer);
        return NULL;
    }
    
    if (crypto_kem_keypair(public_buffer->bytes, secret_buffer->bytes) != 0) {
        return NULL;
    }
    
    wickr_kyber_pub_key_t *pub_key = wickr_kyber_pub_key_create(mode, public_buffer);
    
    if (!pub_key) {
        wickr_buffer_destroy(&public_buffer);
        wickr_buffer_destroy(&secret_buffer);
        return NULL;
    }
    
    wickr_kyber_secret_key_t *secret_key = wickr_kyber_secret_key_create(mode, secret_buffer);
    
    if (!secret_key) {
        wickr_kyber_pub_key_destroy(&pub_key);
        wickr_buffer_destroy(&secret_buffer);
        return NULL;
    }
    
    wickr_kyber_keypair_t *keypair = wickr_kyber_keypair_create(mode, pub_key, secret_key);
    
    if (!keypair) {
        wickr_kyber_pub_key_destroy(&pub_key);
        wickr_kyber_secret_key_destroy(&secret_key);
    }
    
    return keypair;
    
}

wickr_shared_secret_t *pq_crystals_pub_key_encrypt(const wickr_kyber_engine_t *engine,
                                                   const wickr_kyber_pub_key_t *pub_key)
{
    if (!engine || !pub_key) {
        return NULL;
    }
    
    if (!wickr_kyber_engine_is_supported_mode(engine, pub_key->mode)) {
        return NULL;
    }
    
    uint8_t ciphertext[pub_key->mode.ciphertext_len];
    uint8_t shared_secret[pub_key->mode.shared_secret_len];
    
    if (crypto_kem_enc(ciphertext, shared_secret, pub_key->key_data->bytes) != 0) {
        return NULL;
    }
    
    wickr_buffer_t *ciphertext_buffer = wickr_buffer_create(ciphertext, pub_key->mode.ciphertext_len);
    wickr_buffer_t *shared_secret_buffer = wickr_buffer_create(shared_secret, pub_key->mode.shared_secret_len);
    
    wickr_shared_secret_t *kem_result = wickr_shared_secret_create(shared_secret_buffer,
                                                                   ciphertext_buffer);
    
    if (!kem_result) {
        wickr_buffer_destroy(&ciphertext_buffer);
        wickr_buffer_destroy(&shared_secret_buffer);
    }
    
    return kem_result;
}

wickr_shared_secret_t *pq_crystals_secret_key_decrypt(const wickr_kyber_engine_t *engine,
                                                      const wickr_kyber_secret_key_t *secret_key,
                                                      const wickr_buffer_t *ciphertext)
{
    if (!engine || !secret_key || !ciphertext) {
        return NULL;
    }
    
    if (!wickr_kyber_engine_is_supported_mode(engine, secret_key->mode)) {
        return NULL;
    }
    
    uint8_t shared_secret[secret_key->mode.shared_secret_len];
    
    if (crypto_kem_dec(shared_secret, ciphertext->bytes, secret_key->key_data->bytes) != 0) {
        return NULL;
    }
    
    wickr_buffer_t *ciphertext_copy = wickr_buffer_copy(ciphertext);
    wickr_buffer_t *shared_secret_buffer = wickr_buffer_create(shared_secret, secret_key->mode.shared_secret_len);
    
    wickr_shared_secret_t *kem_result = wickr_shared_secret_create(shared_secret_buffer,
                                                                   ciphertext_copy);
    
    if (!kem_result) {
        wickr_buffer_destroy(&ciphertext_copy);
        wickr_buffer_destroy(&shared_secret_buffer);
    }
    
    return kem_result;
}
