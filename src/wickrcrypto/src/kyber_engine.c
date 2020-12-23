
#include "kyber_engine.h"
#include "private/pq_crystals_kyber.h"

wickr_kyber_engine_t wickr_kyber_engine_default = {
    .is_supported_mode = pq_crystals_is_supported_mode,
    .random_keypair = pq_crystals_random_keypair,
    .pub_key_encrypt = pq_crystals_pub_key_encrypt,
    .secret_key_decrypt = pq_crystals_secret_key_decrypt
};

bool wickr_kyber_engine_is_supported_mode(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode)
{
    if (!engine) {
        return NULL;
    }
    return engine->is_supported_mode(engine, mode);
}

wickr_kyber_keypair_t *wickr_kyber_engine_random_keypair(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode)
{
    if (!engine) {
        return NULL;
    }
    return engine->random_keypair(engine, mode);
}

wickr_shared_secret_t *wickr_kyber_engine_pub_key_encrypt(const wickr_kyber_engine_t *engine,
                                                          const wickr_kyber_pub_key_t *pub_key)
{
    if (!engine) {
        return NULL;
    }
    return engine->pub_key_encrypt(engine, pub_key);
}

wickr_shared_secret_t *wickr_kyber_engine_secret_key_decrypt(const wickr_kyber_engine_t *engine,
                                                             const wickr_kyber_secret_key_t *secret_key,
                                                             const wickr_buffer_t *ciphertext)
{
    if (!engine) {
        return NULL;
    }
    return engine->secret_key_decrypt(engine, secret_key, ciphertext);
}
