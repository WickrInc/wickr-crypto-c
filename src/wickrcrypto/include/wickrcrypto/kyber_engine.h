//
//  kyber_engine.h
//  WickrCryptoC
//
//  Created by Thomas Leavy on 12/22/20.
//

#ifndef kyber_engine_h
#define kyber_engine_h

#include "kyber_key.h"
#include "shared_secret.h"

struct wickr_kyber_engine {
    bool (*is_supported_mode)(const struct wickr_kyber_engine *engine, wickr_kyber_mode_t mode);
    
    wickr_kyber_keypair_t *(*random_keypair)(const struct wickr_kyber_engine *engine, wickr_kyber_mode_t mode);
    
    wickr_shared_secret_t *(*pub_key_encrypt)(const struct wickr_kyber_engine *engine,
                                              const wickr_kyber_pub_key_t *pub_key);
    
    wickr_shared_secret_t *(*secret_key_decrypt)(const struct wickr_kyber_engine *engine,
                                                 const wickr_kyber_secret_key_t *secret_key,
                                                 const wickr_buffer_t *ciphertext);
};

typedef struct wickr_kyber_engine wickr_kyber_engine_t;

extern wickr_kyber_engine_t wickr_kyber_engine_default;

bool wickr_kyber_engine_is_supported_mode(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode);

wickr_kyber_keypair_t *wickr_kyber_engine_random_keypair(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode);

wickr_shared_secret_t *wickr_kyber_engine_pub_key_encrypt(const wickr_kyber_engine_t *engine,
                                                          const wickr_kyber_pub_key_t *pub_key);

wickr_shared_secret_t *wickr_kyber_engine_secret_key_decrypt(const wickr_kyber_engine_t *engine,
                                                             const wickr_kyber_secret_key_t *secret_key,
                                                             const wickr_buffer_t *ciphertext);

#endif /* kyber_engine_h */
