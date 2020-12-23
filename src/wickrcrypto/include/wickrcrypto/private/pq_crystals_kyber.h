//
//  pq_crystals_kyber.h
//  wickrcrypto
//
//  Created by Thomas Leavy on 12/22/20.
//

#ifndef pq_crystals_kyber_h
#define pq_crystals_kyber_h

#include "buffer.h"
#include "kyber_engine.h"
#include "shared_secret.h"

bool pq_crystals_is_supported_mode(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode);

wickr_kyber_keypair_t *pq_crystals_random_keypair(const wickr_kyber_engine_t *engine, wickr_kyber_mode_t mode);

wickr_shared_secret_t *pq_crystals_pub_key_encrypt(const wickr_kyber_engine_t *engine,
                                                   const wickr_kyber_pub_key_t *pub_key);

wickr_shared_secret_t *pq_crystals_secret_key_decrypt(const wickr_kyber_engine_t *engine,
                                                      const wickr_kyber_secret_key_t *secret_key,
                                                      const wickr_buffer_t *ciphertext);

#endif /* pq_crystals_kyber_h */
