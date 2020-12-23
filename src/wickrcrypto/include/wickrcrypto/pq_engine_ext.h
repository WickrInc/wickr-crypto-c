//
//  pq_engine_ext.h
//  wickrcrypto
//
//  Created by Thomas Leavy on 12/21/20.
//

#ifndef pq_engine_ext_h
#define pq_engine_ext_h

#include "buffer.h"
#include "ec_kyber_hybrid.h"
#include "shared_secret.h"

wickr_shared_secret_t *wickr_pq_engine_ext_gen_shared_secret(const wickr_ec_key_t *local, const wickr_ec_key_t *peer, const wickr_buffer_t *ciphertext);

wickr_ec_key_t *wickr_pq_engine_ext_ec_rand_key(wickr_ec_curve_t curve);

wickr_ec_key_t *wickr_pq_engine_ext_ec_key_import(const wickr_buffer_t *buffer,
                                                  bool is_private);

#endif /* pq_engine_ext_h */
