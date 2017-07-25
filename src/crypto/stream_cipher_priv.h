//
//  stream_cipher_priv.h
//  Crypto
//
//  Created by Tom Leavy on 7/25/17.
//
//

#ifndef stream_cipher_priv_h
#define stream_cipher_priv_h

#include "stream_cipher.h"
#include "stream.pb-c.h"

void wickr_stream_key_proto_free(Wickr__Proto__StreamKey *proto_key);
Wickr__Proto__StreamKey *wickr_stream_key_to_proto(const wickr_stream_key_t *key);
wickr_stream_key_t *wickr_stream_key_create_from_proto(const Wickr__Proto__StreamKey *proto);

#endif /* stream_cipher_priv_h */
