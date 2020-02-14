//
//  transport_root_key_priv.h
//  wickrcrypto
//
//  Created by Tom Leavy on 2/3/20.
//

#ifndef transport_root_key_priv_h
#define transport_root_key_priv_h

#include "stream.pb-c.h"
#include "transport_root_key.h"

Wickr__Proto__TransportRootKey *wickr_transport_root_key_to_proto(const wickr_transport_root_key_t *root_key);
wickr_transport_root_key_t *wickr_transport_root_key_from_proto(const Wickr__Proto__TransportRootKey *root_key_proto);
void wickr_transport_root_key_proto_free(Wickr__Proto__TransportRootKey *root_key_proto);

#endif /* transport_root_key_priv_h */
