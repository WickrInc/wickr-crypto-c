
#include "private/transport_root_key_priv.h"
#include "private/stream_key_priv.h"
#include "private/buffer_priv.h"
#include "memory.h"

Wickr__Proto__TransportRootKey *wickr_transport_root_key_to_proto(const wickr_transport_root_key_t *root_key)
{
    if (!root_key) {
        return NULL;
    }
    
    Wickr__Proto__TransportRootKey *root_key_proto = wickr_alloc_zero(sizeof(Wickr__Proto__TransportRootKey));
    
    if (!root_key_proto) {
        return NULL;
    }
    
    wickr__proto__transport_root_key__init(root_key_proto);
    
    root_key_proto->cipher_id = root_key->cipher.cipher_id;
    root_key_proto->has_cipher_id = true;
    
    root_key_proto->packets_per_evo_send = root_key->packets_per_evo_send;
    root_key_proto->packets_per_evo_recv = root_key->packets_per_evo_recv;
    root_key_proto->has_packets_per_evo_recv = true;
    root_key_proto->has_packets_per_evo_send = true;
    
    if (!wickr_buffer_to_protobytes(&root_key_proto->secret, root_key->secret)) {
        wickr_free(root_key_proto);
        return NULL;
    }
    
    root_key_proto->has_secret = true;
    return root_key_proto;
}

wickr_transport_root_key_t *wickr_transport_root_key_from_proto(const Wickr__Proto__TransportRootKey *root_key_proto)
{
    if (!root_key_proto || !root_key_proto->has_cipher_id ||
        !root_key_proto->has_secret || !root_key_proto->has_packets_per_evo_send || !root_key_proto->has_packets_per_evo_recv) {
        return NULL;
    }
    
    wickr_buffer_t *secret_buffer = wickr_buffer_from_protobytes(root_key_proto->secret);
    
    if (!secret_buffer) {
        return NULL;
    }
    
    const wickr_cipher_t *cipher = wickr_cipher_find(root_key_proto->cipher_id);
    
    if (!cipher) {
        wickr_buffer_destroy(&secret_buffer);
        return NULL;
    }
    
    wickr_transport_root_key_t *root_key = wickr_transport_root_key_create(secret_buffer, *cipher,
                                                                           root_key_proto->packets_per_evo_send,
                                                                           root_key_proto->packets_per_evo_recv);
    
    if (!root_key) {
        wickr_buffer_destroy(&secret_buffer);
    }
    
    return root_key;
}

void wickr_transport_root_key_proto_free(Wickr__Proto__TransportRootKey *root_key_proto)
{
    if (!root_key_proto) {
        return;
    }
    
    wickr_free(root_key_proto->secret.data);
    wickr_free(root_key_proto);
}
