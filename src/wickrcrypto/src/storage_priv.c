
#include "private/storage_priv.h"
#include "private/cipher_priv.h"
#include "memory.h"

#define CURRENT_STORAGE_KEY_VERSION 1

void wickr_storage_keys_proto_free(Wickr__Proto__StorageKeys *proto_keys)
{
    if (!proto_keys) {
        return;
    }
    
    wickr_free(proto_keys->local_storage.data);
    wickr_free(proto_keys->remote_storage.data);
    wickr_free(proto_keys);
}

Wickr__Proto__StorageKeys *wickr_storage_keys_to_proto(const wickr_storage_keys_t *keys)
{
    if (!keys) {
        return NULL;
    }
    
    Wickr__Proto__StorageKeys *proto_keys = wickr_alloc_zero(sizeof(Wickr__Proto__StorageKeys));
    wickr__proto__storage_keys__init(proto_keys);
    proto_keys->version = CURRENT_STORAGE_KEY_VERSION;
    
    if (!wickr_cipher_key_to_protobytes(&proto_keys->local_storage, keys->local)) {
        wickr_storage_keys_proto_free(proto_keys);
        return NULL;
    }
    
    if (!wickr_cipher_key_to_protobytes(&proto_keys->remote_storage, keys->remote)) {
        wickr_storage_keys_proto_free(proto_keys);
        return NULL;
    }
    
    proto_keys->has_local_storage = true;
    proto_keys->has_remote_storage = true;
    
    return proto_keys;
}

wickr_storage_keys_t *wickr_storage_keys_create_from_proto(const Wickr__Proto__StorageKeys *proto)
{
    if (!proto || !proto->has_local_storage || !proto->has_remote_storage) {
        return NULL;
    }
    
    if (proto->version != CURRENT_STORAGE_KEY_VERSION) {
        return NULL;
    }
    
    wickr_cipher_key_t *local_storage = wickr_cipher_key_from_protobytes(proto->local_storage);
    
    if (!local_storage) {
        return NULL;
    }
    
    wickr_cipher_key_t *remote_storage = wickr_cipher_key_from_protobytes(proto->remote_storage);
    
    if (!remote_storage) {
        wickr_cipher_key_destroy(&local_storage);
        return NULL;
    }
    
    wickr_storage_keys_t *keys = wickr_storage_keys_create(local_storage, remote_storage);
    
    if (!keys) {
        wickr_cipher_key_destroy(&local_storage);
        wickr_cipher_key_destroy(&remote_storage);
    }
    
    return keys;
}
