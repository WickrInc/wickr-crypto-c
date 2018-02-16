
#include "storage.h"
#include "memory.h"
#include "storage.pb-c.h"
#include "private/cipher_priv.h"

#define CURRENT_STORAGE_KEY_VERSION 1

wickr_storage_keys_t *wickr_storage_keys_create(wickr_cipher_key_t *local, wickr_cipher_key_t *remote)
{
    if (!local || !remote) {
        return NULL;
    }
    
    wickr_storage_keys_t *keys = wickr_alloc_zero(sizeof(wickr_storage_keys_t));
    
    if (!keys) {
        return NULL;
    }
    
    keys->local = local;
    keys->remote = remote;
    
    return keys;
}

wickr_storage_keys_t *wickr_storage_keys_copy(const wickr_storage_keys_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_cipher_key_t *local_copy = wickr_cipher_key_copy(source->local);
    
    if (!local_copy) {
        return NULL;
    }
    
    wickr_cipher_key_t *remote_copy = wickr_cipher_key_copy(source->remote);
    
    if (!remote_copy) {
        wickr_cipher_key_destroy(&local_copy);
        return NULL;
    }
    
    wickr_storage_keys_t *keys_copy = wickr_storage_keys_create(local_copy, remote_copy);
    
    if (!keys_copy) {
        wickr_cipher_key_destroy(&local_copy);
        wickr_cipher_key_destroy(&remote_copy);
    }
    
    return keys_copy;
}

wickr_buffer_t *wickr_storage_keys_serialize(const wickr_storage_keys_t *keys)
{
    if (!keys) {
        return NULL;
    }
    
    wickr_buffer_t *local_key_buffer = wickr_cipher_key_serialize(keys->local);
    
    if (!local_key_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *remote_key_buffer = wickr_cipher_key_serialize(keys->remote);
    
    if (!remote_key_buffer) {
        wickr_buffer_destroy_zero(&local_key_buffer);
        return NULL;
    }
    
    Wickr__Proto__StorageKeys proto_keys = WICKR__PROTO__STORAGE_KEYS__INIT;
    proto_keys.version = CURRENT_STORAGE_KEY_VERSION;
    proto_keys.local_storage.data = local_key_buffer->bytes;
    proto_keys.local_storage.len = local_key_buffer->length;
    proto_keys.remote_storage.data = remote_key_buffer->bytes;
    proto_keys.remote_storage.len = remote_key_buffer->length;
    proto_keys.has_local_storage = true;
    proto_keys.has_remote_storage = true;
    
    size_t buffer_size = wickr__proto__storage_keys__get_packed_size(&proto_keys);
    
    wickr_buffer_t *concat_buffer = wickr_buffer_create_empty(buffer_size);
    
    if (!concat_buffer) {
        wickr_buffer_destroy_zero(&local_key_buffer);
        wickr_buffer_destroy_zero(&remote_key_buffer);
        return NULL;
    }
    
    wickr__proto__storage_keys__pack(&proto_keys, concat_buffer->bytes);
    wickr_buffer_destroy_zero(&local_key_buffer);
    wickr_buffer_destroy_zero(&remote_key_buffer);
    
    return concat_buffer;
}

wickr_storage_keys_t *wickr_storage_keys_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__StorageKeys *key_proto = wickr__proto__storage_keys__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!key_proto) {
        return NULL;
    }
    
    if (key_proto->version > CURRENT_STORAGE_KEY_VERSION ||
        !key_proto->has_local_storage || !key_proto->has_remote_storage) {
        wickr__proto__storage_keys__free_unpacked(key_proto, NULL);
        return NULL;
    }
    
    wickr_cipher_key_t *local_key = wickr_cipher_key_from_protobytes(key_proto->local_storage);
    
    if (!local_key) {
        wickr__proto__storage_keys__free_unpacked(key_proto, NULL);
        return NULL;
    }
    
    wickr_cipher_key_t *remote_key = wickr_cipher_key_from_protobytes(key_proto->remote_storage);
    
    if (!remote_key) {
        wickr_cipher_key_destroy(&local_key);
        wickr__proto__storage_keys__free_unpacked(key_proto, NULL);
        return NULL;
    }
    
    wickr_storage_keys_t *storage_keys = wickr_storage_keys_create(local_key, remote_key);
    wickr__proto__storage_keys__free_unpacked(key_proto, NULL);
    
    if (!storage_keys) {
        wickr_cipher_key_destroy(&local_key);
        wickr_cipher_key_destroy(&remote_key);
    }
    
    return storage_keys;
}



void wickr_storage_keys_destroy(wickr_storage_keys_t **keys)
{
    if (!keys || !*keys) {
        return;
    }
    
    wickr_cipher_key_destroy(&(*keys)->local);
    wickr_cipher_key_destroy(&(*keys)->remote);
    wickr_free(*keys);
    *keys = NULL;
}
