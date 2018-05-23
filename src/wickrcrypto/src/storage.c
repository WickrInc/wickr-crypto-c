
#include "private/storage_priv.h"
#include "memory.h"
#include "storage.pb-c.h"
#include "private/cipher_priv.h"

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
    
    Wickr__Proto__StorageKeys *proto_keys = wickr_storage_keys_to_proto(keys);
    size_t buffer_size = wickr__proto__storage_keys__get_packed_size(proto_keys);
    wickr_buffer_t *concat_buffer = wickr_buffer_create_empty(buffer_size);
    
    if (!concat_buffer) {
        wickr_storage_keys_proto_free(proto_keys);
        return NULL;
    }
    
    wickr__proto__storage_keys__pack(proto_keys, concat_buffer->bytes);
    wickr_storage_keys_proto_free(proto_keys);
    
    return concat_buffer;
}

wickr_storage_keys_t *wickr_storage_keys_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__StorageKeys *key_proto = wickr__proto__storage_keys__unpack(NULL, buffer->length,
                                                                              buffer->bytes);
    
    wickr_storage_keys_t *storage_keys = wickr_storage_keys_create_from_proto(key_proto);
    wickr__proto__storage_keys__free_unpacked(key_proto, NULL);
    
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
