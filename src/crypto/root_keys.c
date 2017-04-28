
#include "root_keys.h"
#include "memory.h"
#include "protobuf_util.h"

#define CURRENT_ROOT_KEY_VERSION 1

wickr_root_keys_t *wickr_root_keys_create(wickr_ec_key_t *node_signature_root, wickr_cipher_key_t *node_storage_root,
                                          wickr_cipher_key_t *remote_storage_root)
{
    if (!node_signature_root || !node_storage_root || !remote_storage_root) {
        return NULL;
    }
    
    wickr_root_keys_t *new_keys = wickr_alloc_zero(sizeof(wickr_root_keys_t));
    
    if (!new_keys) {
        return NULL;
    }
    
    new_keys->node_signature_root = node_signature_root;
    new_keys->node_storage_root = node_storage_root;
    new_keys->remote_storage_root = remote_storage_root;
    
    return new_keys;
}

wickr_root_keys_t *wickr_root_keys_generate(const wickr_crypto_engine_t *engine)
{
    if (!engine) {
        return NULL;
    }
    
    wickr_cipher_key_t *new_node_storage_root = engine->wickr_crypto_engine_cipher_key_random(engine->default_cipher);
    
    if (!new_node_storage_root) {
        return NULL;
    }
    
    wickr_cipher_key_t *new_remote_storage_root = engine->wickr_crypto_engine_cipher_key_random(engine->default_cipher);
    
    if (!new_remote_storage_root) {
        wickr_cipher_key_destroy(&new_node_storage_root);
        return NULL;
    }
    
    wickr_ec_key_t *new_signature_root = engine->wickr_crypto_engine_ec_rand_key(engine->default_curve);
    
    if (!new_node_storage_root) {
        wickr_cipher_key_destroy(&new_node_storage_root);
        wickr_cipher_key_destroy(&new_remote_storage_root);
        return NULL;
    }
    
    wickr_root_keys_t *root_keys = wickr_root_keys_create(new_signature_root, new_node_storage_root, new_remote_storage_root);
    
    if (!root_keys) {
        wickr_cipher_key_destroy(&new_node_storage_root);
        wickr_cipher_key_destroy(&new_remote_storage_root);
        wickr_ec_key_destroy(&new_signature_root);
    }
    
    return root_keys;
}

wickr_root_keys_t *wickr_root_keys_create_from_buffer(const wickr_crypto_engine_t *engine, const wickr_buffer_t *buffer)
{
    if (!buffer || !engine) {
        return NULL;
    }
    
    Wickr__Proto__RootKeys *proto_keypair = wickr__proto__root_keys__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!proto_keypair) {
        return NULL;
    }
    
    if (!proto_keypair->has_node_storage_root || !proto_keypair->has_remote_storage_root ||
        proto_keypair->version > CURRENT_ROOT_KEY_VERSION) {
        wickr__proto__root_keys__free_unpacked(proto_keypair, NULL);
        return NULL;
    }
    
    wickr_buffer_t node_key_buffer;
    node_key_buffer.bytes = proto_keypair->node_storage_root.data;
    node_key_buffer.length = proto_keypair->node_storage_root.len;
    
    wickr_cipher_key_t *node_storage_key = wickr_cipher_key_from_protobytes(proto_keypair->node_storage_root);
    
    if (!node_storage_key) {
        wickr__proto__root_keys__free_unpacked(proto_keypair, NULL);
        return NULL;
    }
    
    wickr_cipher_key_t *remote_storage_key = wickr_cipher_key_from_protobytes(proto_keypair->remote_storage_root);
    
    if (!node_storage_key) {
        wickr_cipher_key_destroy(&node_storage_key);
        wickr__proto__root_keys__free_unpacked(proto_keypair, NULL);
        return NULL;
    }
    
    wickr_ec_key_t *node_signature_root = wickr_ec_key_from_protobytes(proto_keypair->node_signature_root, engine);
    
    if (!node_signature_root) {
        wickr_cipher_key_destroy(&remote_storage_key);
        wickr_cipher_key_destroy(&node_storage_key);
        wickr__proto__root_keys__free_unpacked(proto_keypair, NULL);
        return NULL;
    }
    
    wickr_root_keys_t *root_keys = wickr_root_keys_create(node_signature_root, node_storage_key, remote_storage_key);
    wickr__proto__root_keys__free_unpacked(proto_keypair, NULL);
    
    if (!root_keys) {
        wickr_cipher_key_destroy(&remote_storage_key);
        wickr_cipher_key_destroy(&node_storage_key);
        wickr_ec_key_destroy(&node_signature_root);
    }
    
    return root_keys;
}

wickr_buffer_t *wickr_root_keys_serialize(const wickr_root_keys_t *keys)
{
    Wickr__Proto__RootKeys rootkeys = WICKR__PROTO__ROOT_KEYS__INIT;
    rootkeys.version = CURRENT_ROOT_KEY_VERSION;
    
    rootkeys.node_signature_root.data = keys->node_signature_root->pri_data->bytes;
    rootkeys.node_signature_root.len = keys->node_signature_root->pri_data->length;
    rootkeys.has_node_signature_root = true;
    
    wickr_buffer_t *node_storage_root_serialized = wickr_cipher_key_serialize(keys->node_storage_root);
    
    if (!node_storage_root_serialized) {
        return NULL;
    }
    
    rootkeys.node_storage_root.len = node_storage_root_serialized->length;
    rootkeys.node_storage_root.data = node_storage_root_serialized->bytes;
    rootkeys.has_node_storage_root = true;
    
    wickr_buffer_t *remote_storage_root_serialized = wickr_cipher_key_serialize(keys->remote_storage_root);
    
    if (!remote_storage_root_serialized) {
        wickr_buffer_destroy_zero(&node_storage_root_serialized);
        return NULL;
    }
    
    rootkeys.remote_storage_root.len = remote_storage_root_serialized->length;
    rootkeys.remote_storage_root.data = remote_storage_root_serialized->bytes;
    rootkeys.has_remote_storage_root = true;
    
    size_t expected_size = wickr__proto__root_keys__get_packed_size(&rootkeys);
    
    if (expected_size == 0) {
        wickr_buffer_destroy_zero(&remote_storage_root_serialized);
        wickr_buffer_destroy_zero(&node_storage_root_serialized);
        return NULL;
    }
    
    wickr_buffer_t *serialized_object = wickr_buffer_create_empty(expected_size);
    
    if (!serialized_object) {
        wickr_buffer_destroy_zero(&remote_storage_root_serialized);
        wickr_buffer_destroy_zero(&node_storage_root_serialized);
        return NULL;
    }
    
    wickr__proto__root_keys__pack(&rootkeys, serialized_object->bytes);
    
    wickr_buffer_destroy_zero(&remote_storage_root_serialized);
    wickr_buffer_destroy_zero(&node_storage_root_serialized);
    
    return serialized_object;
}

wickr_cipher_result_t *wickr_root_keys_export(const wickr_root_keys_t *keys, const wickr_crypto_engine_t *engine, const wickr_cipher_key_t *export_key)
{
    if (!keys || !engine || !export_key) {
        return NULL;
    }
    
    wickr_buffer_t *serialized_keys = wickr_root_keys_serialize(keys);
    
    if (!serialized_keys) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = engine->wickr_crypto_engine_cipher_encrypt(serialized_keys, NULL, export_key, NULL);
    wickr_buffer_destroy_zero(&serialized_keys);
    
    return cipher_result;
}

wickr_storage_keys_t *wickr_root_keys_localize(const wickr_root_keys_t *keys, const wickr_crypto_engine_t *engine, const wickr_dev_info_t *dev_info)
{
    if (!keys || !dev_info) {
        return NULL;
    }
    
    /* Root storage is the same on every device */
    wickr_cipher_key_t *rsr_copy = wickr_cipher_key_copy(keys->remote_storage_root);
    
    if (!rsr_copy) {
        return NULL;
    }
    
    /* Create our local storage key by taking a hash of the node_storage_root with the system_salt as the salt */
    wickr_buffer_t *local_dev_storage_key_material = engine->wickr_crypto_engine_digest(keys->node_storage_root->key_data, dev_info->system_salt, DIGEST_SHA_256);
    
    if (!local_dev_storage_key_material) {
        wickr_cipher_key_destroy(&rsr_copy);
        return NULL;
    }
    
    wickr_cipher_key_t *local_dev_storage_key = wickr_cipher_key_create(keys->node_storage_root->cipher, local_dev_storage_key_material);
    
    if (!local_dev_storage_key) {
        wickr_cipher_key_destroy(&rsr_copy);
        wickr_buffer_destroy_zero(&local_dev_storage_key_material);
        return NULL;
    }
    
    wickr_storage_keys_t *storage_keys = wickr_storage_keys_create(local_dev_storage_key, rsr_copy);
    
    if (!storage_keys) {
        wickr_cipher_key_destroy(&rsr_copy);
        wickr_cipher_key_destroy(&local_dev_storage_key);
    }
    
    return storage_keys;
}

wickr_root_keys_t *wickr_root_keys_copy(const wickr_root_keys_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_ec_key_t *sig_key_copy = wickr_ec_key_copy(source->node_signature_root);
    
    if (!sig_key_copy) {
        return NULL;
    }
    
    wickr_cipher_key_t *nsr_copy = wickr_cipher_key_copy(source->node_storage_root);
    
    if (!nsr_copy) {
        wickr_ec_key_destroy(&sig_key_copy);
        return NULL;
    }
    
    wickr_cipher_key_t *rsr_copy = wickr_cipher_key_copy(source->remote_storage_root);
    
    if (!rsr_copy) {
        wickr_ec_key_destroy(&sig_key_copy);
        wickr_cipher_key_destroy(&nsr_copy);
        return NULL;
    }
    
    wickr_root_keys_t *root_key_copy = wickr_root_keys_create(sig_key_copy, nsr_copy, rsr_copy);
    
    if (!root_key_copy) {
        wickr_ec_key_destroy(&sig_key_copy);
        wickr_cipher_key_destroy(&nsr_copy);
        wickr_cipher_key_destroy(&rsr_copy);
    }
    
    return root_key_copy;
}

void wickr_root_keys_destroy(wickr_root_keys_t **keys)
{
    if (!keys || !*keys) {
        return;
    }
    
    wickr_ec_key_destroy(&(*keys)->node_signature_root);
    wickr_cipher_key_destroy(&(*keys)->node_storage_root);
    wickr_cipher_key_destroy(&(*keys)->remote_storage_root);
    wickr_free(*keys);
    *keys = NULL;
}
