
#include "devinfo.h"
#include "memory.h"

wickr_dev_info_t *wickr_dev_info_create(wickr_buffer_t *dev_salt, wickr_buffer_t *system_salt, wickr_buffer_t *msg_proto_id, wickr_buffer_t *srv_comm_id)
{
    if (!dev_salt || !msg_proto_id || !srv_comm_id) {
        return NULL;
    }
    
    wickr_dev_info_t *new_info = wickr_alloc_zero(sizeof(wickr_dev_info_t));
    
    if (!new_info) {
        return NULL;
    }
    
    new_info->dev_salt = dev_salt;
    new_info->system_salt = system_salt;
    new_info->msg_proto_id = msg_proto_id;
    new_info->srv_comm_id = srv_comm_id;
    
    return new_info;
}

wickr_dev_info_t *wickr_dev_info_create_new(const wickr_crypto_engine_t *crypto, const wickr_buffer_t *system_id)
{
    if (!crypto || !system_id) {
        return NULL;
    }
    
    /* Use SHA 512 as our digest algorithm so we can get enough bytes to create both a msg_proto_id and a srv_comm_id */
    wickr_digest_t id_gen_digest = DIGEST_SHA_512;
    
    /* Generate a salt to match the digest size */
    wickr_buffer_t *new_dev_salt = crypto->wickr_crypto_engine_crypto_random(id_gen_digest.size);
    
    if (!new_dev_salt) {
        return NULL;
    }
    
    wickr_dev_info_t *derived_info = wickr_dev_info_derive(crypto, new_dev_salt, system_id);
    
    if (!derived_info) {
        wickr_buffer_destroy(&new_dev_salt);
    }
    
    return derived_info;
}

wickr_dev_info_t *wickr_dev_info_derive(const wickr_crypto_engine_t *crypto, wickr_buffer_t *dev_salt, const wickr_buffer_t *system_id)
{
    if (!crypto || !dev_salt || !system_id) {
        return NULL;
    }
    
    /* Convert the system_id into a salt by taking its hash, this value remains private to the client */
    wickr_buffer_t *system_salt = crypto->wickr_crypto_engine_digest(system_id, NULL, DIGEST_SHA_256);
    
    if (!system_salt) {
        return NULL;
    }
    
    /* Use SHA 512 as our digest algorithm so we can get enough bytes to create both a msg_proto_id and a srv_comm_id */
    wickr_digest_t id_gen_digest = DIGEST_SHA_512;
    
    /* Generate an hash of system_id and salt value to make a publishable set of device identifiers */
    wickr_buffer_t *dev_id_data = crypto->wickr_crypto_engine_digest(system_id, dev_salt, id_gen_digest);
    
    if (!dev_id_data) {
        wickr_buffer_destroy(&system_salt);
        return NULL;
    }
    
    /* Split the device identifier into the identifiers we need */
    wickr_buffer_t *msg_proto_id = wickr_buffer_copy_section(dev_id_data, 0, id_gen_digest.size / 2);
    
    if (!msg_proto_id) {
        wickr_buffer_destroy(&system_salt);
        wickr_buffer_destroy(&dev_id_data);
        return NULL;
    }
    
    wickr_buffer_t *srv_comm_id = wickr_buffer_copy_section(dev_id_data, id_gen_digest.size / 2, id_gen_digest.size / 2);
    wickr_buffer_destroy(&dev_id_data);
    
    if (!srv_comm_id) {
        wickr_buffer_destroy(&system_salt);
        wickr_buffer_destroy(&msg_proto_id);
        return NULL;
    }
    
    wickr_dev_info_t *dev_info = wickr_dev_info_create(dev_salt, system_salt, msg_proto_id, srv_comm_id);
    
    if (!dev_info) {
        wickr_buffer_destroy(&system_salt);
        wickr_buffer_destroy(&msg_proto_id);
        wickr_buffer_destroy(&srv_comm_id);
    }
    
    return dev_info;
}

wickr_dev_info_t *wickr_dev_info_copy(const wickr_dev_info_t *info)
{
    if (!info) {
        return NULL;
    }
    
    wickr_buffer_t *system_salt_copy = wickr_buffer_copy(info->system_salt);
    
    if (!system_salt_copy) {
        return NULL;
    }
    
    wickr_buffer_t *dev_salt_copy = wickr_buffer_copy(info->dev_salt);
    
    if (!dev_salt_copy) {
        wickr_buffer_destroy_zero(&system_salt_copy);
        return NULL;
    }
    
    wickr_buffer_t *msg_proto_id_copy = wickr_buffer_copy(info->msg_proto_id);
    
    if (!msg_proto_id_copy) {
        wickr_buffer_destroy_zero(&system_salt_copy);
        wickr_buffer_destroy_zero(&dev_salt_copy);
        return NULL;
    }
    
    wickr_buffer_t *srv_comm_id_copy = wickr_buffer_copy(info->srv_comm_id);
    
    if (!srv_comm_id_copy) {
        wickr_buffer_destroy_zero(&system_salt_copy);
        wickr_buffer_destroy_zero(&dev_salt_copy);
        wickr_buffer_destroy_zero(&msg_proto_id_copy);
        return NULL;
    }
    
    wickr_dev_info_t *dev_info_copy = wickr_dev_info_create(dev_salt_copy, system_salt_copy, msg_proto_id_copy, srv_comm_id_copy);
    
    if (!dev_info_copy) {
        wickr_buffer_destroy_zero(&system_salt_copy);
        wickr_buffer_destroy_zero(&dev_salt_copy);
        wickr_buffer_destroy_zero(&msg_proto_id_copy);
        wickr_buffer_destroy_zero(&srv_comm_id_copy);
    }
    
    return dev_info_copy;

}

void wickr_dev_info_destroy(wickr_dev_info_t **info)
{
    if (!info || !*info) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*info)->system_salt);
    wickr_buffer_destroy_zero(&(*info)->dev_salt);
    wickr_buffer_destroy_zero(&(*info)->msg_proto_id);
    wickr_buffer_destroy_zero(&(*info)->srv_comm_id);
    
    wickr_free((*info));
    *info = NULL;
}
