
#include "encoder_result.h"
#include "memory.h"

wickr_encoder_result_t *wickr_encoder_result_create(wickr_cipher_key_t *packet_key, wickr_packet_t *packet)
{
    if (!packet_key || !packet) {
        return NULL;
    }
    
    wickr_encoder_result_t *new_encode = wickr_alloc_zero(sizeof(wickr_encoder_result_t));
    
    if (!new_encode) {
        return NULL;
    }
    
    new_encode->packet_key = packet_key;
    new_encode->packet = packet;
    
    return new_encode;
}

wickr_encoder_result_t *wickr_encoder_result_copy(const wickr_encoder_result_t *result)
{
    if (!result) {
        return NULL;
    }
    
    wickr_cipher_key_t *packet_key_copy = wickr_cipher_key_copy(result->packet_key);
    
    if (!packet_key_copy) {
        return NULL;
    }
    
    wickr_packet_t *packet_copy = wickr_packet_copy(result->packet);
    
    if (!packet_copy) {
        wickr_cipher_key_destroy(&packet_key_copy);
        return NULL;
    }
    
    wickr_encoder_result_t *encoder_copy = wickr_encoder_result_create(packet_key_copy, packet_copy);
    
    if (!encoder_copy) {
        wickr_cipher_key_destroy(&packet_key_copy);
        wickr_packet_destroy(&packet_copy);
    }
    
    return encoder_copy;
}

void wickr_encoder_result_destroy(wickr_encoder_result_t **encode)
{
    if (!encode || !*encode) {
        return;
    }
    
    wickr_cipher_key_destroy(&(*encode)->packet_key);
    wickr_packet_destroy(&(*encode)->packet);
    wickr_free(*encode);
    *encode = NULL;
}
