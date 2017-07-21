
#include "ecdsa.h"
#include "memory.h"
#include <string.h>

#define ECDSA_HEADER_SIZE 2

wickr_ecdsa_result_t *wickr_ecdsa_result_create(wickr_ec_curve_t curve, wickr_digest_t digest_mode, wickr_buffer_t *sig_data)
{
    if (!sig_data) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *new_result = wickr_alloc_zero(sizeof(wickr_ecdsa_result_t));
    new_result->curve = curve;
    new_result->digest_mode = digest_mode;
    new_result->sig_data = sig_data;
    
    return new_result;
}

wickr_ecdsa_result_t *wickr_ecdsa_result_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length < ECDSA_HEADER_SIZE) {
        return NULL;
    }
    
    const wickr_ec_curve_t *curve = wickr_ec_curve_find((buffer->bytes[0] & 0xF0) >> 4);
    const wickr_digest_t *digest_mode = wickr_digest_find_with_id(buffer->bytes[0] & 0xF);
    
    if (!curve || !digest_mode) {
        return NULL;
    }
    
    uint8_t padding_size = buffer->bytes[1];
    
    if (buffer->length <= ECDSA_HEADER_SIZE + padding_size) {
        return NULL;
    }
    
    size_t start_loc = ECDSA_HEADER_SIZE + padding_size;
    wickr_buffer_t *key_data = wickr_buffer_copy_section(buffer, start_loc, buffer->length - start_loc);
    
    if (!key_data) {
        return NULL;
    }
    
    return wickr_ecdsa_result_create(*curve, *digest_mode, key_data);
}

wickr_buffer_t *wickr_ecdsa_result_serialize(const wickr_ecdsa_result_t *result)
{
    if (!result || result->curve.signature_size < result->sig_data->length + ECDSA_HEADER_SIZE) {
        return NULL;
    }
    
    uint8_t meta_data = (((uint8_t)result->curve.identifier) << 4) | ((uint8_t)result->digest_mode.digest_id);
    
    wickr_buffer_t meta_buffer;
    meta_buffer.bytes = &meta_data;
    meta_buffer.length = sizeof(uint8_t);
    
    uint8_t pad_count = result->curve.signature_size - result->sig_data->length - ECDSA_HEADER_SIZE;
    
    wickr_buffer_t pad_count_buffer;
    pad_count_buffer.bytes = &pad_count;
    pad_count_buffer.length = sizeof(uint8_t);
    
    wickr_buffer_t *pad_buffer = wickr_buffer_create_empty_zero(pad_count);

    wickr_buffer_t *buffers[] = { &meta_buffer, &pad_count_buffer, pad_buffer, result->sig_data };
    
    wickr_buffer_t *fullbuff = wickr_buffer_concat_multi(buffers, BUFFER_ARRAY_LEN(buffers));
    
    wickr_buffer_destroy(&pad_buffer);
    return fullbuff;
}

wickr_ecdsa_result_t *wickr_ecdsa_result_copy(const wickr_ecdsa_result_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *sig_data_copy = wickr_buffer_copy(source->sig_data);
    
    return wickr_ecdsa_result_create(source->curve, source->digest_mode, sig_data_copy);
}

void wickr_ecdsa_result_destroy(wickr_ecdsa_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    
    wickr_buffer_destroy(&(*result)->sig_data);
    wickr_free(*result);
    *result = NULL;
}
