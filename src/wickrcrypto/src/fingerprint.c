
#include "fingerprint.h"
#include "memory.h"
#include "util.h"
#include "b32.h"

static wickr_fingerprint_t *__wickr_fingerprint_sha512_create(wickr_crypto_engine_t engine,
                                                              wickr_buffer_t *input_data)
{
    if (!input_data) {
        return NULL;
    }
    
    wickr_buffer_t *fingerprint_data = engine.wickr_crypto_engine_digest(input_data, NULL, DIGEST_SHA_512);
    
    if (!fingerprint_data) {
        return NULL;
    }
    
    wickr_fingerprint_t *fingerprint = wickr_fingerprint_create(WICKR_FINGERPRINT_TYPE_SHA512, fingerprint_data);
    
    if (!fingerprint) {
        wickr_buffer_destroy(&fingerprint_data);
    }
    
    return fingerprint;
}

static wickr_fingerprint_t *__wickr_fingerprint_sha512_encode(wickr_crypto_engine_t engine,
                                                              const wickr_buffer_t *pub_key_data,
                                                              const wickr_buffer_t *identifier)
{
    if (!pub_key_data || !identifier) {
        return NULL;
    }
    
    wickr_buffer_t *concat_buffer = wickr_buffer_concat(identifier, pub_key_data);
    
    wickr_fingerprint_t *fingerprint = __wickr_fingerprint_sha512_create(engine, concat_buffer);
    wickr_buffer_destroy(&concat_buffer);
    
    return fingerprint;
}

static wickr_fingerprint_t *__wickr_fingerprint_sha512_combine(wickr_crypto_engine_t engine,
                                                               const wickr_fingerprint_t *f1,
                                                               const wickr_fingerprint_t *f2)
{
    if (!f1 || !f2) {
        return NULL;
    }
    
    if (f1->data->length != f2->data->length || f1->type != f2->type) {
        return NULL;
    }
    
    wickr_buffer_t *concat_buffer = NULL;
    
    /* Order the input fingerprints in a consistent way so that outputs are consistent
       regardless of input order */
    for (unsigned i = 0; i < f1->data->length; i++) {
        
        if (f1->data->bytes[i] == f2->data->bytes[i]) {
            continue;
        }
        
        if (f1->data->bytes[i] > f2->data->bytes[i]) {
            concat_buffer = wickr_buffer_concat(f1->data, f2->data);
            break;
        }
        else {
            concat_buffer = wickr_buffer_concat(f2->data, f1->data);
            break;
        }
        
    }
    
    if (!concat_buffer) {
        return NULL;
    }
    
    wickr_fingerprint_t *fingerprint = __wickr_fingerprint_sha512_create(engine, concat_buffer);
    wickr_buffer_destroy(&concat_buffer);
    
    return fingerprint;
}

wickr_fingerprint_t *wickr_fingerprint_gen(wickr_crypto_engine_t engine,
                                           const wickr_ec_key_t *key,
                                           const wickr_buffer_t *identifier,
                                           wickr_fingerprint_type type)
{
    if (!key || !identifier || type != WICKR_FINGERPRINT_TYPE_SHA512) {
        return NULL;
    }
    
    wickr_buffer_t *fixed_pub_data = wickr_ec_key_get_pubdata_fixed_len(key);
    
    if (!fixed_pub_data) {
        return NULL;
    }
    
    wickr_fingerprint_t *encoded_fingerprint = __wickr_fingerprint_sha512_encode(engine, fixed_pub_data, identifier);
    wickr_buffer_destroy(&fixed_pub_data);
    
    return encoded_fingerprint;
}

wickr_fingerprint_t *wickr_fingerprint_gen_bilateral(wickr_crypto_engine_t engine,
                                                     const wickr_fingerprint_t *local,
                                                     const wickr_fingerprint_t *remote,
                                                     wickr_fingerprint_type type)
{
    switch (type) {
        case WICKR_FINGERPRINT_TYPE_SHA512:
            return __wickr_fingerprint_sha512_combine(engine, local, remote);
        default:
            return NULL;
    }
}

wickr_fingerprint_t *wickr_fingerprint_create(wickr_fingerprint_type type, wickr_buffer_t *data)
{
    if (!data) {
        return NULL;
    }
    
    wickr_fingerprint_t *fingerprint = wickr_alloc_zero(sizeof(wickr_fingerprint_t));
    
    if (!fingerprint) {
        return NULL;
    }
    
    fingerprint->data = data;
    fingerprint->type = type;
    
    return fingerprint;
}

wickr_fingerprint_t *wickr_fingerprint_copy(const wickr_fingerprint_t *fingerprint)
{
    if (!fingerprint) {
        return NULL;
    }
    
    wickr_buffer_t *data_copy = wickr_buffer_copy(fingerprint->data);
    
    if (!data_copy) {
        return NULL;
    }
    
    wickr_fingerprint_t *copy = wickr_fingerprint_create(fingerprint->type, data_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&data_copy);
    }
    
    return copy;
}

void wickr_fingerprint_destroy(wickr_fingerprint_t **fingerprint)
{
    if (!fingerprint || !*fingerprint) {
        return;
    }
    
    wickr_buffer_destroy(&(*fingerprint)->data);
    wickr_free(*fingerprint);
    *fingerprint = NULL;
}

typedef wickr_buffer_t *(*wickr_fingerprint_encode_func)(const wickr_buffer_t *);

static wickr_buffer_t *__wickr_fingerprint_encode_for_output_mode(const wickr_fingerprint_t *fingerprint,
                                                                  wickr_fingerprint_output output_mode,
                                                                  wickr_fingerprint_encode_func enc_func)
{
    if (!fingerprint) {
        return NULL;
    }
    
    wickr_buffer_t *encoded_fingerprint_data = enc_func(fingerprint->data);
    
    if (output_mode == FINGERPRINT_OUTPUT_SHORT) {
        size_t short_length = encoded_fingerprint_data->length / 2;
        
        /* Replace the byte at index short_length with a null byte to make sure string encoding is proper */
        encoded_fingerprint_data->bytes[short_length] = '\0';
        encoded_fingerprint_data->length = short_length;
    }
        
    return encoded_fingerprint_data;
    
}

wickr_buffer_t *wickr_fingerprint_get_b32(const wickr_fingerprint_t *fingerprint, wickr_fingerprint_output output_mode)
{
    return __wickr_fingerprint_encode_for_output_mode(fingerprint, output_mode, base32_encode);
}

wickr_buffer_t *wickr_fingerprint_get_hex(const wickr_fingerprint_t *fingerprint, wickr_fingerprint_output output_mode)
{
    return __wickr_fingerprint_encode_for_output_mode(fingerprint, output_mode, getHexStringFromData);
}
