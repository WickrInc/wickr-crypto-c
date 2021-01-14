
#include "ec_kyber_hybrid.h"

static bool __wickr_ec_key_hybrid_get_hybrid_id(wickr_ec_curve_id curve_id, wickr_kyber_mode_id_t kyber_mode, uint8_t *out)
{
    if (curve_id != EC_CURVE_ID_NIST_P521 || kyber_mode != KYBER_MODE_ID_1024) {
        return false;
    }
    *out = (uint8_t)EC_CURVE_ID_P521_KYBER1024_HYBRID;
    return true;
}

wickr_ec_key_t *wickr_ec_key_hybrid_create_with_components(wickr_ec_key_t *ec_key,
                                                           wickr_kyber_keypair_t *kyber_key)
{
    if (!ec_key || !kyber_key) {
        return NULL;
    }
    
    if (!ec_key->pri_data) {
        return NULL;
    }
    
    uint8_t hybrid_id;
    
    if (!__wickr_ec_key_hybrid_get_hybrid_id(ec_key->curve.identifier, kyber_key->mode.identifier, &hybrid_id)) {
        return NULL;
    }
    
    wickr_buffer_t id_buffer = {
        .length = sizeof(uint8_t),
        .bytes = (uint8_t *)&hybrid_id
    };
    
    wickr_buffer_t *kyber_pub_key_buffer = wickr_kyber_pub_key_serialize(kyber_key->public_key);
    
    if (!kyber_pub_key_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *pub_buffers[] = { &id_buffer, kyber_pub_key_buffer, ec_key->pub_data };
    wickr_buffer_t *pub_buffer = wickr_buffer_concat_multi(pub_buffers, BUFFER_ARRAY_LEN(pub_buffers));
    
    wickr_buffer_destroy(&kyber_pub_key_buffer);
    
    if (!pub_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *kyber_secret_key_buffer = wickr_kyber_secret_key_serialize(kyber_key->secret_key);
    
    if (!kyber_secret_key_buffer) {
        wickr_buffer_destroy(&pub_buffer);
        return NULL;
    }
    
    wickr_buffer_t *secret_buffers[] = { &id_buffer, kyber_secret_key_buffer, ec_key->pri_data };
    wickr_buffer_t *pri_buffer = wickr_buffer_concat_multi(secret_buffers, BUFFER_ARRAY_LEN(secret_buffers));
    
    wickr_buffer_destroy(&kyber_secret_key_buffer);
    
    if (!pri_buffer) {
        wickr_buffer_destroy(&pub_buffer);
        return NULL;
    }
    
    wickr_ec_key_t *final_key = wickr_ec_key_create(EC_CURVE_P521_KYBER_HYBRID, pub_buffer, pri_buffer);
    
    if (!final_key) {
        wickr_buffer_destroy(&pub_buffer);
        wickr_buffer_destroy(&pri_buffer);
    }
    
    return final_key;
}

static const wickr_kyber_mode_t *__wickr_buffer_get_kyber_mode(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    if (buffer->length <= HYBRID_KEY_HEADER_SIZE) {
        return NULL;
    }
    
    return wickr_kyber_mode_find(buffer->bytes[sizeof(uint8_t)]);
}

wickr_ec_key_t *wickr_ec_key_hybrid_get_ec_keypair(const wickr_ec_key_t *hbrd_key, wickr_ec_key_import_func import_func)
{
    if (!hbrd_key || hbrd_key->curve.identifier != EC_CURVE_ID_P521_KYBER1024_HYBRID) {
        return NULL;
    }
    
    bool is_private = hbrd_key->pri_data != NULL;
    wickr_buffer_t *key_buffer = is_private ? hbrd_key->pri_data : hbrd_key->pub_data;
    
    const wickr_kyber_mode_t *mode = __wickr_buffer_get_kyber_mode(key_buffer);
    
    if (!mode) {
        return NULL;
    }
    
    size_t kyber_key_len = is_private ? mode->secret_key_len : mode->public_key_len;
    
    if (key_buffer->length <= HYBRID_KEY_HEADER_SIZE + kyber_key_len) {
        return NULL;
    }
    
    size_t ec_key_len = key_buffer->length - HYBRID_KEY_HEADER_SIZE - kyber_key_len;
    
    
    wickr_buffer_t buffer = {
        .bytes = &key_buffer->bytes[HYBRID_KEY_HEADER_SIZE + kyber_key_len],
        .length = ec_key_len
    };
    
    wickr_ec_key_t *ec_key = import_func(&buffer, is_private);
    
    /* If we ever have more than one hybrid type this will need to be adjusted */
    if (ec_key->curve.identifier != EC_CURVE_ID_NIST_P521) {
        wickr_ec_key_destroy(&ec_key);
        return NULL;
    }
    
    return ec_key;
}

static wickr_kyber_pub_key_t *__wickr_ec_key_hybrid_buffer_get_kyber_pub(const wickr_buffer_t *key_buffer, const wickr_kyber_mode_t *expected_mode)
{
    if (!key_buffer || key_buffer->length <= HYBRID_IDENTIFIER_SIZE) {
        return NULL;
    }
    
    wickr_buffer_t without_hybrid_identifier = {
        .bytes = &key_buffer->bytes[HYBRID_IDENTIFIER_SIZE],
        .length = key_buffer->length - HYBRID_IDENTIFIER_SIZE
    };
    
    wickr_kyber_pub_key_t *pub_key = wickr_kyber_pub_key_create_from_buffer(&without_hybrid_identifier);
    
    if (!pub_key) {
        return NULL;
    }
    
    if (pub_key->mode.identifier != expected_mode->identifier) {
        wickr_kyber_pub_key_destroy(&pub_key);
        return NULL;
    }
    
    return pub_key;
}

static wickr_kyber_secret_key_t *__wickr_ec_key_hybrid_buffer_get_kyber_pri(const wickr_buffer_t *key_buffer, const wickr_kyber_mode_t *expected_mode)
{
    if (!key_buffer || key_buffer->length <= HYBRID_IDENTIFIER_SIZE) {
        return NULL;
    }
    
    wickr_buffer_t without_hybrid_identifier = {
        .bytes = &key_buffer->bytes[HYBRID_IDENTIFIER_SIZE],
        .length = key_buffer->length - HYBRID_IDENTIFIER_SIZE
    };
    
    wickr_kyber_secret_key_t *secret_key = wickr_kyber_secret_key_create_from_buffer(&without_hybrid_identifier);
    
    if (!secret_key) {
        return NULL;
    }
    
    if (secret_key->mode.identifier != expected_mode->identifier) {
        wickr_kyber_secret_key_destroy(&secret_key);
        return NULL;
    }
    
    return secret_key;
}

wickr_kyber_pub_key_t *wickr_ec_key_hybrid_get_kyber_pub(const wickr_ec_key_t *hbrd_key)
{
    if (!hbrd_key || !hbrd_key->pub_data || hbrd_key->curve.identifier != EC_CURVE_ID_P521_KYBER1024_HYBRID) {
        return NULL;
    }
    
    /* If we ever have more than one type of hybrid type, this needs to be adjusted */
    const wickr_kyber_mode_t *expected_mode = &KYBER_MODE_1024;
    
    return __wickr_ec_key_hybrid_buffer_get_kyber_pub(hbrd_key->pub_data, expected_mode);
}

wickr_kyber_secret_key_t *wickr_ec_key_hybrid_get_kyber_pri(const wickr_ec_key_t *hbrd_key)
{
    if (!hbrd_key || !hbrd_key->pri_data || hbrd_key->curve.identifier != EC_CURVE_ID_P521_KYBER1024_HYBRID) {
        return NULL;
    }
    
    /* If we ever have more than one type of hybrid type, this needs to be adjusted */
    const wickr_kyber_mode_t *expected_mode = &KYBER_MODE_1024;
    
    return __wickr_ec_key_hybrid_buffer_get_kyber_pri(hbrd_key->pri_data, expected_mode);
}
