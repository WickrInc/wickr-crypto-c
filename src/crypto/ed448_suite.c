// Include
#include <decaf/ed448.h>
#include <decaf/shake.h>


#include "ed448_suite.h"
#include <stdio.h>

#define hash_ctx_t   decaf_shake256_ctx_t
#define hash_init    decaf_shake256_init
#define hash_update  decaf_shake256_update
#define hash_final   decaf_shake256_final
#define hash_destroy decaf_shake256_destroy
#define hash_hash    decaf_shake256_hash

wickr_buffer_t *ed448_sig_derive_public_key(const wickr_buffer_t *private_key_data)
{
    if (!private_key_data || private_key_data->length != EDDSA_448_PRIVATE_KEY_LENGTH)
        return NULL;
    
    wickr_buffer_t *public_key_data = wickr_buffer_create_empty_zero(EDDSA_448_PUBLIC_KEY_LENGTH);

    if (!public_key_data)
        return NULL;
    
    decaf_ed448_derive_public_key(public_key_data->bytes, private_key_data->bytes);
    // This function does not allow for failure

    return public_key_data;    
}

wickr_ecdsa_result_t *ed448_sig_sign(const wickr_ec_key_t *ec_signing_key,
                               const wickr_buffer_t *data_to_sign,
                               wickr_digest_t digest_mode)
{
    if (!ec_signing_key)
        return NULL;

    if (ec_signing_key->curve.identifier != EC_CURVE_ID_ED448_GOLDILOCKS)
        return NULL;

    if (!data_to_sign)
        return NULL;

    if (digest_mode.digest_id != wickr_digest_matching_curve(ec_signing_key->curve).digest_id)
        return NULL;

    const wickr_buffer_t *private_data = ec_signing_key->pri_data;
    const wickr_buffer_t *public_data = ec_signing_key->pub_data;

    if (!private_data || !public_data)
        return NULL;

    if (private_data->length != EDDSA_448_PRIVATE_KEY_LENGTH ||
        public_data->length != EDDSA_448_PUBLIC_KEY_LENGTH)
        return NULL;

    decaf_error_t success;
    hash_ctx_t hash;
    hash_init(hash);
    success = hash_update(hash,data_to_sign->bytes, data_to_sign->length);

    if (success == DECAF_FAILURE) {
        hash_destroy(hash);
        return NULL;
    }

    wickr_buffer_t *signature = wickr_buffer_create_empty_zero(EDDSA_448_SIGNATURE_LENGTH);
    
    if (!signature)
        return NULL;

    uint8_t prehashed = 0;
    uint8_t *context = NULL;
    uint8_t context_length = 0;

    decaf_ed448_sign_prehash(signature->bytes, private_data->bytes, public_data->bytes, hash,
                             context, context_length);
    // Library function has no failure case
    
    wickr_ecdsa_result_t *result = wickr_ecdsa_result_create(ec_signing_key->curve, digest_mode, signature);

    if (!result) {
        wickr_buffer_destroy(&signature);
        return NULL;
    }
    return result;
}

bool ed448_sig_verify(const wickr_ecdsa_result_t *signature,
                      const wickr_ec_key_t *ec_public_key,
                      const wickr_buffer_t *data_to_verify)
{
    if (!signature || !ec_public_key || !data_to_verify)
        return false;

    if (signature->curve.identifier != EC_CURVE_ID_ED448_GOLDILOCKS ||
        ec_public_key->curve.identifier != EC_CURVE_ID_ED448_GOLDILOCKS)
        return false;

    const wickr_buffer_t *raw_signature = signature->sig_data;
    if (!raw_signature || raw_signature->length != EDDSA_448_SIGNATURE_LENGTH)
        return false;
    
    wickr_buffer_t *public_data = ec_public_key->pub_data;

    if (!public_data || public_data->length != EDDSA_448_PUBLIC_KEY_LENGTH)
        return false;
    
    decaf_error_t success;
    hash_ctx_t hash;
    hash_init(hash);

    success = hash_update(hash, data_to_verify->bytes, data_to_verify->length);

    if (success == DECAF_FAILURE) {
        hash_destroy(hash);
        return NULL;
    }

    uint8_t *context = NULL;
    uint8_t context_length = 0;

    return (decaf_ed448_verify_prehash(raw_signature->bytes, public_data->bytes, hash,
            context, context_length) == DECAF_SUCCESS);

}

wickr_buffer_t *ed448_dh_derive_public_key(const wickr_buffer_t *private_key_data)
{
    if (!private_key_data || private_key_data->length != DH_448_PRIVATE_KEY_LENGTH)
        return NULL;

    wickr_buffer_t *public_key_data = wickr_buffer_create_empty_zero(DH_448_PUBLIC_KEY_LENGTH);

    if (!public_key_data)
        return NULL;

    decaf_x448_derive_public_key(public_key_data->bytes, private_key_data->bytes);
    // This function does not allow for failure

    return public_key_data;  
}

wickr_buffer_t *ed448_dh_shared_secret(const wickr_ecdh_params_t *params)
{
    if (!params)
        return NULL;
    
    const wickr_ec_key_t *local_key_pair = params->local_key;
    const wickr_ec_key_t *peer_public_key = params->peer_key;

    if (!local_key_pair || !peer_public_key)
        return NULL;

    if (local_key_pair->curve.identifier != EC_CURVE_ID_ED448_GOLDILOCKS ||
        peer_public_key->curve.identifier != EC_CURVE_ID_ED448_GOLDILOCKS)
        return NULL;
        
    const wickr_buffer_t *local_private_key_data = local_key_pair->pri_data;
    const wickr_buffer_t *peer_public_key_data = peer_public_key->pub_data;

    if (!local_private_key_data || !peer_public_key_data)
        return NULL;

    if (local_private_key_data->length != DH_448_PRIVATE_KEY_LENGTH ||
        peer_public_key_data->length != DH_448_PUBLIC_KEY_LENGTH)
        return NULL;

    wickr_buffer_t *shared_secret = wickr_buffer_create_empty_zero(DH_448_SHARED_SECRET_LENGTH);
    if (!shared_secret)
        return NULL;

    /* Compute the shared secret */
    decaf_error_t result = decaf_x448(shared_secret->bytes, peer_public_key_data->bytes,
                                      local_private_key_data->bytes);
    
    if (result == DECAF_FAILURE) {
        wickr_buffer_destroy(&shared_secret);
        return NULL;
    }

    /* Run the ECDH shared secret through HKDF with the provided salt and info from the ECDH params */
    wickr_kdf_result_t *kdf_result = wickr_perform_kdf_meta(params->kdf_info, shared_secret);

    if (!kdf_result) {
        wickr_buffer_destroy(&shared_secret);
        return NULL;
    }

    wickr_buffer_t *final_buffer = wickr_buffer_copy(kdf_result->hash);
    wickr_kdf_result_destroy(&kdf_result);
    wickr_buffer_destroy(&shared_secret);

    return final_buffer;
}

wickr_buffer_t *ed448_shake256_raw(const wickr_buffer_t *data, uint16_t output_length)
{
    if (!data)
        return NULL;
    
    decaf_error_t success;
    hash_ctx_t hash;
    hash_init(hash);

    success = hash_update(hash,data->bytes, data->length);
    wickr_buffer_t *result = wickr_buffer_create_empty_zero(output_length);

    if (!result || success == DECAF_FAILURE) {
        hash_destroy(hash);
        return NULL;
    }

    hash_final(hash,result->bytes,result->length);
    if (!result) {
        hash_destroy(hash);
        wickr_buffer_destroy(&result);
        return NULL;
    }

    hash_destroy(hash);
    return result;
}

wickr_buffer_t *__ed448_shake256_concat(const wickr_buffer_t **buffer_array, uint16_t num_buffers,
    uint16_t output_length)
{
    if (!buffer_array)
        return NULL;

    hash_ctx_t hash;
    hash_init(hash);
    decaf_error_t success;

    for (int i = 0; i < num_buffers; i++) {
        if(buffer_array[i]) {
            success = hash_update(hash,buffer_array[i]->bytes,buffer_array[i]->length);
            if (success == DECAF_FAILURE) {
                hash_destroy(hash);
                return NULL;
            }
        }
    }

    wickr_buffer_t *result = wickr_buffer_create_empty_zero(output_length);

    if (!result) {
        hash_destroy(hash);
        return NULL;
    }

    hash_final(hash,result->bytes,result->length);
    hash_destroy(hash);

    return result;
}

wickr_buffer_t *ed448_shake256(const wickr_buffer_t *data, const wickr_buffer_t *salt,
                               const wickr_buffer_t *info, uint16_t output_length)
{
    if (!data)
        return NULL;

    /*TODO(All) Is this good order?*/
    const wickr_buffer_t *buffer_array[3] = {salt, info, data};
    return __ed448_shake256_concat(buffer_array, 3, output_length);
    
}