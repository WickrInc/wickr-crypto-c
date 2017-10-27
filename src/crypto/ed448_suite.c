// Include

#include "ed448_suite.h"
#include <stdio.h>


wickr_buffer_t *ed448_sig_gen_key(const wickr_buffer_t *private_key_data)
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

wickr_buffer_t *ed448_sig_sign(const wickr_ec_key_t *ec_signing_key,
                           const wickr_buffer_t *data_to_sign)
{
    if (!ec_signing_key)
        return NULL;

    if (!data_to_sign)
        return NULL;

    wickr_buffer_t *private_data = ec_signing_key->pri_data;
    wickr_buffer_t *public_data = ec_signing_key->pub_data;

    if (!private_data || !public_data)
        return NULL;

    if (private_data->length != EDDSA_448_PRIVATE_KEY_LENGTH ||
        public_data->length != EDDSA_448_PUBLIC_KEY_LENGTH)
        return NULL;

    wickr_buffer_t *signature = wickr_buffer_create_empty_zero(EDDSA_448_SIGNATURE_LENGTH);
    uint8_t prehashed = 0;
    uint8_t * context = NULL;
    uint8_t context_length = 0;

    decaf_ed448_sign(signature->bytes, private_data->bytes, public_data->bytes, data_to_sign->bytes,
                     data_to_sign->length, prehashed, context, context_length);
    // Library function has no failure case

    return signature;

}

bool ed448_sig_verify(const wickr_buffer_t *signature,
                      const wickr_ec_key_t *ec_public_key,
                      const wickr_buffer_t *data_to_verify)
{
    if (!signature || !ec_public_key || !data_to_verify)
        return false;

    if (signature->length != EDDSA_448_SIGNATURE_LENGTH)
        return false;
    
    wickr_buffer_t *public_data = ec_public_key->pub_data;

    if (!public_data || public_data->length != EDDSA_448_PUBLIC_KEY_LENGTH)
        return false;

    uint8_t prehashed = 0;
    uint8_t * context = NULL;
    uint8_t context_length = 0;

    return (decaf_ed448_verify(signature->bytes, public_data->bytes, data_to_verify->bytes,
            data_to_verify->length, prehashed, context, context_length) == DECAF_SUCCESS);

}