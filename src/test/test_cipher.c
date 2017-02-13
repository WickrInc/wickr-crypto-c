#include "cspec.h"
#include "cipher.h"
#include "openssl_suite.h"

#include <limits.h>
#include <string.h>

DESCRIBE(cipher_result, "cipher: cipher_result")
{
    
    IT( "wickr_cipher_result_create with cipher_text returns valid cipher_result" )
    {
        wickr_buffer_t *iv = openssl_crypto_random(CIPHER_AES256_GCM.iv_len);
        wickr_buffer_t *auth_tag = openssl_crypto_random(CIPHER_AES256_GCM.auth_tag_len);
        wickr_buffer_t *cipher_text = openssl_crypto_random(100000);
        wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(CIPHER_AES256_GCM, iv, cipher_text, auth_tag);
        SHOULD_NOT_BE_NULL(cipher_result)
        if (cipher_result) {
            SHOULD_NOT_BE_NULL(cipher_result->auth_tag)
            SHOULD_NOT_BE_NULL(cipher_result->cipher_text)
            SHOULD_NOT_BE_NULL(cipher_result->iv)
            
            wickr_cipher_result_t *result_copy = wickr_cipher_result_copy(cipher_result);
            SHOULD_NOT_BE_NULL(result_copy);
            
            if (result_copy) {
                SHOULD_BE_TRUE(wickr_buffer_is_equal(cipher_result->cipher_text, result_copy->cipher_text, NULL));
                SHOULD_BE_TRUE(wickr_buffer_is_equal(cipher_result->auth_tag, result_copy->auth_tag, NULL));
                SHOULD_BE_TRUE(wickr_buffer_is_equal(cipher_result->iv, result_copy->iv, NULL));
                SHOULD_EQUAL(cipher_result->cipher.cipher_id, result_copy->cipher.cipher_id);
                wickr_cipher_result_destroy(&result_copy);
            }
            
            wickr_cipher_result_destroy(&cipher_result);
        }
        
    }
    END_IT

    IT( "wickr_cipher_result_create with NO cipher_text returns valid cipher_result" )
    {
        wickr_buffer_t *iv = openssl_crypto_random(CIPHER_AES256_GCM.iv_len);
        wickr_buffer_t *auth_tag = openssl_crypto_random(CIPHER_AES256_GCM.auth_tag_len);
        wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(CIPHER_AES256_GCM, iv, NULL, auth_tag);
        SHOULD_NOT_BE_NULL(cipher_result)
        if (cipher_result) {
            SHOULD_NOT_BE_NULL(cipher_result->auth_tag)
            SHOULD_BE_NULL(cipher_result->cipher_text)
            SHOULD_NOT_BE_NULL(cipher_result->iv)
            wickr_cipher_result_destroy(&cipher_result);
        }
    }
    END_IT

    IT( "wickr_cipher_result_serialize with cipher_textv returns valid serialzed value" )
    {
        wickr_buffer_t *iv = openssl_crypto_random(CIPHER_AES256_GCM.iv_len);
        wickr_buffer_t *auth_tag = openssl_crypto_random(CIPHER_AES256_GCM.auth_tag_len);
        wickr_buffer_t *cipher_text = openssl_crypto_random(100000);
        wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(CIPHER_AES256_GCM, iv, cipher_text, auth_tag);
        wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
        size_t length = sizeof(uint8_t) + iv->length + auth_tag->length + cipher_text->length;
        SHOULD_NOT_BE_NULL(serialized)
        if (serialized) {
            SHOULD_NOT_BE_NULL(serialized->bytes)
            SHOULD_BE_TRUE( serialized->length == length )
            wickr_buffer_destroy(&serialized);
        }
        wickr_cipher_result_destroy(&cipher_result);
    }
    END_IT
    
    IT( "wickr_cipher_result_serialize with cipher_text returns same value" )
    {
        wickr_buffer_t *iv = openssl_crypto_random(CIPHER_AES256_GCM.iv_len);
        wickr_buffer_t *auth_tag = openssl_crypto_random(CIPHER_AES256_GCM.auth_tag_len);
        wickr_buffer_t *cipher_text = openssl_crypto_random(100000);
        wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(CIPHER_AES256_GCM, iv, cipher_text, auth_tag);
        wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
        
        wickr_cipher_result_t *cipher_result_from_serialized = wickr_cipher_result_from_buffer(serialized);
        
        SHOULD_NOT_BE_NULL(cipher_result_from_serialized)
        if (cipher_result_from_serialized && cipher_text) {
            SHOULD_NOT_BE_NULL(cipher_result_from_serialized->auth_tag)
            SHOULD_NOT_BE_NULL(cipher_result_from_serialized->cipher_text)
            SHOULD_NOT_BE_NULL(cipher_result_from_serialized->iv)
            if (cipher_result_from_serialized->cipher_text) {
                SHOULD_BE_TRUE( cipher_result_from_serialized->cipher_text->length == cipher_text->length )
        
                bool equal = false;
                if (cipher_result_from_serialized->cipher_text->length == cipher_text->length) {
                    unsigned int i;
                    for (i=0; i<cipher_result_from_serialized->cipher_text->length; i++) {
                        if (cipher_result_from_serialized->cipher_text->bytes[i] != cipher_text->bytes[i])
                            break;
                    }
                    if (i == cipher_result_from_serialized->cipher_text->length)
                        equal = true;
                }
                SHOULD_BE_TRUE( equal )
            }
            wickr_cipher_result_destroy(&cipher_result_from_serialized);
        }

        wickr_buffer_destroy(&serialized);
        wickr_cipher_result_destroy(&cipher_result);
    }
    END_IT

}
END_DESCRIBE
