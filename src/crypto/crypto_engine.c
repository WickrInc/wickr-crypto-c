
#include "crypto_engine.h"
#include "memory.h"
#include "openssl_suite.h"
#include "openssl_file_suite.h"

const wickr_crypto_engine_t wickr_crypto_engine_get_default()
{
    wickr_crypto_engine_t default_engine =
    {
        EC_CURVE_NIST_P521,
        CIPHER_AES256_GCM,
        openssl_crypto_random,
        openssl_cipher_key_random,
        openssl_aes256_encrypt,
        openssl_aes256_decrypt,
        openssl_aes256_file_encrypt,
        openssl_aes256_file_decrypt,
        openssl_sha2,
        openssl_sha2_file,
        openssl_ec_rand_key,
        openssl_ec_key_import,
        openssl_ec_sign,
        openssl_ec_verify,
        openssl_ecdh_gen_key,
        openssl_hmac_create,
        openssl_hmac_verify,
        wickr_perform_kdf,
        wickr_perform_kdf_meta
    };
    
    return default_engine;
}

static wickr_cipher_key_t *__wickr_cipher_key_from_kdf(wickr_kdf_result_t *kdf_result, wickr_cipher_t cipher)
{
    if (!kdf_result) {
        return NULL;
    }
    
    if (kdf_result->hash->length != cipher.key_len) {
        return NULL;
    }
    
    wickr_buffer_t *key_buffer = wickr_buffer_copy(kdf_result->hash);
    
    if (!key_buffer) {
        return NULL;
    }
    
    wickr_cipher_key_t *cipher_key = wickr_cipher_key_create(cipher, key_buffer);
    
    if (!cipher_key) {
        wickr_buffer_destroy_zero(&key_buffer);
    }
    
    return cipher_key;
}

wickr_buffer_t *wickr_crypto_engine_kdf_cipher(const wickr_crypto_engine_t *engine, wickr_kdf_algo_t algo, wickr_cipher_t cipher, const wickr_buffer_t *value, const wickr_buffer_t *passphrase)
{
    if (!engine || !value || !passphrase) {
        return NULL;
    }
    
    /* Don't allow bcrypt, HKDF or unauthenticated ciphers for this operation, not supported */
    if (algo.algo_id != KDF_SCRYPT || !cipher.is_authenticated || algo.output_size != cipher.key_len) {
        return NULL;
    }
    
    wickr_kdf_result_t *kdf_result = engine->wickr_crypto_kdf_gen(algo, passphrase);
    
    if (!kdf_result) {
        return NULL;
    }
    
    wickr_cipher_key_t cipher_key;
    cipher_key.cipher = cipher;
    cipher_key.key_data = kdf_result->hash;
    
    wickr_cipher_result_t *ciphered_data = engine->wickr_crypto_engine_cipher_encrypt(value, NULL, &cipher_key, NULL);
    
    if (!ciphered_data) {
        wickr_kdf_result_destroy(&kdf_result);
        return NULL;
    }
    
    wickr_buffer_t *serialized_cipher_result = wickr_cipher_result_serialize(ciphered_data);
    wickr_cipher_result_destroy(&ciphered_data);
    
    if (!serialized_cipher_result) {
        wickr_kdf_result_destroy(&kdf_result);
        return NULL;
    }
    
    wickr_buffer_t *kdf_meta = wickr_kdf_meta_serialize(kdf_result->meta);
    wickr_kdf_result_destroy(&kdf_result);
    
    if (!kdf_meta) {
        wickr_buffer_destroy(&serialized_cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *final_buffer = wickr_buffer_concat(kdf_meta, serialized_cipher_result);
    wickr_buffer_destroy(&serialized_cipher_result);
    wickr_buffer_destroy(&kdf_meta);
    
    return final_buffer;
}

wickr_buffer_t *wickr_crypto_engine_kdf_decipher(const wickr_crypto_engine_t *engine, const wickr_buffer_t *input_buffer, const wickr_buffer_t *passphrase)
{
    if (!engine || !input_buffer || !passphrase) {
        return NULL;
    }
    
    uint8_t kdf_meta_size = wickr_kdf_meta_size_with_buffer(input_buffer);
    
    if (kdf_meta_size == 0 || kdf_meta_size >= input_buffer->length) {
        return NULL;
    }
    
    wickr_kdf_meta_t *meta = wickr_kdf_meta_create_with_buffer(input_buffer);
    
    if (!meta) {
        return NULL;
    }
    
    wickr_kdf_result_t *kdf_result = engine->wickr_crypto_kdf_meta(meta, passphrase);
    wickr_kdf_meta_destroy(&meta);
    
    if (!kdf_result) {
        return NULL;
    }
    
    wickr_buffer_t cipher_text;
    cipher_text.bytes = input_buffer->bytes + kdf_meta_size;
    cipher_text.length = input_buffer->length - kdf_meta_size;
    
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(&cipher_text);
    
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_cipher_key_t *cipher_key = __wickr_cipher_key_from_kdf(kdf_result, cipher_result->cipher);
    
    wickr_kdf_result_destroy(&kdf_result);
    
    if (!cipher_key) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    /* Attempt decrypt with derived cipher key, only allow authenticated ciphers */
    wickr_buffer_t *decoded_data = engine->wickr_crypto_engine_cipher_decrypt(cipher_result, NULL, cipher_key, true);
    wickr_cipher_result_destroy(&cipher_result);
    wickr_cipher_key_destroy(&cipher_key);
    
    return decoded_data;
}

wickr_digest_t wickr_digest_matching_cipher(wickr_cipher_t cipher)
{
    switch (cipher.cipher_id) {
        case CIPHER_ID_AES256_CTR:
            return DIGEST_SHA_256;
        case CIPHER_ID_AES256_GCM:
            return DIGEST_SHA_256;
    }
}

wickr_digest_t wickr_digest_matching_curve(wickr_ec_curve_t curve)
{
    switch (curve.identifier) {
        case EC_CURVE_ID_NIST_P521:
            return DIGEST_SHA_512;
    }
}

wickr_kdf_algo_t wickr_key_exchange_kdf_matching_cipher(wickr_cipher_t cipher)
{
    wickr_kdf_algo_t algo;
    
    switch (cipher.cipher_id) {
        case CIPHER_ID_AES256_GCM:
        case CIPHER_ID_AES256_CTR:
            algo = KDF_HKDF_SHA512;
            break;
    }
    
    algo.output_size = cipher.key_len;
    
    return algo;
}

/* Use unauthenticated cipher for msg key unwrapping since the output is an authenticated cipher key. 
   This eliminates unnecessary tag bytes for each recipient */

wickr_cipher_t wickr_exchange_cipher_matching_cipher(wickr_cipher_t cipher)
{
    switch (cipher.cipher_id) {
        case CIPHER_ID_AES256_CTR:
            return CIPHER_AES256_CTR;
            break;
        case CIPHER_ID_AES256_GCM:
            return CIPHER_AES256_CTR;
    }
}

