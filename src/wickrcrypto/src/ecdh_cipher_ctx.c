
#include "ecdh_cipher_ctx.h"
#include "memory.h"

wickr_ecdh_cipher_result_t *wickr_ecdh_cipher_result_create(wickr_cipher_result_t *cipher_result, wickr_buffer_t *kem_ctx)
{
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_ecdh_cipher_result_t *ecdh_cipher_result = wickr_alloc_zero(sizeof(wickr_ecdh_cipher_result_t));
    
    if (!ecdh_cipher_result) {
        return NULL;
    }
    
    ecdh_cipher_result->cipher_result = cipher_result;
    ecdh_cipher_result->kem_ctx = kem_ctx;
    
    return ecdh_cipher_result;
}

wickr_ecdh_cipher_result_t *wickr_ecdh_cipher_result_copy(const wickr_ecdh_cipher_result_t *result)
{
    if (!result) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result_copy = wickr_cipher_result_copy(result->cipher_result);
    
    if (!cipher_result_copy) {
        return NULL;
    }
    
    wickr_buffer_t *kem_ctx_copy = wickr_buffer_copy(result->kem_ctx);
    
    if (result->kem_ctx && !kem_ctx_copy) {
        wickr_cipher_result_destroy(&cipher_result_copy);
        return NULL;
    }
    
    wickr_ecdh_cipher_result_t *copy = wickr_ecdh_cipher_result_create(cipher_result_copy, kem_ctx_copy);
    
    if (!copy) {
        wickr_cipher_result_destroy(&cipher_result_copy);
        wickr_buffer_destroy(&kem_ctx_copy);
    }
    
    return copy;
}

void wickr_ecdh_cipher_result_destroy(wickr_ecdh_cipher_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    
    wickr_cipher_result_destroy(&(*result)->cipher_result);
    wickr_buffer_destroy(&(*result)->kem_ctx);
    wickr_free(*result);
    *result = NULL;
}

wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_create_key(wickr_crypto_engine_t engine,
                                                          wickr_ec_key_t *key,
                                                          wickr_cipher_t cipher)
{
    if (!key) {
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *ctx = wickr_alloc_zero(sizeof(wickr_ecdh_cipher_ctx_t));
    
    if (!ctx) {
        return NULL;
    }
    
    ctx->engine = engine;
    ctx->cipher = cipher;
    ctx->local_key = key;
    
    return ctx;
}

wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_create(wickr_crypto_engine_t engine, wickr_ec_curve_t curve, wickr_cipher_t cipher)
{
    wickr_ec_key_t *local_key = engine.wickr_crypto_engine_ec_rand_key(curve);
    
    if (!local_key) {
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *ctx = wickr_ecdh_cipher_ctx_create_key(engine, local_key, cipher);
    
    if (!ctx) {
        wickr_ec_key_destroy(&local_key);
        return NULL;
    }
    
    return ctx;
}

wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_copy(const wickr_ecdh_cipher_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_ec_key_t *local_key_copy = wickr_ec_key_copy(ctx->local_key);
    
    if (!local_key_copy) {
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *copy = wickr_ecdh_cipher_ctx_create_key(ctx->engine, local_key_copy, ctx->cipher);
    
    if (!copy) {
        wickr_ec_key_destroy(&local_key_copy);
        return NULL;
    }
    
    return copy;
}

void wickr_ecdh_cipher_ctx_destroy(wickr_ecdh_cipher_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    wickr_ec_key_destroy(&(*ctx)->local_key);
    wickr_free(*ctx);
    *ctx = NULL;
}

static wickr_cipher_key_t *__wickr_ecdh_cipher_ctx_gen_cipher_key(const wickr_ecdh_cipher_ctx_t *ctx,
                                                                  const wickr_ec_key_t *remote_pub,
                                                                  const wickr_buffer_t *kem_ctx,
                                                                  const wickr_kdf_meta_t *kdf_params,
                                                                  wickr_buffer_t **kem_ctx_out)
{
    if (!ctx || !remote_pub || !kdf_params) {
        return NULL;
    }
    
    /* Only HKDF is supported by this function */
    if (kdf_params->algo.algo_id != KDF_HMAC_SHA2) {
        return NULL;
    }

	wickr_kdf_meta_t kdf_meta = {
		.algo = kdf_params->algo,
		.salt = kdf_params->salt,
		.info = kdf_params->info
	};

	/* Truncate the HKDF output to the desired cipher length if necessary */
	if (kdf_params->algo.output_size != ctx->cipher.key_len) {
		kdf_meta.algo.output_size = ctx->cipher.key_len;
	}
    
    /* Generate the ECDH shared secret */
    wickr_shared_secret_t *shared_secret = ctx->engine.wickr_crypto_engine_gen_shared_secret(ctx->local_key, remote_pub, kem_ctx);
    
    if (!shared_secret) {
        return NULL;
    }
    
    /* Run the ECDH shared secret through HKDF with the provided salt and info from the ECDH params */
    wickr_kdf_result_t *kdf_result = wickr_perform_kdf_meta(&kdf_meta, shared_secret->secret);
    
    if (!kdf_result) {
        wickr_shared_secret_destroy(&shared_secret);
        return NULL;
    }
    
    wickr_buffer_t *key_data = wickr_buffer_copy(kdf_result->hash);
    wickr_kdf_result_destroy(&kdf_result);
    
    if (!key_data) {
        wickr_shared_secret_destroy(&shared_secret);
        return NULL;
    }
    
    /* Create a cipher key of the proper cipher type out the result of the kdf */
    wickr_cipher_key_t *secret_key = wickr_cipher_key_create(ctx->cipher, key_data);
    
    if (!secret_key) {
        wickr_shared_secret_destroy(&shared_secret);
        wickr_buffer_destroy_zero(&key_data);
        return NULL;
    }
    
    if (shared_secret->ctx && kem_ctx_out) {
        *kem_ctx_out = wickr_buffer_copy(shared_secret->ctx);
    }
    
    wickr_shared_secret_destroy(&shared_secret);
    
    return secret_key;
}

wickr_ecdh_cipher_result_t *wickr_ecdh_cipher_ctx_cipher(const wickr_ecdh_cipher_ctx_t *ctx,
                                                         const wickr_buffer_t *plaintext,
                                                         const wickr_ec_key_t *remote_pub,
                                                         const wickr_kdf_meta_t *kdf_params)
{
    if (!ctx || !plaintext || !remote_pub || !kdf_params) {
        return NULL;
    }
    
    /* Create a cipher key by generating a shared secret and running it through a kdf specified in kdf_params */
    wickr_buffer_t *kem_ctx = NULL;
    wickr_cipher_key_t *secret_key = __wickr_ecdh_cipher_ctx_gen_cipher_key(ctx, remote_pub, NULL, kdf_params, &kem_ctx);
    
    if (!secret_key) {
        return NULL;
    }
    
    /* Encrypt the plaintext with the cipher key */
    wickr_cipher_result_t *cipher_result = ctx->engine.wickr_crypto_engine_cipher_encrypt(plaintext, NULL, secret_key, NULL);
    wickr_cipher_key_destroy(&secret_key);
    
    if (!cipher_result) {
        wickr_buffer_destroy(&kem_ctx);
        return NULL;
    }
    
    wickr_ecdh_cipher_result_t *result = wickr_ecdh_cipher_result_create(cipher_result, kem_ctx);
    
    if (!result) {
        wickr_cipher_result_destroy(&cipher_result);
        wickr_buffer_destroy(&kem_ctx);
    }
    
    return result;
}

wickr_buffer_t *wickr_ecdh_cipher_ctx_decipher(const wickr_ecdh_cipher_ctx_t *ctx,
                                               const wickr_ecdh_cipher_result_t *ciphertext,
                                               const wickr_ec_key_t *remote_pub,
                                               const wickr_kdf_meta_t *kdf_params)
{
    if (!ctx || !ciphertext || !remote_pub || !kdf_params) {
        return NULL;
    }
    
    /* Verify that the ciphertext was created by the cipher we expect */
    if (ciphertext->cipher_result->cipher.cipher_id != ctx->cipher.cipher_id) {
        return NULL;
    }
    
    /* Create a cipher key by generating a shared secret and running it through a kdf specified in kdf_params */
    wickr_cipher_key_t *secret_key = __wickr_ecdh_cipher_ctx_gen_cipher_key(ctx, remote_pub, ciphertext->kem_ctx, kdf_params, NULL);
    
    if (!secret_key) {
        return NULL;
    }
    
    /* Decrypt the ciphered data with the secret key */
    wickr_buffer_t *plaintext = ctx->engine.wickr_crypto_engine_cipher_decrypt(ciphertext->cipher_result, NULL, secret_key, false);
    wickr_cipher_key_destroy(&secret_key);
    
    return plaintext;
}
