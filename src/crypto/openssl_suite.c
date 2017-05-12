
#include "openssl_suite.h"
#include "memory.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <string.h>
#include <limits.h>

#if OPENSSL_VERSION_NUMBER >= 0x010100000
#include <openssl/ossl_typ.h>
#include <openssl/kdf.h>
#endif

static const EVP_MD *__openssl_get_digest_mode(wickr_digest_t mode)
{
    switch (mode.digest_id) {
        case DIGEST_ID_SHA256:
            return EVP_sha256();
        case DIGEST_ID_SHA384:
            return EVP_sha384();
        case DIGEST_ID_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

static const EVP_CIPHER *__openssl_get_cipher_mode(wickr_cipher_t mode)
{
    switch (mode.cipher_id) {
        case CIPHER_ID_AES256_GCM:
            return EVP_aes_256_gcm();
        case CIPHER_ID_AES256_CTR:
            return EVP_aes_256_ctr();
        default:
            return NULL;
    }
}

#define NID_UNSUPPORTED 0

static int __openssl_get_ec_nid(wickr_ec_curve_t curve)
{
    switch (curve.identifier) {
        case EC_CURVE_ID_NIST_P521:
            return NID_secp521r1;
        default:
            return NID_undef;
    }
}

typedef EC_KEY *(*wickr_key_deserialization_func)(EC_KEY**, const uint8_t **, long);

static EVP_PKEY *__openssl_evp_ec_key_from_buffer(EC_KEY *existing,
                                                  const wickr_buffer_t *buffer,
                                                  wickr_key_deserialization_func key_deserialization_func)
{
    if (!buffer || buffer->length > LONG_MAX) {
        return NULL;
    }
    
    /* Convert the passed in buffer to an EC_KEY data structure */
    const uint8_t *result_holder = buffer->bytes;
    
    EC_KEY **existing_key = existing ? &existing : NULL;
    EC_KEY *key = key_deserialization_func(existing_key, &result_holder, (long)buffer->length);
    
    if (!key) {
        return NULL;
    }
    
    /* Allocate a new EVP key */
    EVP_PKEY *evp_signing_key = EVP_PKEY_new();
    
    if (!evp_signing_key) {
        return NULL;
    }
    
    /* Convert the EC_KEY structure to an EVP_PKEY */
    if (1 != EVP_PKEY_assign_EC_KEY(evp_signing_key, key)) {
        EVP_PKEY_free(evp_signing_key);
        return NULL;
    }
    
    return evp_signing_key;
}

static wickr_buffer_t *__openssl_ec_pub_key_to_buffer(wickr_ec_curve_t curve, EC_KEY *key)
{
    size_t key_size = i2o_ECPublicKey(key, NULL);
    wickr_buffer_t *pub_key_data = wickr_buffer_create_empty_zero(sizeof(uint8_t) + key_size);
    
    if (!pub_key_data) {
        return NULL;
    }
    
    uint8_t curve_id = curve.identifier;
    
    /* Prepend the curve to the beginning because OpenSSL will serialize just the octects of the key */
    if (!wickr_buffer_modify_section(pub_key_data, &curve_id, 0, sizeof(uint8_t))) {
        wickr_buffer_destroy(&pub_key_data);
        return NULL;
    }
    
    uint8_t* bytes = pub_key_data->bytes + sizeof(uint8_t);
    if (!i2o_ECPublicKey(key, &bytes)) {
        wickr_buffer_destroy(&pub_key_data);
        return NULL;
    }
    
    return pub_key_data;
}

static wickr_buffer_t *__openssl_ec_pri_key_to_buffer(EC_KEY *key)
{
    size_t key_size = i2d_ECPrivateKey(key, NULL);
    wickr_buffer_t *pri_key_data = wickr_buffer_create_empty_zero(key_size);
    
    if (!pri_key_data) {
        return NULL;
    }
    
    uint8_t *bytes = pri_key_data->bytes;
    if (!i2d_ECPrivateKey(key, &bytes)) {
        wickr_buffer_destroy(&pri_key_data);
        return NULL;
    }
    
    return pri_key_data;
}

static EVP_PKEY *__openssl_evp_private_key_from_buffer(const wickr_buffer_t *buffer)
{
    return __openssl_evp_ec_key_from_buffer(NULL, buffer, d2i_ECPrivateKey);
}

static EVP_PKEY *__openssl_evp_public_key_from_buffer(const wickr_buffer_t *buffer)
{
    if (buffer->length <= sizeof(uint8_t)) {
        return NULL;
    }
    const wickr_ec_curve_t *curve = wickr_ec_curve_find(buffer->bytes[0]);
    
    if (!curve) {
        return NULL;
    }
    
    int nid = __openssl_get_ec_nid(*curve);
    
    if (nid == NID_UNSUPPORTED) {
        return NULL;
    }
    
    EC_KEY *new_key = EC_KEY_new_by_curve_name(nid);
    
    if (!new_key) {
        return NULL;
    }
    
    wickr_buffer_t remaining_buffer;
    remaining_buffer.bytes = buffer->bytes + sizeof(uint8_t);
    remaining_buffer.length = buffer->length - sizeof(uint8_t);
    
    EVP_PKEY *p_key = __openssl_evp_ec_key_from_buffer(new_key, &remaining_buffer, o2i_ECPublicKey);
    
    if (!p_key) {
        EC_KEY_free(new_key);
    }
    
    return p_key;
}

static EVP_PKEY *__openssl_evp_hmac_key_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length > INT_MAX) {
        return NULL;
    }
    
    return EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buffer->bytes, (int)buffer->length);
}

static EVP_MD_CTX * __openssl_digest_ctx_create(wickr_digest_t digest_mode)
{
    const EVP_MD *digest = __openssl_get_digest_mode(digest_mode);
    
    if (!digest) {
        return NULL;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    
    /* Initialize a digest context using the requested digest mode */
    if (1 != EVP_DigestInit_ex(ctx, digest, NULL)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    return ctx;
}

typedef EVP_PKEY *(*wickr_buffer_to_key_func)(const wickr_buffer_t *);

static EVP_MD_CTX * __openssl_digest_sign_ctx_create(wickr_digest_t digest_mode,
                                                     const wickr_buffer_t *key_data,
                                                     wickr_buffer_to_key_func key_deserialization_function)
{
    if (!key_data || !key_deserialization_function) {
        return NULL;
    }
    
    EVP_MD_CTX *ctx = __openssl_digest_ctx_create(digest_mode);
    
    if (!ctx) {
        return NULL;
    }
    
    /* Convert the signing key to EVP format */
    EVP_PKEY *evp_signing_key = key_deserialization_function(key_data);
    
    if (!evp_signing_key) {
        return NULL;
    }
    
    /* Initialize the digest context into a signing context */
    if (1 != EVP_DigestSignInit(ctx, NULL, EVP_MD_CTX_md(ctx), NULL, evp_signing_key)) {
        EVP_PKEY_free(evp_signing_key);
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    EVP_PKEY_free(evp_signing_key);
    
    return ctx;
}

static EVP_MD_CTX * __openssl_digest_verify_ctx_create(wickr_digest_t digest_mode,
                                                       wickr_buffer_t *key_data,
                                                       wickr_buffer_to_key_func key_deserialization_function)
{
    EVP_MD_CTX *ctx = __openssl_digest_ctx_create(digest_mode);
    
    if (!ctx) {
        return NULL;
    }
    
    /* Initialize a digest context with the digest the signature was created with */
    if (1 != EVP_DigestInit_ex(ctx, EVP_MD_CTX_md(ctx), NULL)) {
        return NULL;
    }
    
    /* Convert the supplied public key to EVP format */
    EVP_PKEY *evp_signing_key = __openssl_evp_public_key_from_buffer(key_data);
    
    if (!evp_signing_key) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    /* Initialize the digest context to a verify context */
    if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_MD_CTX_md(ctx), NULL, evp_signing_key)) {
        EVP_MD_CTX_destroy(ctx);
        EVP_PKEY_free(evp_signing_key);
        return NULL;
    }
    
    EVP_PKEY_free(evp_signing_key);

    return ctx;
}

static wickr_buffer_t * __openssl_digest_sign_operation(wickr_digest_t digest_mode,
                                                        const wickr_buffer_t *data_to_process,
                                                        const wickr_buffer_t *key_data,
                                                        wickr_buffer_to_key_func key_deserialization_function)
{
    EVP_MD_CTX *ctx = __openssl_digest_sign_ctx_create(digest_mode, key_data, key_deserialization_function);
    
    if (!ctx) {
        return NULL;
    }
    
    /* Provide the bytes we want to sign the hash of to EVP */
    if (1 != EVP_DigestSignUpdate(ctx, data_to_process->bytes, data_to_process->length)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    size_t signature_size = 0;
    
    /* Determine the size of the resulting signature */
    if (1 != EVP_DigestSignFinal(ctx, NULL, &signature_size)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    if (!(signature_size > 0)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    wickr_buffer_t *signature_buffer = wickr_buffer_create_empty(signature_size);
    
    if (!signature_buffer) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    signature_buffer->length = signature_size;
    
    /* Perform the signature */
    if (1 != EVP_DigestSignFinal(ctx, signature_buffer->bytes, &signature_buffer->length)) {
        wickr_buffer_destroy(&signature_buffer);
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }
    
    EVP_MD_CTX_destroy(ctx);
    
    return signature_buffer;
}

wickr_buffer_t *openssl_crypto_random(size_t len)
{
    /* OpenSSL does not allow random byte generation greater than INT_MAX size */
    if (len > INT_MAX) {
        return NULL;
    }
    
    wickr_buffer_t *new_buffer = wickr_buffer_create_empty(len);
    
    if (1 != RAND_bytes(new_buffer->bytes, (int)len)) {
        wickr_buffer_destroy(&new_buffer);
        return NULL;
    }
    
    return new_buffer;
}

wickr_cipher_key_t *openssl_cipher_key_random(wickr_cipher_t cipher)
{
    wickr_buffer_t *key_material = openssl_crypto_random(cipher.key_len);
    
    if (!key_material) {
        return NULL;
    }
    
    wickr_cipher_key_t *new_key = wickr_cipher_key_create(cipher, key_material);
    
    if (!new_key) {
        wickr_buffer_destroy_zero(&key_material);
    }
    
    return new_key;
}

wickr_cipher_result_t *openssl_aes256_encrypt(const wickr_buffer_t *plaintext, const wickr_buffer_t *aad, const wickr_cipher_key_t *key, const wickr_buffer_t *iv)
{
    if (!plaintext || !key) {
        return NULL;
    }
    
    /* AAD only works if the cipher supports authentication */
    if (aad && !key->cipher.is_authenticated) {
        return NULL;
    }
    
    const EVP_CIPHER *openssl_cipher = __openssl_get_cipher_mode(key->cipher);
    
    if (!openssl_cipher) {
        return NULL;
    }
    
    wickr_cipher_t cipher = key->cipher;
    
    /* OpenSSL does not allow encryption of buffers greater than INT_MAX size */
    if (key->key_data->length != cipher.key_len || plaintext->length > INT_MAX) {
        return NULL;
    }
    
    /* If an IV is not passed in, generate a random one */
    wickr_buffer_t *iv_f = iv ? wickr_buffer_copy(iv) : openssl_crypto_random(cipher.iv_len);
    
    /* Allocate a buffer to hold the resulting ciphertext */
    wickr_buffer_t *cipher_text = wickr_buffer_create_empty(plaintext->length + EVP_CIPHER_block_size(openssl_cipher));
    
    /* Initialize an OpenSSL cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    /* If we are using GCM mode, allocate memory to hold the auth tag */
    wickr_buffer_t *auth_tag = NULL;
    
    if (cipher.is_authenticated) {
        auth_tag = wickr_buffer_create_empty(cipher.auth_tag_len);
        if (!auth_tag) {
            goto process_error;
        }
    }
    
    /* Verify integrity of our allocations */
    if (!iv_f || !cipher_text || !ctx) {
        goto process_error;
    }
    
    /* Initialize the context with NULL to allow us to perform control operations */
    if (1 != EVP_EncryptInit_ex(ctx, openssl_cipher, NULL, NULL, NULL)) {
        goto process_error;
    }
    
    /* Re-Initialize the context with proper values to prepare for encryption */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key->key_data->bytes, iv_f->bytes)) {
        goto process_error;
    }
    
    int temp_length = 0;
    int final_length = 0;
    
    /* Insert AAD */
    if (aad) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &temp_length, aad->bytes, (int)aad->length)) {
            goto process_error;
        }
    }
    
    /* Perform the cipher */
    if (1 != EVP_EncryptUpdate(ctx, cipher_text->bytes, &temp_length, plaintext->bytes, (int)plaintext->length)) {
        goto process_error;
    }
    cipher_text->length = (size_t)temp_length;
    
    /* Add padding if necessary for the selected mode */
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_text->bytes + temp_length, &final_length)) {
        goto process_error;
    }
    
    /* Update the length of the resulting cipher_text */
    cipher_text->length += (size_t)final_length;
    
    /* Extract the tag from EVP if we are using AES_GCM mode */
    if (cipher.is_authenticated && cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (!auth_tag) {
            goto process_error;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cipher.auth_tag_len, auth_tag->bytes)) {
            goto process_error;
        }
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    return wickr_cipher_result_create(cipher, iv_f, cipher_text, auth_tag);
    
process_error:
    if (auth_tag) {
        wickr_buffer_destroy(&auth_tag);
    }
    if (cipher_text) {
        wickr_buffer_destroy(&cipher_text);
    }
    if (iv_f) {
        wickr_buffer_destroy(&iv_f);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return NULL;
}

wickr_buffer_t *openssl_aes256_decrypt(const wickr_cipher_result_t *cipher_result, const wickr_buffer_t *aad, const wickr_cipher_key_t *key, bool only_auth_ciphers)
{
    if (!cipher_result || !key) {
        return NULL;
    }
    
    if (only_auth_ciphers && !cipher_result->cipher.is_authenticated) {
        return NULL;
    }
    
    /* AAD only works with authenticated ciphers */
    if (aad && !cipher_result->cipher.is_authenticated) {
        return NULL;
    }

    const EVP_CIPHER *cipher = __openssl_get_cipher_mode(cipher_result->cipher);
    
    if (!cipher) {
        return NULL;
    }
    
    /* OpenSSL does not allow decryption of buffers greater than INT_MAX in length */
    if (key->cipher.cipher_id != cipher_result->cipher.cipher_id || cipher_result->cipher_text->length > INT_MAX) {
        return NULL;
    }
    
    /* In GCM mode, make sure the length of the auth tag is correct */
    if (cipher_result->cipher.is_authenticated) {
        if (!cipher_result->auth_tag || cipher_result->auth_tag->length != cipher_result->cipher.auth_tag_len) {
            return NULL;
        }
    }
    
    /* Allocate a cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    /* Allocate the output buffer */
    wickr_buffer_t *output_buffer = wickr_buffer_create_empty(cipher_result->cipher_text->length);
    
    if (!ctx || !output_buffer) {
        goto process_error;
    }
    
    /* Initialize the context with NULL to allow us to perform control operations */
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        goto process_error;
    }
    
    /* In GCM mode, set the IV length to match our cipher (currently 12 bytes, which happens to be OpenSSL default) */
    if (cipher_result->cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cipher_result->cipher.iv_len, NULL)) {
            goto process_error;
        }
    }
    
    /* Re-Initialize the context with proper values to prepare for encryption */
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key->key_data->bytes, cipher_result->iv->bytes)) {
        goto process_error;
    }

    /* If we are decrypting in GCM mode, set the expected tag */
    if (cipher_result->cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, cipher_result->cipher.auth_tag_len, cipher_result->auth_tag->bytes)) {
            goto process_error;
        }
    }
    
    int temp_length = 0;
    int final_length = 0;
    
    /* Update the AAD if needed */
    
    if (aad) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &temp_length, aad->bytes, aad->length)) {
            goto process_error;
        }
    }
    
    /* Perform the decryption */
    if (1 != EVP_DecryptUpdate(ctx, output_buffer->bytes, &temp_length,
                               cipher_result->cipher_text->bytes, (int)cipher_result->cipher_text->length)) {
        goto process_error;
    }
    output_buffer->length = (size_t)temp_length;
    
    /* Remove any padding and if GCM mode verify the tag */
    if (1 != EVP_DecryptFinal_ex(ctx, output_buffer->bytes + temp_length, &final_length)) {
        goto process_error;
    }
    
    /* Update the length of the resulting plain text */
    output_buffer->length += (size_t)final_length;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return output_buffer;
    
process_error:
    if (output_buffer) {
        wickr_buffer_destroy(&output_buffer);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return NULL;
}

static bool __openssl_sha2_initialize_ctx(wickr_digest_t mode, EVP_MD_CTX *c)
{
    const EVP_MD *digest = __openssl_get_digest_mode(mode);
    
    /* End processing if OpenSSL does not support the request digest */
    if (!digest) {
        return false;
    }
    
    if (1 != EVP_DigestInit(c, digest)) {
        return false;
    }
    
    return true;
}

wickr_buffer_t *openssl_sha2(const wickr_buffer_t *buffer, const wickr_buffer_t *salt, wickr_digest_t mode)
{
    if (!buffer) {
        return NULL;
    }
    
    EVP_MD_CTX *c = EVP_MD_CTX_create();
    
    if (!c) {
        return NULL;
    }
    
    if (!__openssl_sha2_initialize_ctx(mode, c)) {
        EVP_MD_CTX_destroy(c);
        return NULL;
    }
    
    /* Perform the digest */
    if (1 != EVP_DigestUpdate(c, buffer->bytes, buffer->length)) {
        EVP_MD_CTX_destroy(c);
        return NULL;
    }
    
    /* If a salt has been requested, it is added into the digest */
    if (salt) {
        if (1 != EVP_DigestUpdate(c, salt->bytes, salt->length)) {
            EVP_MD_CTX_destroy(c);
            return NULL;
        }
    }
    
    wickr_buffer_t *hash_result = wickr_buffer_create_empty_zero(mode.size);
    
    if (1 != EVP_DigestFinal(c, hash_result->bytes, NULL)) {
        wickr_buffer_destroy(&hash_result);
        EVP_MD_CTX_destroy(c);
        return NULL;
    }
    
    EVP_MD_CTX_destroy(c);
    
    return hash_result;
}

wickr_buffer_t *openssl_sha2_file(FILE *in_file, wickr_digest_t mode)
{
    if (!in_file) {
        return NULL;
    }
    
    EVP_MD_CTX *c = EVP_MD_CTX_create();
    
    if (!c) {
        return NULL;
    }
    
    if (!__openssl_sha2_initialize_ctx(mode, c)) {
        EVP_MD_CTX_destroy(c);
        return NULL;
    }
    
    unsigned char plainBuffer[4096];
    
    wickr_buffer_t *hash_result = wickr_buffer_create_empty_zero(mode.size);
    
    if (!hash_result) {
        EVP_MD_CTX_destroy(c);
        return NULL;
    }
    
    for (;;) {
        size_t bytesRead = fread(plainBuffer, 1, sizeof(plainBuffer), in_file);
        
        if (ferror(in_file)) {
            wickr_buffer_destroy(&hash_result);
            EVP_MD_CTX_destroy(c);
            return NULL;
        }
        
        if (1 != EVP_DigestUpdate(c, plainBuffer, bytesRead)) {
            wickr_buffer_destroy(&hash_result);
            EVP_MD_CTX_destroy(c);
            return NULL;
        }
        
        if (bytesRead < sizeof(plainBuffer)) {
            if (1 != EVP_DigestFinal(c, hash_result->bytes, NULL)) {
                wickr_buffer_destroy(&hash_result);
                EVP_MD_CTX_destroy(c);
                return NULL;
            }
            break;
        }
    }
    
    EVP_MD_CTX_destroy(c);
    
    return hash_result;
}

wickr_ec_key_t *openssl_ec_rand_key(wickr_ec_curve_t curve)
{
    /* Find the proper curve */
    int nid = __openssl_get_ec_nid(curve);
    
    if (nid == NID_undef) {
        return NULL;
    }
    
    /* Generate an EC_KEY struct with the selected curve */
    EC_KEY *new_key = EC_KEY_new_by_curve_name(nid);
    
    /* Tell OpenSSL we are using a named curve so it gets serialized with the keys */
    EC_KEY_set_asn1_flag(new_key, OPENSSL_EC_NAMED_CURVE);
    
    if (!new_key) {
        return NULL;
    }
    
    /* Generate a random  key pair  and store it in new_key */
    if (1 != EC_KEY_generate_key(new_key)) {
        EC_KEY_free(new_key);
        return NULL;
    }
    
    wickr_buffer_t *pri_key_buffer = __openssl_ec_pri_key_to_buffer(new_key);
    
    if (!pri_key_buffer) {
        EC_KEY_free(new_key);
        return NULL;
    }
    
    wickr_buffer_t *pub_key_buffer = __openssl_ec_pub_key_to_buffer(curve, new_key);
    
    if (!pub_key_buffer) {
        EC_KEY_free(new_key);
        wickr_buffer_destroy(&pri_key_buffer);
        return NULL;
    }
    
    EC_KEY_free(new_key);
    
    wickr_ec_key_t *new_ec_key = wickr_ec_key_create(curve, pub_key_buffer, pri_key_buffer);
    
    if (!new_ec_key) {
        wickr_buffer_destroy(&pri_key_buffer);
        wickr_buffer_destroy(&pub_key_buffer);
    }
    
    return new_ec_key;
}

static const wickr_ec_curve_t *__openssl_get_pkey_ec_curve(EVP_PKEY *key)
{
    if (!key) {
        return NULL;
    }
    
#if OPENSSL_VERSION_NUMBER >= 0x010100000
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(key);
#else
    EC_KEY *ec_key = key->pkey.ec;
#endif
    
    if (!ec_key) {
        return NULL;
    }
    
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    
    if (!group) {
        return NULL;
    }
    
    int nid = EC_GROUP_get_curve_name(group);
    
    switch (nid) {
        case NID_secp521r1:
            return &EC_CURVE_NIST_P521;
        default:
            return NULL;
    }
}

wickr_ec_key_t *openssl_ec_key_import(const wickr_buffer_t *buffer, bool is_private)
{
    if (!buffer) {
        return NULL;
    }
    
    EVP_PKEY *key = NULL;
    
    if (is_private) {
        key = __openssl_evp_private_key_from_buffer(buffer);
    }
    else {
        key = __openssl_evp_public_key_from_buffer(buffer);
    }
    
    if (!key) {
        return NULL;
    }
    
#if OPENSSL_VERSION_NUMBER >= 0x010100000
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(key);
#else
    EC_KEY *ec_key = key->pkey.ec;
#endif
    
    if (!ec_key) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    const EC_GROUP *ec_key_group = EC_KEY_get0_group(ec_key);
    
    if (!ec_key_group) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    
    if (!pub_key) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    /* Check if the key is the point at infinity, OpenSSL does a poor job of detecting this in certain cases */
    if (EC_POINT_is_at_infinity(ec_key_group, pub_key)) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    const wickr_ec_curve_t *curve = __openssl_get_pkey_ec_curve(key);
    
    if (!curve) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    wickr_buffer_t *public_key = __openssl_ec_pub_key_to_buffer(*curve, ec_key);
    
    if (!public_key) {
        EVP_PKEY_free(key);
        return NULL;
    }
    
    wickr_buffer_t *private_key = NULL;
    
    if (is_private) {
        private_key = __openssl_ec_pri_key_to_buffer(ec_key);
        
        if (!private_key) {
            EVP_PKEY_free(key);
            wickr_buffer_destroy(&public_key);
            return NULL;
        }
    }
    
    EVP_PKEY_free(key);
    
    wickr_ec_key_t *new_key = wickr_ec_key_create(*curve, public_key, private_key);
    
    if (!new_key) {
        wickr_buffer_destroy_zero(&public_key);
        wickr_buffer_destroy_zero(&private_key);
    }
    
    return new_key;
}

wickr_ecdsa_result_t *openssl_ec_sign(const wickr_ec_key_t *ec_signing_key, const wickr_buffer_t *data_to_sign, wickr_digest_t digest_mode)
{
    if (!ec_signing_key || !ec_signing_key->pri_data || !data_to_sign) {
        return NULL;
    }
    
    wickr_buffer_t *signed_data = __openssl_digest_sign_operation(digest_mode, data_to_sign, ec_signing_key->pri_data,
                                                                  __openssl_evp_private_key_from_buffer);
    
    if (!signed_data) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *final_result = wickr_ecdsa_result_create(ec_signing_key->curve, digest_mode, signed_data);
    
    if (!final_result) {
        wickr_buffer_destroy(&signed_data);
    }
    
    return final_result;
}

bool openssl_ec_verify(const wickr_ecdsa_result_t *signature, const wickr_ec_key_t *ec_public_key, const wickr_buffer_t *data_to_verify)
{
    if (!signature || !ec_public_key || !data_to_verify) {
        return false;
    }
    
    EVP_MD_CTX *ctx = __openssl_digest_verify_ctx_create(signature->digest_mode, ec_public_key->pub_data, __openssl_evp_public_key_from_buffer);
    
    if (!ctx) {
        return false;
    }
    
    /* Provide the signature we want to validate to the digest context */
    if (1 != EVP_DigestVerifyUpdate(ctx, data_to_verify->bytes, data_to_verify->length)) {
        EVP_MD_CTX_destroy(ctx);
        return false;
    }
    
    /* Perform the verification to determine the validity of the signature */
    int result = EVP_DigestVerifyFinal(ctx, signature->sig_data->bytes, signature->sig_data->length);
    EVP_MD_CTX_destroy(ctx);
    
    return result == 1 ? true : false;
}

wickr_buffer_t *openssl_ecdh_gen_key(const wickr_ecdh_params_t *params)
{
    if (!params || !wickr_ecdh_params_are_valid(params)) {
        return NULL;
    }
    
    /* Convert your local private key to EVP format */
    EVP_PKEY *local_key = __openssl_evp_private_key_from_buffer(params->local_key->pri_data);
    
    if (!local_key) {
        return NULL;
    }
    
    /* Convert the peer's public key to EVP format */
    EVP_PKEY *peer_key = __openssl_evp_public_key_from_buffer(params->peer_key->pub_data);
    
    
    if (!peer_key) {
        EVP_PKEY_free(local_key);
        return NULL;
    }
    
    /* Allocate a new PKEY_CTX */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_key, NULL);
    
    if (!ctx) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return NULL;
    }
    
    /* Initialize the PKEY_CTX to perform the ECDH derivation */
    if (1 != EVP_PKEY_derive_init(ctx)) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    /* Set the peer key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peer_key)) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    size_t shared_secret_len = 0;
    
    /* Determine the length of the shared secret so we can allocate a buffer for it */
    if (1 != EVP_PKEY_derive(ctx, NULL, &shared_secret_len)) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    wickr_buffer_t *shared_secret_buffer = wickr_buffer_create_empty_zero(shared_secret_len);
    
    if (!shared_secret_buffer) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    /* Derive the ECDH shared secret */
    if (1 != EVP_PKEY_derive(ctx, shared_secret_buffer->bytes, &shared_secret_buffer->length)) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        wickr_buffer_destroy_zero(&shared_secret_buffer);
        return NULL;
    }
    
    /* Run the ECDH shared secret through HKDF with the provided salt and info from the ECDH params */
    wickr_kdf_result_t *kdf_result = wickr_perform_kdf_meta(params->kdf_info, shared_secret_buffer);

    EVP_PKEY_free(local_key);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(ctx);
    wickr_buffer_destroy_zero(&shared_secret_buffer);
    
    if (!kdf_result) {
        return NULL;
    }
    
    wickr_buffer_t *final_buffer = wickr_buffer_copy(kdf_result->hash);
    wickr_kdf_result_destroy(&kdf_result);
    
    return final_buffer;
}

wickr_buffer_t *openssl_hmac_create(const wickr_buffer_t *data, const wickr_buffer_t *hmac_key, wickr_digest_t mode)
{
    if (!data || !hmac_key) {
        return NULL;
    }
    
    return __openssl_digest_sign_operation(mode, data, hmac_key, __openssl_evp_hmac_key_from_buffer);
}

bool openssl_hmac_verify(const wickr_buffer_t *data, const wickr_buffer_t *hmac_key, wickr_digest_t mode, const wickr_buffer_t *expected)
{
    /* Compute the expected HMAC */
    wickr_buffer_t *computed_hmac = openssl_hmac_create(data, hmac_key, mode);
    
    if (!expected || !computed_hmac) {
        return false;
    }
    
    /* Verify the computed HMAC is equal to the expected HMAC value */
    bool result = wickr_buffer_is_equal(computed_hmac, expected, (wickr_buffer_compare_func)CRYPTO_memcmp);
    
    wickr_buffer_destroy_zero(&computed_hmac);
    
    return result;
}


bool
openssl_encrypt_file(FILE *in_file, const wickr_cipher_key_t *key, FILE *out_file)
{
    if (!in_file || !key || !out_file) {
        return false;
    }
    
    rewind(out_file);

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *cipherBuffer = NULL;
    bool ret_val = false;
    
    wickr_buffer_t *iv_f = openssl_crypto_random(key->cipher.iv_len);
    wickr_buffer_t *auth_tag = wickr_buffer_create_empty(key->cipher.auth_tag_len);
    
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(key->cipher, iv_f, NULL, auth_tag);
    
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    if (!serialized)
        goto process_error;
    
    size_t num_written = fwrite(serialized->bytes, 1, serialized->length, out_file);
    if (num_written != serialized->length) {
        goto process_error;
    }
    wickr_buffer_destroy(&serialized);
    
    const EVP_CIPHER *openssl_cipher = __openssl_get_cipher_mode(cipher_result->cipher);
    if (!openssl_cipher) {
        goto process_error;
    }
    
    /* OpenSSL does not allow encryption of buffers greater than INT_MAX size */
    if (key->key_data->length != cipher_result->cipher.key_len) {
        goto process_error;
    }
    
    /* Initialize an OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto process_error;
    
    /* If we are using GCM mode, allocate memory to hold the auth tag */    
    if (cipher_result->cipher.is_authenticated) {
        wickr_buffer_destroy(&cipher_result->auth_tag);
        cipher_result->auth_tag = wickr_buffer_create_empty_zero(cipher_result->cipher.auth_tag_len);
    }
    
    /* Verify integrity of our allocations */
    if ((cipher_result->cipher.is_authenticated && !cipher_result->auth_tag)) {
        goto process_error;
    }
    
    /* Initialize the context with NULL to allow us to perform control operations */
    if (1 != EVP_EncryptInit_ex(ctx, openssl_cipher, NULL, NULL, NULL)) {
        goto process_error;
    }
    
    /* Re-Initialize the context with proper values to prepare for encryption */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key->key_data->bytes, cipher_result->iv->bytes)) {
        goto process_error;
    }
    
    // Use a 4kb block size
    unsigned char plainBuffer[4096];
    cipherBuffer = (unsigned char *)wickr_alloc(sizeof(plainBuffer) + EVP_CIPHER_CTX_block_size(ctx));
    int outlength = 0;
    
    for (;;) {
        size_t bytes_read = fread(plainBuffer, 1, sizeof(plainBuffer), in_file);
        
        if (1 != EVP_EncryptUpdate(ctx, cipherBuffer, &outlength, plainBuffer, (int)bytes_read)) {
            goto process_error;
        }

        // Write the bytes to the output file
        size_t bytes_written = fwrite(cipherBuffer, 1, outlength, out_file);
        if (bytes_written != outlength) {
            goto process_error;
        }
        
        if (bytes_read < sizeof(plainBuffer)) {
            
            if (1 != EVP_EncryptFinal_ex(ctx, plainBuffer, &outlength)) {
                goto process_error;
            }
            
            if (outlength > 0) {
                size_t bytes_written = fwrite(cipherBuffer, 1, outlength, out_file);
                if (bytes_written != outlength) {
                    goto process_error;
                }
            }
            break;
        }
    }
    
    /* Extract the tag from EVP if we are using AES_GCM mode */
    if (cipher_result->cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (!cipher_result->auth_tag)
            goto process_error;
        
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cipher_result->cipher.auth_tag_len,cipher_result->auth_tag->bytes)) {
            goto process_error;
        }
    }
    
    // Complete the saving of data to the file
    serialized = wickr_cipher_result_serialize(cipher_result);
    if (serialized) {
        //Seek to the position that the Tag zeros start in the file so we can fill in the tag
        rewind(out_file);
        size_t bytes_written = fwrite(serialized->bytes, 1, serialized->length, out_file);
        if (bytes_written != serialized->length) {
            goto process_error;
        }
    }
    
    ret_val = true;
    
    // Fall through to clean up
    
process_error:
    if (serialized) {
        wickr_buffer_destroy(&serialized);
    }
    if (cipher_result) {
        wickr_cipher_result_destroy(&cipher_result);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (cipherBuffer) {
        wickr_free(cipherBuffer);
    }
    
    return ret_val;
}


bool
openssl_decrypt_file(FILE *in_file, const wickr_cipher_key_t *key, FILE *out_file, bool only_auth_ciphers)
{
    if (!in_file || !key || !out_file) {
        return false;
    }
    
    uint8_t cipherMode[1] = {0};
    bool ret_val = false;
    EVP_CIPHER_CTX *ctx = NULL;
    
    //Read in the header info that tells us the legnth of the IV and TAG fields
    size_t readLen = fread(cipherMode, 1, 1, in_file);
    if (readLen != 1) {
        return false;
    }
    
    const wickr_cipher_t *mode = wickr_cipher_find(cipherMode[0]);
    if (!mode) {
        return false;
    }
    
    if (only_auth_ciphers && !mode->is_authenticated) {
        return false;
    }
    
    size_t required_size = sizeof(uint8_t) + mode->iv_len + mode->auth_tag_len;
    
    uint8_t *cipher_bytes = wickr_alloc(required_size);
    if (!cipher_bytes) {
        return false;
    }
    cipher_bytes[0] = cipherMode[0];
    readLen = fread(&cipher_bytes[1], 1, required_size-1, in_file);
    
    if (readLen != (required_size - 1)) {
        wickr_free(cipher_bytes);
        return false;
    }
    
    wickr_buffer_t* cipher_buffer = wickr_buffer_create(cipher_bytes, required_size);
    wickr_free(cipher_bytes);
    
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(cipher_buffer);
    
    unsigned char *plainBuffer = NULL;
    const EVP_CIPHER *cipher = __openssl_get_cipher_mode(cipher_result->cipher);
    if (!cipher) {
        goto process_error;
    }
    
    /* OpenSSL does not allow decryption of buffers greater than INT_MAX in length */
    if (key->key_data->length != cipher_result->cipher.key_len) {
        goto process_error;
    }
    
    /* In GCM mode, make sure the length of the auth tag is correct */
    if (cipher_result->cipher.is_authenticated) {
        if (!cipher_result->auth_tag || cipher_result->auth_tag->length != cipher_result->cipher.auth_tag_len) {
            goto process_error;
        }
    }
    
    /* Allocate a cipher context */
    ctx = EVP_CIPHER_CTX_new();
    
    /* Initialize the context with NULL to allow us to perform control operations */
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        goto process_error;
    }
    
    /* In GCM mode, raise the IV length from OpenSSL default of 12 to 16 */
    if (cipher_result->cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cipher_result->cipher.iv_len, NULL)) {
            goto process_error;
        }
    }
    
    /* Re-Initialize the context with proper values to prepare for encryption */
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key->key_data->bytes, cipher_result->iv->bytes)) {
        goto process_error;
    }

    /* In GCM mode, set the tag len */
    if (cipher_result->cipher.cipher_id == CIPHER_ID_AES256_GCM) {
        if (cipher_result->auth_tag->length > INT_MAX) {
            goto process_error;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)cipher_result->auth_tag->length, cipher_result->auth_tag->bytes)) {
            goto process_error;
        }
    }
    
    
    unsigned char cipherBuffer[4096];
    plainBuffer = wickr_alloc(sizeof(cipherBuffer) + EVP_CIPHER_CTX_block_size(ctx));
    int outlength = 0;
    
    for (;;) {
        size_t bytesRead = fread(cipherBuffer, 1, sizeof(cipherBuffer), in_file);
       
        if (1 != EVP_DecryptUpdate(ctx, plainBuffer, &outlength, cipherBuffer, (int)bytesRead)) {
            goto process_error;
        }
        
        size_t bytes_written = fwrite(plainBuffer, 1, outlength, out_file);
        if (bytes_written != outlength) {
            goto process_error;
        }

        
        if (bytesRead < sizeof(cipherBuffer)) {
            if (1 != EVP_DecryptFinal_ex(ctx, cipherBuffer, &outlength)) {
                goto process_error;
            }
            if (outlength > 0) {
                size_t bytes_written = fwrite(plainBuffer, 1, outlength, out_file);
                if (bytes_written != outlength) {
                    goto process_error;
                }
            }
            break;
        }
    }
    ret_val = true;
    
process_error:
    if (cipher_buffer) {
        wickr_buffer_destroy(&cipher_buffer);
    }
    if (cipher_result) {
        wickr_cipher_result_destroy(&cipher_result);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (plainBuffer) {
        wickr_free(plainBuffer);
    }
    return ret_val;
}

/* Copied from OpenSSL ecdhtest.c */
static EC_KEY *mk_eckey(int nid, const char *str)
{
    int ok = 0;
    EC_KEY *k = NULL;
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    const EC_GROUP *grp;
    k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        goto err;
    EC_KEY_set_asn1_flag(k, OPENSSL_EC_NAMED_CURVE);
    if(!BN_hex2bn(&priv, str))
        goto err;
    if (!priv)
        goto err;
    if (!EC_KEY_set_private_key(k, priv))
        goto err;
    grp = EC_KEY_get0_group(k);
    pub = EC_POINT_new(grp);
    if (!pub)
        goto err;
    if (!EC_POINT_mul(grp, pub, priv, NULL, NULL, NULL))
        goto err;
    if (!EC_KEY_set_public_key(k, pub))
        goto err;
    ok = 1;
err:
    BN_clear_free(priv);
    EC_POINT_free(pub);
    if (ok)
        return k;
    EC_KEY_free(k);
    return NULL;
}

wickr_ec_key_t *openssl_ec_key_import_test_key(wickr_ec_curve_t curve, const char *priv_hex)
{
    int nid = __openssl_get_ec_nid(curve);
    
    if (nid == NID_UNSUPPORTED) {
        return NULL;
    }
    
    EC_KEY *ec_key = mk_eckey(nid, priv_hex);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_buffer_t *pri_data = __openssl_ec_pri_key_to_buffer(ec_key);
    
    if (!pri_data) {
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    wickr_buffer_t *pub_data = __openssl_ec_pub_key_to_buffer(curve, ec_key);
    EC_KEY_free(ec_key);
    
    if (!pub_data) {
        wickr_buffer_destroy(&pri_data);
        return NULL;
    }
    
    wickr_ec_key_t *converted_key = wickr_ec_key_create(curve, pub_data, pri_data);
    
    if (!converted_key) {
        wickr_buffer_destroy(&pri_data);
        wickr_buffer_destroy(&pub_data);
    }
    
    return converted_key;
}

#if OPENSSL_VERSION_NUMBER < 0x010100000

/* Backported to OpenSSL 1.0.2.x from OpenSSL 1.1.0.x */

static unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len);

/* Backported to OpenSSL 1.0.2.x from OpenSSL 1.1.0.x */

static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len);

/* Backported to OpenSSL 1.0.2.x from OpenSSL 1.1.0.x */

unsigned char *HKDF(const EVP_MD *evp_md,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *info, size_t info_len,
                    unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned char *ret;
    size_t prk_len;
    
    
    /* Defend against OpenSSL 1.0.2 returning NULL if a NULL key is passed in a one shot HMAC
    https://github.com/openssl/openssl/commit/b1413d9bd9d2222823ca1ba2d6cdf4849e635231 */
    
    static const unsigned char dummy_salt[1] = {'\0'};
    
    if (salt == NULL && salt_len == 0) {
        salt = dummy_salt;
    }
    
    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, &prk_len))
        return NULL;
    
    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));
    
    return ret;
}

/* Backported to OpenSSL 1.0.2.x from OpenSSL 1.1.0.x */

static unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len)
{
    unsigned int tmp_len;
    
    if (!HMAC(evp_md, salt, salt_len, key, key_len, prk, &tmp_len))
        return NULL;
    
    *prk_len = tmp_len;
    return prk;
}

/* Backported to OpenSSL 1.0.2.x from OpenSSL 1.1.0.x */

static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len)
{
    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    
    unsigned int i;
    
    unsigned char prev[EVP_MAX_MD_SIZE];
    
    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);
    
    size_t n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;
    
    if (n > 255 || okm == NULL)
        return NULL;
    
    if (!HMAC_Init_ex(&hmac, prk, prk_len, evp_md, NULL))
        goto err;
    
    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;
        
        if (i > 1) {
            if (!HMAC_Init_ex(&hmac, NULL, 0, NULL, NULL))
                goto err;
            
            if (!HMAC_Update(&hmac, prev, dig_len))
                goto err;
        }
        
        if (!HMAC_Update(&hmac, info, info_len))
            goto err;
        
        if (!HMAC_Update(&hmac, &ctr, 1))
            goto err;
        
        if (!HMAC_Final(&hmac, prev, NULL))
            goto err;
        
        copy_len = (done_len + dig_len > okm_len) ?
        okm_len - done_len :
        dig_len;
        
        memcpy(okm + done_len, prev, copy_len);
        
        done_len += copy_len;
    }
    
    
    HMAC_CTX_cleanup(&hmac);
    
    return okm;
    
err:
    HMAC_CTX_cleanup(&hmac);
    return NULL;
}

#endif

wickr_buffer_t *openssl_hkdf(const wickr_buffer_t *input_key_material, const wickr_buffer_t *salt, const wickr_buffer_t *info, wickr_digest_t hash_mode)
{
    if (!input_key_material) {
        return NULL;
    }
    
    /* Don't let info exceed 1024 bytes. https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_hkdf_md.html */
    if (info && info->length > 1024) {
        return NULL;
    }
    
    const EVP_MD *openssl_digest = __openssl_get_digest_mode(hash_mode);
    
    if (!openssl_digest) {
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x010100000
    wickr_buffer_t *out_buffer = wickr_buffer_create_empty_zero(hash_mode.size);
    
    if (!out_buffer) {
        return NULL;
    }
    

    if (!HKDF(openssl_digest,
              salt ? salt->bytes : NULL, salt ? salt->length : 0,
              input_key_material->bytes, input_key_material->length,
              info ? info->bytes: NULL, info ? info->length : 0,
              out_buffer->bytes, out_buffer->length))
    {
        wickr_buffer_destroy(&out_buffer);
        return NULL;
    }
#else
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    
    if (!pctx) {
        return NULL;
    }
    
    if (1 != EVP_PKEY_derive_init(pctx)) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, openssl_digest)) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, input_key_material->bytes, input_key_material->length)) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    if (salt) {
        if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt->bytes, salt->length)) {
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
    }
    
    if (info) {
        if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, info->bytes, info->length)) {
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
    }
    
    wickr_buffer_t *out_buffer = wickr_buffer_create_empty_zero(hash_mode.size);
    
    if (!out_buffer) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    int res = EVP_PKEY_derive(pctx, out_buffer->bytes, &out_buffer->length);
    EVP_PKEY_CTX_free(pctx);
    
    if (1 != res) {
        wickr_buffer_destroy(&out_buffer);
    }
    
#endif
    
    return out_buffer;
}
