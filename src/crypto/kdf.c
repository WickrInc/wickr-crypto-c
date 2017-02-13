
#include "kdf.h"
#include "libscrypt.h"
#include "bcrypt.h"
#include "memory.h"
#include "openssl_suite.h"
#include "ow-crypt.h"

#include <string.h>

#define BCRYPT_SALT_BYTE_LEN 16

static const wickr_kdf_algo_t *__find_dkf_algo_with_id(uint8_t algo_id)
{
    switch (algo_id) {
        case KDF_ID_BCRYPT_15:
            return &KDF_BCRYPT_15;
        case KDF_ID_SCRYPT_17:
            return &KDF_SCRYPT_2_17;
        case KDF_ID_SCRYPT_18:
            return &KDF_SCRYPT_2_18;
        case KDF_ID_SCRYPT_19:
            return &KDF_SCRYPT_2_19;
        case KDF_ID_SCRYPT_20:
            return &KDF_SCRYPT_2_20;
        default: return NULL;
    }
}

wickr_kdf_meta_t *wickr_kdf_meta_create(wickr_kdf_algo_t algo, wickr_buffer_t *salt)
{
    if (!salt || salt->length != algo.salt_size) {
        return NULL;
    }
    
    wickr_kdf_meta_t *meta = wickr_alloc_zero(sizeof(wickr_kdf_meta_t));
    
    if (!meta) {
        return NULL;
    }
    
    meta->algo = algo;
    meta->salt = salt;
    
    return meta;
}

uint8_t wickr_kdf_meta_size_with_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return 0;
    }
    
    if (buffer->length <= sizeof(uint8_t)) {
        return 0;
    }
    
    const wickr_kdf_algo_t *algo = __find_dkf_algo_with_id(buffer->bytes[0]);
    
    if (!algo) {
        return 0;
    }
    
    return sizeof(uint8_t) + algo->salt_size;
}

wickr_kdf_meta_t *wickr_kdf_meta_create_with_buffer(const wickr_buffer_t *buffer)
{
    uint8_t meta_size = wickr_kdf_meta_size_with_buffer(buffer);
    
    if (meta_size == 0) {
        return NULL;
    }
    
    if (buffer->length < meta_size) {
        return NULL;
    }
    
    const wickr_kdf_algo_t *algo = __find_dkf_algo_with_id(buffer->bytes[0]);
    
    if (!algo) {
        return NULL;
    }
    
    wickr_buffer_t *salt_buffer = wickr_buffer_copy_section(buffer, sizeof(uint8_t), algo->salt_size);
    
    if (!salt_buffer) {
        return NULL;
    }
    
    return wickr_kdf_meta_create(*algo, salt_buffer);
}

wickr_buffer_t *wickr_kdf_meta_serialize(const wickr_kdf_meta_t *meta)
{
    if (!meta) {
        return NULL;
    }
    
    uint8_t algo_id = (uint8_t)meta->algo.kdf_id;
    
    wickr_buffer_t algo_id_buffer;
    algo_id_buffer.bytes = &algo_id;
    algo_id_buffer.length = sizeof(uint8_t);
    
    return wickr_buffer_concat(&algo_id_buffer, meta->salt);
}

wickr_kdf_meta_t *wickr_kdf_meta_copy(const wickr_kdf_meta_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *salt_copy = wickr_buffer_copy(source->salt);
    
    if (!salt_copy) {
        return NULL;
    }
    
    return wickr_kdf_meta_create(source->algo, salt_copy);
}

void wickr_kdf_meta_destroy(wickr_kdf_meta_t **meta)
{
    if (!meta || !*meta) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*meta)->salt);
    wickr_free(*meta);
    *meta = NULL;
}

wickr_kdf_result_t *wickr_kdf_result_create(wickr_kdf_meta_t *meta, wickr_buffer_t *hash)
{
    if (!meta || !hash) {
        return NULL;
    }
    
    wickr_kdf_result_t *result = wickr_alloc_zero(sizeof(wickr_kdf_result_t));
    
    if (!result) {
        return NULL;
    }
    
    result->meta = meta;
    result->hash = hash;
    
    return result;
}

wickr_kdf_result_t *wickr_kdf_result_copy(const wickr_kdf_result_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_kdf_meta_t *meta_copy = wickr_kdf_meta_copy(source->meta);
    
    if (!meta_copy) {
        return NULL;
    }
    
    wickr_buffer_t *hash_copy = wickr_buffer_copy(source->hash);
    
    if (!hash_copy) {
        wickr_kdf_meta_destroy(&meta_copy);
        return NULL;
    }
    
    return wickr_kdf_result_create(meta_copy, hash_copy);
}

void wickr_kdf_result_destroy(wickr_kdf_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*result)->hash);
    wickr_kdf_meta_destroy(&(*result)->meta);
    
    wickr_free(*result);
    *result = NULL;
}

static wickr_buffer_t *__scrypt_generate_salt(uint8_t len)
{
    return openssl_crypto_random(len);
}

static const char *_bcrypt_header = "$2y$15$";

static wickr_buffer_t *__bcrypt_generate_salt(int workfactor, int salt_size)
{
    wickr_buffer_t *rand_bytes = openssl_crypto_random(BCRYPT_SALT_BYTE_LEN);
    
    if (!rand_bytes) {
        return NULL;
    }
    
    wickr_buffer_t *salt_buffer = wickr_buffer_create_empty_zero(salt_size + strlen(_bcrypt_header) + 1);
    
    if (!salt_buffer) {
        wickr_buffer_destroy(&rand_bytes);
        return NULL;
    }
    
    if (!crypt_gensalt_rn("$2y$", workfactor, (const char *)rand_bytes->bytes, rand_bytes->length, (char *)salt_buffer->bytes, salt_buffer->length)) {
        wickr_buffer_destroy(&rand_bytes);
        wickr_buffer_destroy(&salt_buffer);
        return NULL;
    }
    
    wickr_buffer_destroy(&rand_bytes);
    salt_buffer->length -= 1;
    
    uint8_t header_size = strlen(_bcrypt_header);
    wickr_buffer_t *final_salt_buffer = wickr_buffer_copy_section(salt_buffer, header_size, salt_buffer->length - header_size);
    wickr_buffer_destroy(&salt_buffer);
    
    return final_salt_buffer;
}

static wickr_buffer_t *__bcrypt_generate_hash(const wickr_kdf_meta_t *meta, const wickr_buffer_t *passphrase)
{
    if (!meta || meta->algo.algo_id != KDF_BCRYPT) {
        return NULL;
    }
    
    const char *salt_header = NULL;
    
    switch (meta->algo.kdf_id) {
        case KDF_ID_BCRYPT_15:
            salt_header = _bcrypt_header;
            break;
        default:
            return NULL;
    }
    
    wickr_buffer_t salt_header_buffer;
    salt_header_buffer.bytes = (uint8_t *)salt_header;
    salt_header_buffer.length = strlen(salt_header);
    
    wickr_buffer_t *salt_buffer = wickr_buffer_create_empty_zero(BCRYPT_HASHSIZE);
    
    if (!salt_buffer) {
        return NULL;
    }
    
    if (!wickr_buffer_modify_section(salt_buffer, salt_header_buffer.bytes, 0, salt_header_buffer.length)) {
        wickr_buffer_destroy(&salt_buffer);
        return NULL;
    }
    
    if (!wickr_buffer_modify_section(salt_buffer, meta->salt->bytes, salt_header_buffer.length, meta->salt->length)) {
        wickr_buffer_destroy(&salt_buffer);
        return NULL;
    }
    
    wickr_buffer_t *passphrase_final = wickr_buffer_create_empty_zero(passphrase->length + 1);
    
    if (!wickr_buffer_modify_section(passphrase_final, passphrase->bytes, 0, passphrase->length)) {
        wickr_buffer_destroy(&salt_buffer);
        return NULL;
    }
    
    char out[BCRYPT_HASHSIZE];
    memset(&out, 0, BCRYPT_HASHSIZE);
    
    if (0 != bcrypt_hashpw((char *)passphrase_final->bytes, (char *)salt_buffer->bytes, out)) {
        wickr_buffer_destroy(&passphrase_final);
        wickr_buffer_destroy(&salt_buffer);
        return NULL;
    }
    
    wickr_buffer_destroy(&passphrase_final);
    
    wickr_buffer_t *hash_buffer = wickr_buffer_create((uint8_t *)out, strlen(out));
    wickr_buffer_destroy(&salt_buffer);

    return hash_buffer;
}

static wickr_buffer_t *__scrypt_generate_hash(const wickr_kdf_meta_t *meta, const wickr_buffer_t *passphrase)
{
    if (!meta || meta->algo.algo_id != KDF_SCRYPT) {
        return NULL;
    }
    
    wickr_buffer_t *hash_buffer = wickr_buffer_create_empty(meta->algo.output_size);
    
    if (!hash_buffer) {
        return NULL;
    }
    
    uint64_t N;
    uint8_t r,p;
    
    p = meta->algo.cost & 0xff;
    r = (meta->algo.cost >> 8) & 0xff;
    N = meta->algo.cost >> 16;
    N = (uint64_t)1 << N;
    
    if (0 != libscrypt_scrypt(passphrase->bytes, passphrase->length, meta->salt->bytes, meta->salt->length, N, r, p, hash_buffer->bytes, hash_buffer->length)) {
        wickr_buffer_destroy(&hash_buffer);
        return NULL;
    }
    
    return hash_buffer;
}

static wickr_buffer_t *__kdf_algo_generate_salt(wickr_kdf_algo_t algo)
{
    switch (algo.algo_id) {
        case KDF_SCRYPT:
            return __scrypt_generate_salt(algo.salt_size);
        case KDF_BCRYPT:
            return __bcrypt_generate_salt(algo.cost, algo.salt_size);
        default:
            return NULL;
    }
}

static wickr_buffer_t *__kdf_algo_hash(const wickr_kdf_meta_t *meta, const wickr_buffer_t *passphrase)
{
    if (!meta) {
        return NULL;
    }
    
    switch (meta->algo.algo_id) {
        case KDF_SCRYPT:
            return __scrypt_generate_hash(meta, passphrase);
        case KDF_BCRYPT:
            return __bcrypt_generate_hash(meta, passphrase);
        default:
            return NULL;
    }
}

wickr_kdf_result_t *wickr_perform_kdf(wickr_kdf_algo_t algo, const wickr_buffer_t *passphrase)
{
    if (!passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *salt = __kdf_algo_generate_salt(algo);
    
    if (!salt) {
        return NULL;
    }
    
    wickr_kdf_meta_t meta;
    meta.algo = algo;
    meta.salt = salt;
    
    wickr_kdf_result_t *result = wickr_perform_kdf_meta(&meta, passphrase);
    wickr_buffer_destroy(&salt);
    
    return result;
}

wickr_kdf_result_t *wickr_perform_kdf_meta(const wickr_kdf_meta_t *existing_meta, const wickr_buffer_t *passphrase)
{
    if (!existing_meta || !passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *hash_output = __kdf_algo_hash(existing_meta, passphrase);
    
    if (!hash_output) {
        return NULL;
    }
    
    wickr_kdf_meta_t *result_meta = wickr_kdf_meta_copy(existing_meta);
    
    if (!result_meta) {
        wickr_buffer_destroy(&hash_output);
        return NULL;
    }
    
    return wickr_kdf_result_create(result_meta, hash_output);
}


