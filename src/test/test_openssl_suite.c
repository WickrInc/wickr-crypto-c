#include "cspec.h"
#include "openssl_suite.h"
#include "cipher.h"
#include "util.h"
#include <limits.h>
#include <string.h>
#include "externs.h"

DESCRIBE(openssl_crypto_random, "openssl_suite: openssl_crypto_random")
{
#if defined(_WIN32) || defined(__ANDROID__)
#else
    IT( "returns NULL when len > INT_MAX" )
    {
		wickr_buffer_t *ret = openssl_crypto_random(INT_MAX+1);

        SHOULD_BE_TRUE( ret == NULL )
    }
    END_IT
#endif

    IT( "return non-NULL value when len == 100 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(100);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT
    IT( "return non-NULL value when len == 1000 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(1000);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT
    IT( "return non-NULL value when len == 100000 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(100000);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT
    IT( "return non-NULL value when len == 1000000 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(1000000);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT
    IT( "return non-NULL value when len == 10000000 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(10000000);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT
    IT( "return non-NULL value when len == INT_MAX / 8 "  )
    {
        wickr_buffer_t *ret = openssl_crypto_random(INT_MAX/8);
        SHOULD_BE_TRUE( ret != NULL )
        wickr_buffer_destroy(&ret);
    }
    END_IT

    IT( "return different value in subsequent calls"  )
    {
        uint32_t test_len = 1000;
        
        wickr_buffer_t *ret1 = openssl_crypto_random(test_len);

        bool found_equal = false;
        
        for (int i = 0; i < 1000; i++) {
            wickr_buffer_t *ret2 = openssl_crypto_random(test_len);
            bool is_equal = wickr_buffer_is_equal(ret1, ret2, NULL);
            wickr_buffer_destroy(&ret2);
            if (is_equal) {
                found_equal = true;
                break;
            }
        }
        
        SHOULD_BE_FALSE(found_equal);
        
        wickr_buffer_destroy(&ret1);
    }
    END_IT
}
END_DESCRIBE

void test_cipher_key_randomness(wickr_cipher_t cipher)
{
    wickr_cipher_key_t *one_rand = openssl_cipher_key_random(cipher);
    SHOULD_NOT_BE_NULL(one_rand);
    
    bool found_equal = false;
    
    for (int i = 0; i < 1000; i++) {
        wickr_cipher_key_t *another_rand = openssl_cipher_key_random(cipher);
        bool is_equal = wickr_buffer_is_equal(one_rand->key_data, another_rand->key_data, NULL);
        wickr_cipher_key_destroy(&another_rand);
        if (is_equal) {
            found_equal = true;
            break;
        }
    }
    
    SHOULD_BE_FALSE(found_equal);
    
    wickr_cipher_key_destroy(&one_rand);
}

DESCRIBE(openssl_cipher_key_random, "openssl_suite: openssl_cipher_key_random")
{
    IT("should produce random keys for the GCM cipher")
    {
        test_cipher_key_randomness(CIPHER_AES256_GCM);
    }
    END_IT
    
    IT("should produce random keys for the CTR cipher")
    {
        test_cipher_key_randomness(CIPHER_AES256_CTR);
    }
    END_IT
}
END_DESCRIBE

static void test_cipher_inputs(wickr_cipher_key_t *test_key, wickr_buffer_t *test_plaintext)
{
    wickr_cipher_result_t *result = openssl_aes256_encrypt(NULL, NULL, test_key, NULL);
    SHOULD_BE_NULL(result);
    result = openssl_aes256_encrypt(test_plaintext, NULL, NULL, NULL);
    SHOULD_BE_NULL(result);
}

static void test_cipher_random_iv(wickr_cipher_key_t *test_key, wickr_buffer_t *test_plaintext)
{
    wickr_cipher_result_t *result = openssl_aes256_encrypt(test_plaintext, NULL, test_key, NULL);
    SHOULD_NOT_BE_NULL(result);
    
    bool found_equal = false;
    
    for (int i = 0; i < 1000; i++) {
        wickr_cipher_result_t *another_result = openssl_aes256_encrypt(test_plaintext, NULL, test_key, NULL);
        SHOULD_NOT_BE_NULL(another_result);
        bool is_equal = wickr_buffer_is_equal(another_result->iv, result->iv, NULL);
        if (!is_equal) {
            is_equal = wickr_buffer_is_equal(another_result->cipher_text, result->cipher_text, NULL);
        }
        wickr_cipher_result_destroy(&another_result);
        if (is_equal) {
            found_equal = true;
            break;
        }
    }
    
    SHOULD_BE_FALSE(found_equal);
    wickr_cipher_result_destroy(&result);
}

static void test_cipher_provided_iv(wickr_cipher_key_t *test_key, wickr_buffer_t *test_plaintext, wickr_buffer_t *test_iv, wickr_buffer_t *test_aad, wickr_buffer_t *expected_cipher_text, wickr_buffer_t *expected_tag, wickr_cipher_t cipher)
{
    wickr_cipher_result_t *result = openssl_aes256_encrypt(test_plaintext, test_aad, test_key, test_iv);
    SHOULD_NOT_BE_NULL(result);
    SHOULD_EQUAL(result->cipher.cipher_id, cipher.cipher_id);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(result->cipher_text, expected_cipher_text, NULL));
    if (expected_tag) {
        SHOULD_BE_TRUE(wickr_buffer_is_equal(result->auth_tag, expected_tag, NULL));
    }
    SHOULD_BE_TRUE(wickr_buffer_is_equal(result->iv, test_iv, NULL));
    
    wickr_buffer_t *decoded = openssl_aes256_decrypt(result, test_aad, test_key, false);
    SHOULD_NOT_BE_NULL(decoded);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(decoded, test_plaintext, NULL));
    wickr_cipher_result_destroy(&result);
    wickr_buffer_destroy(&decoded);
}

DESCRIBE(openssl_cipher_ctr, "openssl_suite: openssl_aes256_encrypt(ctr), openssl_aes256_decrypt(ctr)")
{
    /* http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.5.5 CTR-AES256.Encrypt */
    
    wickr_buffer_t *test_plaintext = hex_char_to_buffer("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    
    wickr_buffer_t *key_data = hex_char_to_buffer("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    
    wickr_cipher_key_t *test_key = wickr_cipher_key_create(CIPHER_AES256_CTR, key_data);
    
    wickr_buffer_t *test_iv = hex_char_to_buffer("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    wickr_buffer_t *expected_cipher_text = hex_char_to_buffer("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
    
    IT("should fail if required inputs are missing")
    {
        test_cipher_inputs(test_key, test_plaintext);
    }
    END_IT
    
    IT("should perform encryption with a random IV if none is provided")
    {
        test_cipher_random_iv(test_key, test_plaintext);
    }
    END_IT
    
    IT("should perform encryption with a provided IV")
    {
        test_cipher_provided_iv(test_key, test_plaintext, test_iv, NULL, expected_cipher_text, NULL, CIPHER_AES256_CTR);
    }
    END_IT
    
    IT("should fail encryption if you pass AAD to a non authenticated cipher")
    {
        wickr_buffer_t *test_aad = hex_char_to_buffer("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        SHOULD_BE_NULL(openssl_aes256_encrypt(test_plaintext, test_aad, test_key, test_iv));
        wickr_buffer_destroy(&test_aad);
    }
    END_IT
    
    wickr_buffer_destroy(&test_plaintext);
    wickr_cipher_key_destroy(&test_key);
    wickr_buffer_destroy(&test_iv);
    wickr_buffer_destroy(&expected_cipher_text);
}
END_DESCRIBE

DESCRIBE(openssl_cipher_gcm, "openssl_suite: openssl_aes256_encrypt(gcm), openssl_aes256_decrypt(gcm)")
{
    /* http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf CASE 15, 16 */
    
    wickr_buffer_t *test_plaintext = hex_char_to_buffer("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    
    wickr_buffer_t *test_plaintext_aad = hex_char_to_buffer("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    
    wickr_buffer_t *key_data = hex_char_to_buffer("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    
    wickr_cipher_key_t *test_key = wickr_cipher_key_create(CIPHER_AES256_GCM, key_data);
    
    wickr_buffer_t *test_iv = hex_char_to_buffer("cafebabefacedbaddecaf888");
    
    wickr_buffer_t *test_aad = hex_char_to_buffer("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    
    wickr_buffer_t *expected_tag_no_aad = hex_char_to_buffer("b094dac5d93471bdec1a502270e3cc6c");
    
    wickr_buffer_t *expected_tag_aad = hex_char_to_buffer("76fc6ece0f4e1768cddf8853bb2d551b");
    
    wickr_buffer_t *expected_cipher_text = hex_char_to_buffer("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    
    wickr_buffer_t *expected_cipher_text_aad = hex_char_to_buffer("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
    
    
    IT("should fail if required inputs are missing")
    {
        test_cipher_inputs(test_key, test_plaintext);
    }
    END_IT
    
    IT("should perform encryption with a random IV if none is provided")
    {
        test_cipher_random_iv(test_key, test_plaintext);
    }
    END_IT
    
    IT("should perform encryption with a provided IV")
    {
        test_cipher_provided_iv(test_key, test_plaintext, test_iv, NULL, expected_cipher_text, expected_tag_no_aad, CIPHER_AES256_GCM);
    }
    END_IT
    
    IT("should perform encryption with a provided IV and AAD")
    {
        test_cipher_provided_iv(test_key, test_plaintext_aad, test_iv, test_aad, expected_cipher_text_aad, expected_tag_aad, CIPHER_AES256_GCM);
    }
    END_IT
    
    IT("should fail if the key is correct but the tag is wrong")
    {
        wickr_cipher_result_t *result = openssl_aes256_encrypt(test_plaintext, NULL, test_key, test_iv);
        wickr_buffer_destroy(&result->auth_tag);
        result->auth_tag = hex_char_to_buffer("f00df00df00df00df00df00df00df00d");
        
        wickr_buffer_t *decoded = openssl_aes256_decrypt(result, NULL, test_key, false);
        SHOULD_BE_NULL(decoded);
        wickr_cipher_result_destroy(&result);
    }
    END_IT
    
    IT("should fail if the decryption function is set to only accept authenticated modes and gets an unauthenticated mode")
    {
        wickr_cipher_result_t *result = openssl_aes256_encrypt(test_plaintext, NULL, test_key, test_iv);
        result->cipher = CIPHER_AES256_CTR;
        wickr_buffer_destroy(&result->auth_tag);
        
        wickr_cipher_key_t *ctr_key = wickr_cipher_key_copy(test_key);
        ctr_key->cipher = CIPHER_AES256_CTR;
        
        SHOULD_BE_NULL(openssl_aes256_decrypt(result, NULL, ctr_key, true));
        wickr_cipher_result_destroy(&result);
        wickr_cipher_key_destroy(&ctr_key);
    }
    END_IT
    
    wickr_buffer_destroy(&expected_cipher_text_aad);
    wickr_buffer_destroy(&test_plaintext_aad);
    wickr_buffer_destroy(&test_plaintext);
    wickr_buffer_destroy(&test_aad);
    wickr_cipher_key_destroy(&test_key);
    wickr_buffer_destroy(&test_iv);
    wickr_buffer_destroy(&expected_cipher_text);
    wickr_buffer_destroy(&expected_tag_no_aad);
    wickr_buffer_destroy(&expected_tag_aad);
    
}
END_DESCRIBE

DESCRIBE(openssl_ec_key_management, "openssl_suite: openssl_ec_rand_key, openssl_ec_key_import")
{
    wickr_ec_key_t *one_key = NULL;
    
    IT("should be able to generate random ec keys")
    {
        one_key = openssl_ec_rand_key(EC_CURVE_NIST_P521);
        SHOULD_NOT_BE_NULL(one_key);
        SHOULD_NOT_BE_NULL(one_key->pri_data);
        SHOULD_NOT_BE_NULL(one_key->pub_data);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(one_key->pub_data, one_key->pri_data, NULL));
        SHOULD_BE_TRUE(one_key->pri_data->length > one_key->pub_data->length);
        
        bool found_match = false;
        for (int i = 0; i < 1000; i++) {
            wickr_ec_key_t *another_key = openssl_ec_rand_key(EC_CURVE_NIST_P521);
            bool match = wickr_buffer_is_equal(another_key->pri_data, one_key->pri_data, NULL);
            if (!match) {
                match = wickr_buffer_is_equal(another_key->pub_data, one_key->pub_data, NULL);
            }
            wickr_ec_key_destroy(&another_key);
            if (match) {
                break;
            }
        }
        SHOULD_BE_FALSE(found_match);
    }
    END_IT
    
    IT("should be able to import private key buffers")
    {
        wickr_buffer_t *pri_data = wickr_buffer_copy(one_key->pri_data);
        SHOULD_NOT_BE_NULL(pri_data);
        wickr_ec_key_t *key = openssl_ec_key_import(pri_data, true);
        SHOULD_NOT_BE_NULL(key);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pri_data, key->pri_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(one_key->pub_data, key->pub_data, NULL));
        SHOULD_EQUAL(one_key->curve.identifier, key->curve.identifier);
        wickr_ec_key_destroy(&key);
        wickr_buffer_destroy(&pri_data);
    }
    END_IT
    
    IT("should be able to import public key buffers")
    {
        wickr_buffer_t *pub_data = wickr_buffer_copy(one_key->pub_data);
        SHOULD_NOT_BE_NULL(pub_data);
        wickr_ec_key_t *key = openssl_ec_key_import(pub_data, false);
        SHOULD_NOT_BE_NULL(key);
        SHOULD_BE_NULL(key->pri_data);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pub_data, key->pub_data, NULL));
        SHOULD_EQUAL(one_key->curve.identifier, key->curve.identifier);
        wickr_ec_key_destroy(&key);
        wickr_buffer_destroy(&pub_data);
    }
    END_IT
    
    wickr_ec_key_destroy(&one_key);
    
}
END_DESCRIBE

void test_ec_signature(wickr_ec_key_t *pri_key, wickr_buffer_t *test_data, wickr_digest_t digest)
{
    wickr_ecdsa_result_t *result = openssl_ec_sign(pri_key, test_data, digest);
    SHOULD_NOT_BE_NULL(result);
    SHOULD_EQUAL(digest.digest_id, result->digest_mode.digest_id);
    SHOULD_NOT_BE_NULL(result->sig_data);
    
    wickr_buffer_t *pub_data = wickr_buffer_copy(pri_key->pub_data);
    wickr_ec_key_t *pub_key = wickr_ec_key_create(pri_key->curve, pub_data, NULL);

    bool did_validate = openssl_ec_verify(result, pub_key, test_data);
    wickr_ec_key_destroy(&pub_key);
    
    SHOULD_BE_TRUE(did_validate);
    
    wickr_ec_key_t *another_key = openssl_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_buffer_destroy(&another_key->pri_data);
    SHOULD_NOT_BE_NULL(another_key);
    did_validate = openssl_ec_verify(result, another_key, test_data);
    SHOULD_BE_FALSE(did_validate);
    wickr_ec_key_destroy(&another_key);
    wickr_ecdsa_result_destroy(&result);
}

void test_ecdsa_serialization(wickr_ec_key_t *pri_key, wickr_buffer_t *test_data, wickr_digest_t digest)
{
    wickr_ecdsa_result_t *result = openssl_ec_sign(pri_key, test_data, digest);
    SHOULD_NOT_BE_NULL(result);
    
    wickr_buffer_t *ecdsa_buffer = wickr_ecdsa_result_serialize(result);
    
    SHOULD_NOT_BE_NULL(ecdsa_buffer);
    SHOULD_EQUAL(ecdsa_buffer->length, result->curve.signature_size);
    
    wickr_ecdsa_result_t *restore_ecdsa = wickr_ecdsa_result_create_from_buffer(ecdsa_buffer);
    wickr_buffer_destroy(&ecdsa_buffer);
    
    SHOULD_NOT_BE_NULL(restore_ecdsa);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(restore_ecdsa->sig_data, result->sig_data, NULL));
    wickr_ecdsa_result_destroy(&restore_ecdsa);
    wickr_ecdsa_result_destroy(&result);
}

DESCRIBE(openssl_ec_sign_verify, "openssl_suite: openssl_ec_sign openssl_ec_verify")
{
    wickr_ec_curve_t curve = EC_CURVE_NIST_P521;
    wickr_ec_key_t *key = openssl_ec_rand_key(curve);
    wickr_buffer_t *test_data = hex_char_to_buffer("522dc1f099567d07f");
    
    SHOULD_NOT_BE_NULL(key);
    SHOULD_NOT_BE_NULL(test_data);
    
    IT("should create a signature given a key and data using SHA256 digest")
    {
        test_ec_signature(key, test_data, DIGEST_SHA_256);
    }
    END_IT
    
    IT("should create a signature given a key and data using SHA384 digest")
    {
        test_ec_signature(key, test_data, DIGEST_SHA_384);
    }
    END_IT
    
    IT("should create a signature given a key and data using SHA512 digest")
    {
        test_ec_signature(key, test_data, DIGEST_SHA_512);
    }
    END_IT
    
    IT("should serialize the signature to the appropriate length, and be able to deserialize it SHA256")
    {
        test_ecdsa_serialization(key, test_data, DIGEST_SHA_256);
    }
    END_IT
    
    IT("should serialize the signature to the appropriate length, and be able to deserialize it SHA384")
    {
        test_ecdsa_serialization(key, test_data, DIGEST_SHA_384);
    }
    END_IT
    
    IT("should serialize the signature to the appropriate length, and be able to deserialize it SHA512")
    {
        test_ecdsa_serialization(key, test_data, DIGEST_SHA_512);
    }
    END_IT
    
    wickr_ec_key_destroy(&key);
    wickr_buffer_destroy(&test_data);
    
}
END_DESCRIBE

void sha_2_test(wickr_buffer_t *expected_output, const char *sample_message, wickr_digest_t digest)
{
    IT("should calculate a proper hash value")
    {
        wickr_buffer_t input_message = { strlen(sample_message), (uint8_t *)sample_message };
        wickr_buffer_t *hash = openssl_sha2(&input_message, NULL, digest);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(hash, expected_output, NULL));
        
        wickr_buffer_destroy(&hash);
    }
    END_IT
    
    IT("should produce salted hashes by appending the salt to the original input")
    {
        uint8_t half_message = strlen(sample_message) / 2;
        
        wickr_buffer_t input_message = { half_message, (uint8_t *)sample_message };
        wickr_buffer_t input_salt = { half_message, (uint8_t *)sample_message + half_message };
        
        wickr_buffer_t *hash = openssl_sha2(&input_message, &input_salt, digest);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(hash, expected_output, NULL));
        
        wickr_buffer_destroy(&hash);
    }
    END_IT
}

DESCRIBE(openssl_digest_sha256, "openssl_suite: openssl_sha2(SHA256)")
{
    /* http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf SHA256 2 Block Sample Message */
    
    wickr_buffer_t *expected_output = hex_char_to_buffer("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    
    const char *sample_message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    
    sha_2_test(expected_output, sample_message, DIGEST_SHA_256);
    
    wickr_buffer_destroy(&expected_output);
}
END_DESCRIBE

DESCRIBE(openssl_digest_sha384, "openssl_suite: openssl_sha2(SHA384)")
{
    /* http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf SHA384 2 Block Sample Message */
    
    wickr_buffer_t *expected_output = hex_char_to_buffer("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    
    const char *sample_message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    
    sha_2_test(expected_output, sample_message, DIGEST_SHA_384);
    
    wickr_buffer_destroy(&expected_output);
}
END_DESCRIBE

DESCRIBE(openssl_digest_sha512, "openssl_suite: openssl_sha2(SHA512)")
{
    /* http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf SHA512 2 Block Sample Message */
    
    wickr_buffer_t *expected_output = hex_char_to_buffer("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    
    const char *sample_message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    
    sha_2_test(expected_output, sample_message, DIGEST_SHA_512);
    
    wickr_buffer_destroy(&expected_output);
}
END_DESCRIBE

void hmac_test(wickr_buffer_t *data, wickr_buffer_t *hmac_key, wickr_digest_t digest, wickr_buffer_t *expected)
{
    wickr_buffer_t *calculated_hmac = openssl_hmac_create(data, hmac_key, digest);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(calculated_hmac, expected, NULL));
    SHOULD_BE_TRUE(openssl_hmac_verify(data, hmac_key, digest, calculated_hmac));
    wickr_buffer_destroy(&calculated_hmac);
}

DESCRIBE(openssl_hmac, "openssl_suite: openssl_hmac_create, openssl_hmac_verify")
{
    /* https://tools.ietf.org/html/rfc4231#page-4  Test Case 1 */
    
    wickr_buffer_t *hmac_key = hex_char_to_buffer("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    wickr_buffer_t *data = hex_char_to_buffer("4869205468657265");
    
    IT("should calculate hmac using sha-256 properly")
    {
        wickr_buffer_t *expected_256 = hex_char_to_buffer("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        hmac_test(data, hmac_key, DIGEST_SHA_256, expected_256);
        wickr_buffer_destroy(&expected_256);
    }
    END_IT
    
    IT("should calculate hmac using sha-384 properly")
    {
        wickr_buffer_t *expected_384 = hex_char_to_buffer("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
        hmac_test(data, hmac_key, DIGEST_SHA_384, expected_384);
        wickr_buffer_destroy(&expected_384);

    }
    END_IT
    
    IT("should calculate hmac using sha-512 properly")
    {
        wickr_buffer_t *expected_512 = hex_char_to_buffer("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        hmac_test(data, hmac_key, DIGEST_SHA_512, expected_512);
        wickr_buffer_destroy(&expected_512);
    }
    END_IT
    
    wickr_buffer_destroy(&hmac_key);
    wickr_buffer_destroy(&data);
    
}
END_DESCRIBE

void test_ecdh(wickr_ec_key_t *local_test_key, wickr_ec_key_t *peer_test_key, wickr_digest_t digest, wickr_buffer_t *expected_shared_secret, wickr_buffer_t *expected_kdf_output)
{
    SHOULD_NOT_BE_NULL(peer_test_key);
    wickr_buffer_destroy(&peer_test_key->pri_data);
    
    const wickr_kdf_algo_t *algo = wickr_hkdf_algo_for_digest(digest);
    SHOULD_NOT_BE_NULL(algo);
    
    wickr_kdf_meta_t *kdf_info = wickr_kdf_meta_create(*algo, hex_char_to_buffer("f00d"), hex_char_to_buffer("bar"));
    SHOULD_NOT_BE_NULL(kdf_info);
    
    wickr_ecdh_params_t *test_params = wickr_ecdh_params_create(local_test_key, peer_test_key, kdf_info);
    
    SHOULD_BE_TRUE(wickr_ecdh_params_are_valid(test_params));
    
    SHOULD_NOT_BE_NULL(test_params);
    
    wickr_ecdh_params_t *copy_params = wickr_ecdh_params_copy(test_params);
    
    SHOULD_NOT_BE_NULL(copy_params);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_params->kdf_info->salt, test_params->kdf_info->salt, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_params->kdf_info->info, test_params->kdf_info->info, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_params->local_key->pri_data, test_params->local_key->pri_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_params->local_key->pub_data, test_params->local_key->pub_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_params->peer_key->pub_data, test_params->peer_key->pub_data, NULL));
    SHOULD_EQUAL(copy_params->local_key->curve.identifier, test_params->local_key->curve.identifier);
    SHOULD_EQUAL(copy_params->peer_key->curve.identifier, test_params->peer_key->curve.identifier);
    SHOULD_EQUAL(copy_params->kdf_info->algo.algo_id, test_params->kdf_info->algo.algo_id);
    
    SHOULD_BE_TRUE(wickr_ecdh_params_are_valid(copy_params));

    wickr_buffer_destroy(&copy_params->local_key->pri_data);
    
    SHOULD_BE_FALSE(wickr_ecdh_params_are_valid(copy_params))
    
    wickr_ecdh_params_destroy(&copy_params);
    SHOULD_BE_NULL(copy_params);
    
    /* The expected output is the expected shared secret as input to a KDF function that performs
     a digest using a provided salt */
    wickr_buffer_t *expected_output = openssl_hkdf(expected_shared_secret, test_params->kdf_info->salt, test_params->kdf_info->info, digest);
    
    SHOULD_NOT_BE_NULL(expected_output);
    
    wickr_buffer_t *output = openssl_ecdh_gen_key(test_params);
    SHOULD_EQUAL(expected_output->length, digest.size);
    
    
    SHOULD_NOT_BE_NULL(output);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output, output, NULL));
    
    wickr_buffer_destroy(&expected_output);
    wickr_buffer_destroy(&output);
    wickr_ecdh_params_destroy(&test_params);
}

DESCRIBE(openssl_ecdh, "openssl_suite: openssl_ecdh_gen_key")
{
    /* https://tools.ietf.org/html/rfc5114 521-bit Random ECP Group */
    
    wickr_ec_key_t *dA = openssl_ec_key_import_test_key(EC_CURVE_NIST_P521, "0113f82da825735e3d97276683b2b74277bad27335ea71664af2430cc4f33459b9669ee78b3ffb9b8683015d344dcbfef6fb9af4c6c470be254516cd3c1a1fb47362");
    
    SHOULD_NOT_BE_NULL(dA);
    
    wickr_ec_key_t *dB = openssl_ec_key_import_test_key(EC_CURVE_NIST_P521, "00cee3480d8645a17d249f2776d28bae616952d1791fdb4b70f7c3378732aa1b22928448bcd1dc2496d435b01048066ebe4f72903c361b1a9dc1193dc2c9d0891b96");
    
    SHOULD_NOT_BE_NULL(dB);
    
    wickr_buffer_t *expected_shared_secret = hex_char_to_buffer("00cdea89621cfa46b132f9e4cfe2261cde2d4368eb5656634c7cc98c7a00cde54ed1866a0dd3e6126c9d2f845daff82ceb1da08f5d87521bb0ebeca77911169c20cc");
    
    SHOULD_NOT_BE_NULL(expected_shared_secret);
    
    wickr_buffer_t *expected_256_output = hex_char_to_buffer("95640c1817115db83b9d9a2f56c29fcca8a05cc787a95a9055e9b1b6a03a8478");
    wickr_buffer_t *expected_384_output = hex_char_to_buffer("54b8bab40639df5561bc53fdd31ec56ad0e4e5b6dadd89e3d4e70f373ce647dfabefe51a9ee9be10a25e772e3758ff2e");
    wickr_buffer_t *expected_512_output = hex_char_to_buffer("fe4178413af02bbbb11f93fd8cbc65b71faa6ff9f33ef49c0da49c33bc73277b0578813f5c3a54e9909ac5dc803dad2a01da3aec371c67b683638d9f7ee0b247");
    
    IT("should make a proper 256bit shared secret (A is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dA);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dB);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_256, expected_shared_secret, expected_256_output);
    }
    END_IT
    
    IT("should make a proper 256bit shared secret (B is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dB);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dA);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_256, expected_shared_secret, expected_256_output);
    }
    END_IT
    
    IT("should make a proper 384bit shared secret (A is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dA);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dB);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_384, expected_shared_secret, expected_384_output);
    }
    END_IT
    
    IT("should make a proper 384bit shared secret (B is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dB);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dA);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_384, expected_shared_secret, expected_384_output);
    }
    END_IT
    
    IT("should make a proper 512bit shared secret (A is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dA);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dB);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_512, expected_shared_secret, expected_512_output);
    }
    END_IT
    
    IT("should make a proper 512bit shared secret (B is local)")
    {
        wickr_ec_key_t *local_test_key = wickr_ec_key_copy(dB);
        wickr_ec_key_t *peer_test_key = wickr_ec_key_copy(dA);
        
        test_ecdh(local_test_key, peer_test_key, DIGEST_SHA_512, expected_shared_secret, expected_512_output);
    }
    END_IT
    
    wickr_buffer_destroy(&expected_256_output);
    wickr_buffer_destroy(&expected_384_output);
    wickr_buffer_destroy(&expected_512_output);
    wickr_ec_key_destroy(&dA);
    wickr_ec_key_destroy(&dB);
    wickr_buffer_destroy(&expected_shared_secret);
    
}
END_DESCRIBE

DESCRIBE(openssl_hkdf, "openssl_suite: openssl_hkdf")
{
    IT("should fail if no key material is provided")
    {
        SHOULD_BE_NULL(openssl_hkdf(NULL, NULL, NULL, DIGEST_SHA_256));
    }
    END_IT
    
    IT("should calculate hkdf with salt and info data")
    {
        wickr_buffer_t *initial_key_material = hex_char_to_buffer("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        wickr_buffer_t *salt = hex_char_to_buffer("000102030405060708090a0b0c");
        wickr_buffer_t *info = hex_char_to_buffer("f0f1f2f3f4f5f6f7f8f9");
        
        wickr_digest_t sha_256_42_len = DIGEST_SHA_256;
        sha_256_42_len.size = 42;
        
        wickr_digest_t sha_512_42_len = DIGEST_SHA_512;
        sha_512_42_len.size = 42;
        
        wickr_buffer_t *output_256 = openssl_hkdf(initial_key_material, salt, info, sha_256_42_len);
        wickr_buffer_t *output_512 = openssl_hkdf(initial_key_material, salt, info, sha_512_42_len);
        
        wickr_buffer_t *expected_output_256 = hex_char_to_buffer("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        wickr_buffer_t *expected_output_512 = hex_char_to_buffer("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb");
        
        SHOULD_NOT_BE_NULL(output_256);
        SHOULD_NOT_BE_NULL(output_512);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_256, output_256, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_512, output_512, NULL));
        
        wickr_buffer_destroy(&initial_key_material);
        wickr_buffer_destroy(&salt);
        wickr_buffer_destroy(&info);
        wickr_buffer_destroy(&output_256);
        wickr_buffer_destroy(&output_512);
        wickr_buffer_destroy(&expected_output_256);
        wickr_buffer_destroy(&expected_output_512);
    }
    END_IT
    
    IT("should calculate hkdf with longer inputs and outputs")
    {
        wickr_buffer_t *initial_key_material = hex_char_to_buffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        wickr_buffer_t *salt = hex_char_to_buffer("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        wickr_buffer_t *info = hex_char_to_buffer("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        
        wickr_digest_t sha_256_82_len = DIGEST_SHA_256;
        sha_256_82_len.size = 82;
        
        wickr_digest_t sha_512_82_len = DIGEST_SHA_512;
        sha_512_82_len.size = 82;
        
        wickr_buffer_t *output_256 = openssl_hkdf(initial_key_material, salt, info, sha_256_82_len);
        wickr_buffer_t *output_512 = openssl_hkdf(initial_key_material, salt, info, sha_512_82_len);

        wickr_buffer_t *expected_output_256 = hex_char_to_buffer("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
        
        wickr_buffer_t *expected_output_512 = hex_char_to_buffer("ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93");
        
        SHOULD_NOT_BE_NULL(output_256);
        SHOULD_NOT_BE_NULL(output_512);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_256, output_256, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_512, output_512, NULL));

        wickr_buffer_destroy(&initial_key_material);
        wickr_buffer_destroy(&salt);
        wickr_buffer_destroy(&info);
        wickr_buffer_destroy(&output_256);
        wickr_buffer_destroy(&expected_output_256);
        wickr_buffer_destroy(&output_512);
        wickr_buffer_destroy(&expected_output_512);
    }
    END_IT
    
    IT("should calculate hkdf with zero length salt and info")
    {
        wickr_buffer_t *initial_key_material = hex_char_to_buffer("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        
        wickr_digest_t sha_256_42_len = DIGEST_SHA_256;
        sha_256_42_len.size = 42;
        
        wickr_digest_t sha_512_42_len = DIGEST_SHA_512;
        sha_512_42_len.size = 42;
        
        wickr_buffer_t *output_256 = openssl_hkdf(initial_key_material, NULL, NULL, sha_256_42_len);
        wickr_buffer_t *output_512 = openssl_hkdf(initial_key_material, NULL, NULL, sha_512_42_len);
        
        
        wickr_buffer_t *expected_output_256 = hex_char_to_buffer("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
        wickr_buffer_t *expected_output_512 = hex_char_to_buffer("f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac");
        
        SHOULD_NOT_BE_NULL(output_256);
        SHOULD_NOT_BE_NULL(output_512);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_256, output_256, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_output_512, output_512, NULL));

        wickr_buffer_destroy(&initial_key_material);
        wickr_buffer_destroy(&output_256);
        wickr_buffer_destroy(&expected_output_256);
        wickr_buffer_destroy(&output_512);
        wickr_buffer_destroy(&expected_output_512);
    }
    END_IT
}
END_DESCRIBE
