
#include "test_ecdh_cipher.h"
#include "ecdh_cipher_ctx.h"
#include "openssl_suite.h"
#include "externs.h"

DESCRIBE(wickr_ecdh_cipher, "ecdh cipher context")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    
    IT("can be created with a random key")
    {
        wickr_ecdh_cipher_ctx_t *ctx_a = wickr_ecdh_cipher_ctx_create(test_engine, EC_CURVE_NIST_P521, CIPHER_AES256_GCM);
        SHOULD_NOT_BE_NULL(ctx_a);
        SHOULD_EQUAL(ctx_a->local_key->curve.identifier, EC_CURVE_NIST_P521.identifier);
        SHOULD_EQUAL(ctx_a->cipher.cipher_id, CIPHER_AES256_GCM.cipher_id);
        
        wickr_ecdh_cipher_ctx_t *ctx_b = wickr_ecdh_cipher_ctx_create(test_engine, EC_CURVE_NIST_P521, CIPHER_AES256_GCM);
        SHOULD_NOT_BE_NULL(ctx_b);
        SHOULD_EQUAL(ctx_b->local_key->curve.identifier, EC_CURVE_NIST_P521.identifier);
        SHOULD_EQUAL(ctx_b->cipher.cipher_id, CIPHER_AES256_GCM.cipher_id);

        SHOULD_BE_FALSE(wickr_buffer_is_equal(ctx_a->local_key->pub_data, ctx_b->local_key->pub_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(ctx_a->local_key->pri_data, ctx_b->local_key->pri_data, NULL));
        
        wickr_ecdh_cipher_ctx_destroy(&ctx_a);
        wickr_ecdh_cipher_ctx_destroy(&ctx_b);
    }
    END_IT
    
    wickr_ec_key_t *dA = openssl_ec_key_import_test_key(EC_CURVE_NIST_P521, "0113f82da825735e3d97276683b2b74277bad27335ea71664af2430cc4f33459b9669ee78b3ffb9b8683015d344dcbfef6fb9af4c6c470be254516cd3c1a1fb47362");
    
    SHOULD_NOT_BE_NULL(dA);
    
    wickr_ec_key_t *dB = openssl_ec_key_import_test_key(EC_CURVE_NIST_P521, "00cee3480d8645a17d249f2776d28bae616952d1791fdb4b70f7c3378732aa1b22928448bcd1dc2496d435b01048066ebe4f72903c361b1a9dc1193dc2c9d0891b96");
    
    SHOULD_NOT_BE_NULL(dB);
    
    wickr_ecdh_cipher_ctx_t *test_ctx = NULL;
    
    IT("can be created with an existing key")
    {
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_create_key(test_engine, NULL, CIPHER_AES256_GCM));
        test_ctx = wickr_ecdh_cipher_ctx_create_key(test_engine, dA, CIPHER_AES256_GCM);
        
        SHOULD_NOT_BE_NULL(test_ctx);
        SHOULD_EQUAL(test_ctx->local_key, dA);
        SHOULD_EQUAL(CIPHER_AES256_GCM.cipher_id, test_ctx->cipher.cipher_id);
    }
    END_IT
    
    IT("can be copied")
    {
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_copy(NULL));
        
        wickr_ecdh_cipher_ctx_t *copy = wickr_ecdh_cipher_ctx_copy(test_ctx);
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_ctx->local_key->pri_data, copy->local_key->pri_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_ctx->local_key->pub_data, copy->local_key->pub_data, NULL));
        SHOULD_EQUAL(test_ctx->cipher.cipher_id, copy->cipher.cipher_id);
        
        wickr_ecdh_cipher_ctx_destroy(&copy);
    }
    END_IT
    
    wickr_buffer_t *test_plaintext = test_engine.wickr_crypto_engine_crypto_random(32);
    SHOULD_NOT_BE_NULL(test_plaintext);
    
    wickr_kdf_meta_t *test_kdf_meta = wickr_kdf_meta_create(KDF_HKDF_SHA256,
                                                            hex_char_to_buffer("f00d"),
                                                            hex_char_to_buffer("bar"));
    SHOULD_NOT_BE_NULL(test_kdf_meta);
    
    wickr_cipher_key_t *expected_key = wickr_cipher_key_create(CIPHER_AES256_GCM, hex_char_to_buffer("95640c1817115db83b9d9a2f56c29fcca8a05cc787a95a9055e9b1b6a03a8478"));
	wickr_cipher_key_t *expected_large_key = wickr_cipher_key_create(CIPHER_AES256_GCM, hex_char_to_buffer("fe4178413af02bbbb11f93fd8cbc65b71faa6ff9f33ef49c0da49c33bc73277b"));

    SHOULD_NOT_BE_NULL(expected_key);
    
    wickr_cipher_result_t *test_cipher_result = NULL;
    
    IT("can be used to cipher data")
    {
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_cipher(NULL, NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_cipher(test_ctx, NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_cipher(test_ctx, test_plaintext, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_cipher(test_ctx, test_plaintext, dB, NULL));

        test_cipher_result = wickr_ecdh_cipher_ctx_cipher(test_ctx, test_plaintext, dB, test_kdf_meta);
        SHOULD_NOT_BE_NULL(test_cipher_result);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_plaintext, test_cipher_result->cipher_text, NULL));
        
        /* The bytes that are output should be decodable with the expected key bytes
           the expected key bytes were pre-computed to be the shared secret of dA pub + dA pri + dB pub
           passed through HKDF with SHA256 with salt of hex bytes f00d and info bytes bar */
        wickr_buffer_t *test_decode = test_engine.wickr_crypto_engine_cipher_decrypt(test_cipher_result, NULL, expected_key, NULL);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_decode, test_plaintext, NULL));
        
        wickr_buffer_destroy(&test_decode);
    }
    END_IT

	IT("can use a KDF with a larger output than the desired cipher key length")
	{
		wickr_kdf_meta_t *test_kdf_meta_large = wickr_kdf_meta_create(KDF_HKDF_SHA512, 
			hex_char_to_buffer("f00d"),
			hex_char_to_buffer("bar"));
		SHOULD_NOT_BE_NULL(test_kdf_meta_large);

		wickr_cipher_result_t *large_cipher_result = wickr_ecdh_cipher_ctx_cipher(test_ctx, test_plaintext, dB, test_kdf_meta_large);
		SHOULD_NOT_BE_NULL(large_cipher_result);

		/* The bytes that are output should be decodable with the expected key bytes
		the expected key bytes were pre-computed to be the shared secret of dA pub + dA pri + dB pub
		passed through HKDF with SHA512 with salt of hex bytes f00d and info bytes bar truncated to 32 bytes */
		wickr_buffer_t *test_decode = test_engine.wickr_crypto_engine_cipher_decrypt(large_cipher_result, NULL, expected_large_key, NULL);
		SHOULD_BE_TRUE(wickr_buffer_is_equal(test_decode, test_plaintext, NULL));

		wickr_buffer_destroy(&test_decode);
		wickr_kdf_meta_destroy(&test_kdf_meta_large);
		wickr_cipher_result_destroy(&large_cipher_result);
	}
	END_IT
    
    IT("should fail to decipher if parameters are missing")
    {
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(NULL, NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, NULL, NULL));
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, NULL));
    }
    END_IT
    
    IT("should fail to decipher if the key is incorrect")
    {
        wickr_ec_key_t *incorrect_key = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        SHOULD_NOT_BE_NULL(incorrect_key);
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, incorrect_key, test_kdf_meta));
        wickr_ec_key_destroy(&incorrect_key);
    }
    END_IT
    
    IT("should fail to decipher if the cipher mode is manipulated in transit")
    {
        test_cipher_result->cipher = CIPHER_AES256_CTR;
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, test_kdf_meta));
        test_cipher_result->cipher = CIPHER_AES256_GCM;
    }
    END_IT
    
    IT("should fail to decipher if the kdf information is incorrect")
    {
        wickr_kdf_meta_t *incorrect_kdf = wickr_kdf_meta_copy(test_kdf_meta);
        SHOULD_NOT_BE_NULL(incorrect_kdf);
        
        incorrect_kdf->algo = KDF_HKDF_SHA512;
        incorrect_kdf->algo.output_size = test_cipher_result->cipher.key_len;
        
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, incorrect_kdf));
        
        wickr_kdf_meta_destroy(&incorrect_kdf);
        incorrect_kdf = wickr_kdf_meta_copy(test_kdf_meta);
        SHOULD_NOT_BE_NULL(incorrect_kdf);
        wickr_buffer_destroy(&incorrect_kdf->info);
        incorrect_kdf->info = test_engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(incorrect_kdf->info);

        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, incorrect_kdf));

        wickr_kdf_meta_destroy(&incorrect_kdf);
        incorrect_kdf = wickr_kdf_meta_copy(test_kdf_meta);
        SHOULD_NOT_BE_NULL(incorrect_kdf);
        wickr_buffer_destroy(&incorrect_kdf->salt);
        incorrect_kdf->salt = test_engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(incorrect_kdf->salt);
        
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, incorrect_kdf));

        wickr_kdf_meta_destroy(&incorrect_kdf);
    }
    END_IT
    
    IT("should properly decipher if the key and kdf are correct")
    {
        wickr_buffer_t *test_decode = wickr_ecdh_cipher_ctx_decipher(test_ctx, test_cipher_result, dB, test_kdf_meta);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_decode, test_plaintext, NULL));
        
        wickr_buffer_destroy(&test_decode);
    }
    END_IT
    
    wickr_ec_key_destroy(&dB);
    wickr_cipher_result_destroy(&test_cipher_result);
    wickr_kdf_meta_destroy(&test_kdf_meta);
    wickr_buffer_destroy(&test_plaintext);
    wickr_cipher_key_destroy(&expected_key);
	wickr_cipher_key_destroy(&expected_large_key);
    wickr_ecdh_cipher_ctx_destroy(&test_ctx);
    SHOULD_BE_NULL(test_ctx);
}
END_DESCRIBE

DESCRIBE(wickr_ecdh_cipher_e2e_test, "ecdh cipher end to end test")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();

    wickr_ec_key_t *alice_key_private = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    SHOULD_NOT_BE_NULL(alice_key_private);
    
    wickr_ec_key_t *bob_key_private = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    SHOULD_NOT_BE_NULL(bob_key_private);
    
    wickr_ec_key_t *alice_key_public = wickr_ec_key_copy(alice_key_private);
    wickr_buffer_destroy_zero(&alice_key_public->pri_data);
    SHOULD_NOT_BE_NULL(alice_key_public);
    SHOULD_BE_NULL(alice_key_public->pri_data);
    
    wickr_ec_key_t *bob_key_public = wickr_ec_key_copy(bob_key_private);
    wickr_buffer_destroy_zero(&bob_key_public->pri_data);
    SHOULD_NOT_BE_NULL(bob_key_public);
    SHOULD_BE_NULL(bob_key_public->pri_data);
    
    wickr_buffer_t *test_plaintext = test_engine.wickr_crypto_engine_crypto_random(32);
    SHOULD_NOT_BE_NULL(test_plaintext);
    
    wickr_kdf_meta_t *test_kdf_meta = wickr_kdf_meta_create(KDF_HKDF_SHA256,
                                                            hex_char_to_buffer("f00d"),
                                                            hex_char_to_buffer("bar"));
    SHOULD_NOT_BE_NULL(test_kdf_meta);
    
    IT("can exchange data securely between parties without private keys being transferred")
    {
        wickr_ecdh_cipher_ctx_t *alice_ctx = wickr_ecdh_cipher_ctx_create_key(test_engine,
                                                                              alice_key_private,
                                                                              CIPHER_AES256_GCM);
        
        wickr_ecdh_cipher_ctx_t *bob_ctx = wickr_ecdh_cipher_ctx_create_key(test_engine,
                                                                            bob_key_private,
                                                                            CIPHER_AES256_GCM);
        
        SHOULD_NOT_BE_NULL(alice_ctx);
        SHOULD_NOT_BE_NULL(bob_ctx);
        
        wickr_cipher_result_t *ciphered = wickr_ecdh_cipher_ctx_cipher(alice_ctx, test_plaintext,
                                                                       bob_key_public, test_kdf_meta);
        
        SHOULD_NOT_BE_NULL(ciphered);
        
        wickr_ec_key_t *incorrect_key = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        SHOULD_NOT_BE_NULL(incorrect_key);
        
        SHOULD_BE_NULL(wickr_ecdh_cipher_ctx_decipher(bob_ctx, ciphered, incorrect_key, test_kdf_meta));
        
        wickr_buffer_t *deciphered = wickr_ecdh_cipher_ctx_decipher(bob_ctx, ciphered,
                                                                    alice_key_public, test_kdf_meta);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deciphered, test_plaintext, NULL));
        
        wickr_cipher_result_destroy(&ciphered);
        wickr_ec_key_destroy(&incorrect_key);
        wickr_buffer_destroy(&deciphered);
        wickr_ecdh_cipher_ctx_destroy(&alice_ctx);
        wickr_ecdh_cipher_ctx_destroy(&bob_ctx);
    }
    END_IT
    
    wickr_ec_key_destroy(&alice_key_public);
    wickr_ec_key_destroy(&bob_key_public);
    wickr_buffer_destroy(&test_plaintext);
    wickr_kdf_meta_destroy(&test_kdf_meta);
}
END_DESCRIBE
