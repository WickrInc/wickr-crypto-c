
#include "test_kdf.h"
#include "kdf.h"
#include <string.h>
#include <stdio.h>
#include "util.h"
#include "crypto_engine.h"

static uint8_t one_byte = 0x0;
static wickr_buffer_t one_byte_buffer = { 1, &one_byte };

void test_kdf_algo_equality(wickr_kdf_algo_t a1, wickr_kdf_algo_t a2)
{
    SHOULD_EQUAL(a1.algo_id, a2.algo_id);
    SHOULD_EQUAL(a1.cost, a2.cost);
    SHOULD_EQUAL(a1.kdf_id, a2.kdf_id);
    SHOULD_EQUAL(a1.output_size, a2.output_size);
    SHOULD_EQUAL(a1.salt_size, a2.salt_size);
}

void test_kdf_meta_equality(wickr_kdf_meta_t *m1, wickr_kdf_meta_t *m2)
{
    SHOULD_BE_TRUE(wickr_buffer_is_equal(m1->salt, m2->salt, NULL));
    test_kdf_algo_equality(m1->algo, m2->algo);
}

DESCRIBE(wickr_kdf_meta, "kdf.c: wickr_kdf_meta")
{
    
    IT("can't be created if a salt is missing or the wrong size")
    {
        SHOULD_BE_NULL(wickr_kdf_meta_create(KDF_SCRYPT_2_17, NULL, NULL));
        SHOULD_BE_NULL(wickr_kdf_meta_create(KDF_SCRYPT_2_17, &one_byte_buffer, NULL));
        SHOULD_BE_NULL(wickr_kdf_meta_create(KDF_HKDF_SHA256, NULL, NULL));
    }
    END_IT
    
    IT("should allow HKDF without a salt and with info")
    {
        wickr_buffer_t *info_buffer = wickr_buffer_create_empty(KDF_SCRYPT_2_17.salt_size);
        wickr_kdf_meta_t *test = wickr_kdf_meta_create(KDF_HKDF_SHA256, NULL, info_buffer);
        SHOULD_NOT_BE_NULL(test);
        wickr_kdf_meta_destroy(&test);
    }
    END_IT
    
    wickr_kdf_meta_t *test_meta = NULL;
    
    IT("can be created given an algorithm and a salt")
    {
        wickr_buffer_t *salt_buffer = wickr_buffer_create_empty(KDF_SCRYPT_2_17.salt_size);
        test_meta = wickr_kdf_meta_create(KDF_SCRYPT_2_17, salt_buffer, NULL);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(salt_buffer, test_meta->salt, NULL));
        test_kdf_algo_equality(test_meta->algo, KDF_SCRYPT_2_17);
        SHOULD_NOT_BE_NULL(test_meta);
    }
    END_IT
    
    IT("can be serialized into a buffer and deserialized back into a struct")
    {
        wickr_buffer_t *test_serialization = wickr_kdf_meta_serialize(test_meta);
        SHOULD_NOT_BE_NULL(test_serialization);
        SHOULD_EQUAL(test_serialization->length, KDF_SCRYPT_2_17.salt_size + sizeof(uint8_t));
        
        wickr_kdf_meta_t *test_deserialize = wickr_kdf_meta_create_with_buffer(test_serialization);
        SHOULD_NOT_BE_NULL(test_deserialize);
        test_kdf_meta_equality(test_meta, test_deserialize);
        wickr_buffer_destroy(&test_serialization);
        wickr_kdf_meta_destroy(&test_deserialize);
    }
    END_IT
    
    IT("can't be serialized into a buffer if HKDF and no salt was used")
    {
        wickr_buffer_t *info_buffer = wickr_buffer_create_empty(KDF_SCRYPT_2_17.salt_size);
        wickr_kdf_meta_t *test = wickr_kdf_meta_create(KDF_HKDF_SHA256, NULL, info_buffer);
        SHOULD_BE_NULL(wickr_kdf_meta_serialize(test));
        SHOULD_NOT_BE_NULL(test);
        wickr_kdf_meta_destroy(&test);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_kdf_meta_t *copy_test_meta = wickr_kdf_meta_copy(test_meta);
        SHOULD_NOT_BE_NULL(copy_test_meta);
        test_kdf_meta_equality(copy_test_meta, test_meta);
        wickr_kdf_meta_destroy(&copy_test_meta);
    }
    END_IT
    
    wickr_kdf_meta_destroy(&test_meta);
    SHOULD_BE_NULL(test_meta);
}
END_DESCRIBE

void test_kdf_result_equality(wickr_kdf_result_t *r1, wickr_kdf_result_t *r2)
{
    SHOULD_BE_TRUE(wickr_buffer_is_equal(r1->hash, r2->hash, NULL));
    test_kdf_meta_equality(r1->meta, r2->meta);
}

DESCRIBE(wickr_kdf_result, "kdf.c: wickr_kdf_result")
{
    wickr_kdf_result_t *test_result = NULL;
    
    IT("can't be created unless it has a valid meta and hash")
    {
        wickr_buffer_t *test_salt = wickr_buffer_create_empty(KDF_SCRYPT_2_17.salt_size);
        wickr_kdf_meta_t *test_meta = wickr_kdf_meta_create(KDF_SCRYPT_2_17, test_salt, NULL);
        SHOULD_BE_NULL(wickr_kdf_result_create(NULL, &one_byte_buffer));
        SHOULD_BE_NULL(wickr_kdf_result_create(test_meta, NULL));
        
        wickr_buffer_t *test_hash = wickr_buffer_create_empty(KDF_SCRYPT_2_17.output_size);
        test_result = wickr_kdf_result_create(test_meta, test_hash);
        test_kdf_meta_equality(test_result->meta, test_meta);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_result->hash, test_hash, NULL));
        SHOULD_NOT_BE_NULL(test_result);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_kdf_result_t *copied_result = wickr_kdf_result_copy(test_result);
        SHOULD_NOT_BE_NULL(copied_result);
        test_kdf_result_equality(copied_result, test_result);
        wickr_kdf_result_destroy(&copied_result);
    }
    END_IT
    
    wickr_kdf_result_destroy(&test_result);
    SHOULD_BE_NULL(test_result);
}
END_DESCRIBE

struct kdf_test_vector
{
    wickr_kdf_algo_t algo;
    const char *algo_name;
    wickr_buffer_t *salt;
    wickr_buffer_t *info;
    wickr_buffer_t *passphrase;
    wickr_buffer_t *expected_out;
};

typedef struct kdf_test_vector kdf_test_vector_t;

DESCRIBE(wickr_perform_kdf, "kdf.c: wickr_perform_kdf, wickr_perform_kdf_meta")
{
    char *test_bcrypt_salt = "qqM9HeaGheyCy99QtDm0kO";
    
    kdf_test_vector_t test_vectors[8] =
    {
        { KDF_SCRYPT_2_17,
            "KDF_SCRIPT_2_17",
            hex_char_to_buffer("31323334353637383930616263646566"),
            NULL,
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("1add828da5c436e578b458a59619081e273b58b06b99ff5b363c88fc3246a948")
        },
        { KDF_SCRYPT_2_18,
            "KDF_SCRIPT_2_18",
            hex_char_to_buffer("31323334353637383930616263646566"),
            NULL,
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("63c7c9f4cc120c7750b6318aa4945df80d9d7f02cd5d4ac51b7bfe3bd2730b0f")
        },
        { KDF_SCRYPT_2_19,
            "KDF_SCRIPT_2_19",
            hex_char_to_buffer("31323334353637383930616263646566"),
            NULL,
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("88947413b203f3ef7a8ef14a4f80bbd3c44880b5f54790dd5c1731d73f4ac89b")
        },
        { KDF_SCRYPT_2_20,
            "KDF_SCRIPT_2_20",
            hex_char_to_buffer("31323334353637383930616263646566"),
            NULL,
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("f77171051a2b7bd32a377cb81c83a40d2ee1965e9a77978ec29cd06196707097")
        },
        { KDF_BCRYPT_15,
            "KDF_BCRYPT_15",
            wickr_buffer_create((uint8_t *)test_bcrypt_salt, strlen(test_bcrypt_salt)) ,
            NULL,
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("2432792431352471714d3948656147686579437939395174446d306b4f334b654c65637863656c304a7861664c4e415338716a766f6b336172616575")
        },
        { KDF_HKDF_SHA256,
            "KDF_HKDF_SHA256",
            hex_char_to_buffer("3132333435363738393061626364656631323334353637383930616263646566"),
            hex_char_to_buffer("1234"),
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("03fe9d71dddff316b108f0293211c04e54d60df66bad0971a035afaf2e0230de")
        },
        { KDF_HKDF_SHA384,
            "KDF_HKDF_SHA384",
            hex_char_to_buffer("313233343536373839306162636465663132333435363738393061626364656631323334353637383930616263646566"),
            hex_char_to_buffer("1234"),
            hex_char_to_buffer("70617373776f7264"),
            hex_char_to_buffer("81e0c1d469c2cf1df6ea9a442ffe94c88df7b1789033fa8f1a970064312796f758770b5771aedc0cbb190ecdf05cd949")
        },
        { KDF_HKDF_SHA512,
            "KDF_HKDF_SHA512",
        hex_char_to_buffer("31323334353637383930616263646566313233343536373839306162636465663132333435363738393061626364656631323334353637383930616263646566"),
            hex_char_to_buffer("1234"),
            hex_char_to_buffer("70617373776f7264"),
        hex_char_to_buffer("40dae76d651610413f4d03fdcab9ea0ea4d6213997b81be43de7fc0b642ab474a10cea8f6edabcce99ac0bc8663ddf622d2fed40d8972a00fd8e4d1c80008c86")
        }
    };
    
    
    for (int i = 0; i < 8; i++) {
        
        char it_statement[1024];
        sprintf( it_statement, "should calculare proper hashes given specific known metadata: %s", test_vectors[i].algo_name );
        
        IT(it_statement)
        {
            wickr_kdf_meta_t *meta = wickr_kdf_meta_create(test_vectors[i].algo, wickr_buffer_copy(test_vectors[i].salt), wickr_buffer_copy(test_vectors[i].info));
            
            SHOULD_NOT_BE_NULL(meta);
            
            
            wickr_kdf_result_t *kdf_result = wickr_perform_kdf_meta(meta, test_vectors[i].passphrase);

            wickr_kdf_result_t expected_result;
            expected_result.meta = meta;
            expected_result.hash =  wickr_buffer_copy(test_vectors[i].expected_out);
            
            test_kdf_result_equality(kdf_result, &expected_result);
            
            wickr_kdf_result_destroy(&kdf_result);
            wickr_buffer_destroy(&expected_result.hash);
            wickr_kdf_meta_destroy(&expected_result.meta);

        }
        END_IT
        
        if (test_vectors[i].algo.algo_id == KDF_HMAC_SHA2) {
            
            sprintf( it_statement, "should get different output if salt or info is left out: %s", test_vectors[i].algo_name );
            
            IT(it_statement)
            {
                wickr_kdf_meta_t *meta_no_info = wickr_kdf_meta_create(test_vectors[i].algo, wickr_buffer_copy(test_vectors[i].salt), NULL);
                SHOULD_NOT_BE_NULL(meta_no_info);
                
                wickr_kdf_meta_t *meta_no_salt = wickr_kdf_meta_create(test_vectors[i].algo, NULL, wickr_buffer_copy(test_vectors[i].info));
                SHOULD_NOT_BE_NULL(meta_no_salt);
                
                wickr_kdf_result_t *kdf_result_no_info = wickr_perform_kdf_meta(meta_no_info, test_vectors[i].passphrase);
                wickr_kdf_result_t *kdf_result_no_salt = wickr_perform_kdf_meta(meta_no_salt, test_vectors[i].passphrase);
                
                SHOULD_BE_FALSE(wickr_buffer_is_equal(test_vectors[i].expected_out, kdf_result_no_info->hash, NULL));
                SHOULD_BE_FALSE(wickr_buffer_is_equal(test_vectors[i].expected_out, kdf_result_no_salt->hash, NULL));
                SHOULD_BE_FALSE(wickr_buffer_is_equal(kdf_result_no_salt->hash, kdf_result_no_info->hash, NULL));

                wickr_kdf_result_destroy(&kdf_result_no_info);
                wickr_kdf_meta_destroy(&meta_no_info);
                
                wickr_kdf_result_destroy(&kdf_result_no_salt);
                wickr_kdf_meta_destroy(&meta_no_salt);
            }
            END_IT
            
            sprintf( it_statement, "should allow you to get smaller output: %s", test_vectors[i].algo_name );
            
            IT(it_statement)
            {
                wickr_kdf_algo_t algo = test_vectors[i].algo;
                algo.output_size = test_vectors[i].algo.output_size / 2;
                
                wickr_kdf_meta_t *meta = wickr_kdf_meta_create(algo, wickr_buffer_copy(test_vectors[i].salt), wickr_buffer_copy(test_vectors[i].info));
                SHOULD_NOT_BE_NULL(meta);
                
                wickr_kdf_result_t *kdf_result = wickr_perform_kdf_meta(meta, test_vectors[i].passphrase);

                wickr_kdf_result_t expected_result;
                expected_result.meta = meta;
                expected_result.hash =  wickr_buffer_copy(test_vectors[i].expected_out);
                expected_result.hash->length = expected_result.hash->length / 2;
                
                test_kdf_result_equality(kdf_result, &expected_result);
                
                wickr_kdf_result_destroy(&kdf_result);
                wickr_buffer_destroy(&expected_result.hash);
                wickr_kdf_meta_destroy(&expected_result.meta);
            }
            END_IT
            
            sprintf( it_statement, "should allow you to get larger output: %s", test_vectors[i].algo_name );
            
        }
        
        sprintf( it_statement, "should make hashes with random salts: %s", test_vectors[i].algo_name );
        
        IT(it_statement)
        {
            wickr_kdf_result_t *result_1 = wickr_perform_kdf(test_vectors[i].algo, test_vectors[i].passphrase);
            wickr_kdf_result_t *result_2 = wickr_perform_kdf(test_vectors[i].algo, test_vectors[i].passphrase);
            SHOULD_NOT_BE_NULL(result_1);
            SHOULD_NOT_BE_NULL(result_2);
			if (result_1 != NULL && result_2 != NULL) {
				SHOULD_BE_FALSE(wickr_buffer_is_equal(result_1->hash, result_2->hash, NULL));
				SHOULD_BE_FALSE(wickr_buffer_is_equal(result_1->meta->salt, result_2->meta->salt, NULL));
				wickr_kdf_result_destroy(&result_1);
				wickr_kdf_result_destroy(&result_2);
			}
        }
        END_IT
        
        wickr_buffer_destroy(&test_vectors[i].expected_out);
        wickr_buffer_destroy(&test_vectors[i].passphrase);
        wickr_buffer_destroy(&test_vectors[i].salt);
        wickr_buffer_destroy(&test_vectors[i].info);
    }

    
    
}
END_DESCRIBE

DESCRIBE(wickr_crypto_engine_kdf, "wickr_crypto_engine.c : wickr_crypto_engine_kdf_cipher / decipher")
{
    
    wickr_kdf_algo_t kdf_algos_to_test[4] = { KDF_SCRYPT_2_17, KDF_SCRYPT_2_18, KDF_SCRYPT_2_19, KDF_SCRYPT_2_20 };
    wickr_cipher_t ciphers_to_test[1] = { CIPHER_AES256_GCM };
    
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();

    uint8_t zero = 0;
    wickr_buffer_t one_byte;
    one_byte.bytes = &zero;
    one_byte.length = sizeof(uint8_t);
    
    IT("should not cipher with bcrypt")
    {
        SHOULD_BE_NULL(wickr_crypto_engine_kdf_cipher(&default_engine, KDF_BCRYPT_15, CIPHER_AES256_GCM, &one_byte, &one_byte));
    }
    END_IT
    
    IT("should not cipher with unauthenticated aes modes")
    {
        SHOULD_BE_NULL(wickr_crypto_engine_kdf_cipher(&default_engine, KDF_BCRYPT_15, CIPHER_AES256_CTR, &one_byte, &one_byte))
    }
    END_IT
    
    IT("should not cipher if it is missing an engine")
    {
        SHOULD_BE_NULL(wickr_crypto_engine_kdf_cipher(NULL, KDF_SCRYPT_2_17, CIPHER_AES256_GCM, &one_byte, &one_byte));
    }
    END_IT
    
    IT("should not cipher if it is missing input data")
    {
        SHOULD_BE_NULL(wickr_crypto_engine_kdf_cipher(&default_engine, KDF_SCRYPT_2_17, CIPHER_AES256_GCM, NULL, &one_byte));
    }
    END_IT
    
    IT("should not cipher if it is missing a passphrase")
    {
        SHOULD_BE_NULL(wickr_crypto_engine_kdf_cipher(&default_engine, KDF_SCRYPT_2_17, CIPHER_AES256_GCM, &one_byte, NULL));
    }
    END_IT
    
    for (int i = 0; i < 4; i++) {
        
        for (int j = 0; j < 1; j++) {
            
            char it_statement[1024];
            
            
            wickr_buffer_t *test_data = default_engine.wickr_crypto_engine_crypto_random(1024);
            wickr_buffer_t *test_passphrase = default_engine.wickr_crypto_engine_crypto_random(8);
            wickr_buffer_t *incorrect_passphrase = default_engine.wickr_crypto_engine_crypto_random(8);
            wickr_kdf_algo_t test_algo = kdf_algos_to_test[i];
            wickr_cipher_t cipher_algo = ciphers_to_test[j];
            
            wickr_buffer_t *cipher_output = NULL;
            
            sprintf( it_statement, "should cipher / decipher data given the correct passphrase %i %i", i, j );
            
            IT("should cipher / decipher data given the correct passphrase")
            {
                cipher_output = wickr_crypto_engine_kdf_cipher(&default_engine, test_algo, cipher_algo, test_data, test_passphrase);
                SHOULD_NOT_BE_NULL(cipher_output);
                
                wickr_buffer_t *decode_output = wickr_crypto_engine_kdf_decipher(&default_engine, cipher_output, test_passphrase);
                SHOULD_NOT_BE_NULL(decode_output);
                
                SHOULD_BE_TRUE(wickr_buffer_is_equal(decode_output, test_data, NULL));
                wickr_buffer_destroy(&decode_output);
            }
            END_IT
            
            sprintf( it_statement, "should not decipher data if it is missing an engine %i %i", i, j );
            
            IT("should not decipher data if it is missing an engine")
            {
                SHOULD_BE_NULL(wickr_crypto_engine_kdf_decipher(NULL, cipher_output, test_passphrase));
            }
            END_IT
            
            sprintf( it_statement, "should not decipher data if it is missing cipher data %i %i", i, j );
            
            IT("should not decipher data if it is missing cipher data")
            {
                SHOULD_BE_NULL(wickr_crypto_engine_kdf_decipher(&default_engine, NULL, test_passphrase));
            }
            END_IT
            
            sprintf( it_statement, "should not decipher data without a passphrase %i %i", i, j );
            
            IT("should not decipher data without a passphrase")
            {
                SHOULD_BE_NULL(wickr_crypto_engine_kdf_decipher(&default_engine, cipher_output, NULL));
            }
            END_IT
            
            sprintf( it_statement, "should not decipher data with an incorrect passphrase %i %i", i, j );
            
            IT("should not decipher data with an incorrect passphrase")
            {
                SHOULD_BE_NULL(wickr_crypto_engine_kdf_decipher(&default_engine, cipher_output, incorrect_passphrase));
            }
            END_IT
            
            sprintf( it_statement, "should be choosing random salts %i %i", i, j );
            
            IT("should be choosing random salts")
            {
                wickr_buffer_t *cipher_output_2 = wickr_crypto_engine_kdf_cipher(&default_engine, test_algo, cipher_algo, test_data, test_passphrase);
                SHOULD_NOT_BE_NULL(cipher_output_2);
                SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_output_2, cipher_output, NULL));
                wickr_buffer_destroy(&cipher_output_2);
            }
            END_IT
            
            wickr_buffer_destroy(&cipher_output);
            wickr_buffer_destroy(&test_data);
            wickr_buffer_destroy(&test_passphrase);
            wickr_buffer_destroy(&incorrect_passphrase);
        }
        
        
    }
    
}
END_DESCRIBE






