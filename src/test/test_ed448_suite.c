#include "cspec.h"
#include "ed448_suite.h"
#include "openssl_suite.h"

#include <decaf/ed448.h>
#include <decaf/shake.h>

wickr_ec_key_t *sig_random_key_pair()
{
    wickr_ec_curve_t curve = EC_CURVE_ED448_GOLDILOCKS;
    wickr_buffer_t *private_key_data = openssl_crypto_random(EDDSA_448_PRIVATE_KEY_LENGTH);
    wickr_buffer_t *public_key_data = ed448_sig_derive_public_key(private_key_data);

    SHOULD_NOT_BE_NULL(public_key_data)
    SHOULD_EQUAL(public_key_data->length, EDDSA_448_PUBLIC_KEY_LENGTH)
    
    wickr_ec_key_t *result = wickr_ec_key_create(curve, public_key_data, private_key_data);
    return result;  
}

void test_eddsa_signature(wickr_ec_key_t *pri_key, wickr_buffer_t *test_data, wickr_digest_t digest)
{
    wickr_ecdsa_result_t *result = ed448_sig_sign(pri_key, test_data, digest);
    SHOULD_NOT_BE_NULL(result);
    SHOULD_EQUAL(digest.digest_id, result->digest_mode.digest_id);
    SHOULD_NOT_BE_NULL(result->sig_data);
    
    wickr_buffer_t *pub_data = wickr_buffer_copy(pri_key->pub_data);
    wickr_ec_key_t *pub_key = wickr_ec_key_create(pri_key->curve, pub_data, NULL);

    bool did_validate = ed448_sig_verify(result, pub_key, test_data);
    wickr_ec_key_destroy(&pub_key);
    
    SHOULD_BE_TRUE(did_validate);
    
    wickr_ec_key_t *another_key = sig_random_key_pair();
    wickr_buffer_destroy(&another_key->pri_data);
    SHOULD_NOT_BE_NULL(another_key);
    did_validate = ed448_sig_verify(result, another_key, test_data);
    SHOULD_BE_FALSE(did_validate);
    wickr_ec_key_destroy(&another_key);
    wickr_ecdsa_result_destroy(&result);
}

DESCRIBE(ed448_signature_scheme, "ed448_suite: ed448_sig_sign ed448_sig_verify")
{
    wickr_ec_curve_t curve = EC_CURVE_ED448_GOLDILOCKS;
    wickr_digest_t digest_mode = wickr_digest_matching_curve(curve);
    uint8_t message_length = 100;

    IT("Invalid/Insufficient input")
    {
        wickr_ec_key_t *local_key = sig_random_key_pair();
        wickr_buffer_t *message = openssl_crypto_random(message_length);

        wickr_ecdsa_result_t *result = ed448_sig_sign(NULL, message, digest_mode);
        SHOULD_BE_NULL(result)

        result = ed448_sig_sign(local_key, NULL, digest_mode);
        SHOULD_BE_NULL(result)

        result = ed448_sig_sign(local_key, message, DIGEST_SHA_256);
        SHOULD_BE_NULL(result)

        result = ed448_sig_sign(local_key, message, digest_mode);
        SHOULD_NOT_BE_NULL(result)

        bool did_validate = ed448_sig_verify(result, local_key, NULL);
        SHOULD_BE_FALSE(did_validate)

        did_validate = ed448_sig_verify(NULL, local_key, message);
        SHOULD_BE_FALSE(did_validate)

        did_validate = ed448_sig_verify(result, NULL, message);
        SHOULD_BE_FALSE(did_validate)
        
        did_validate = ed448_sig_verify(result, local_key, message);
        SHOULD_BE_TRUE(did_validate)
        
        wickr_ec_key_destroy(&local_key);
        wickr_buffer_destroy(&message);
        wickr_ecdsa_result_destroy(&result);
    }
    END_IT

    IT("Signature verifies precisely on right pubkey")
    {
        

        for (uint16_t i = 0; i < 1000; i++) {
            wickr_ec_key_t *local_key = sig_random_key_pair();
            wickr_buffer_t *message = openssl_crypto_random(message_length);
            test_eddsa_signature(local_key, message, digest_mode);
            wickr_buffer_destroy(&message);
            wickr_ec_key_destroy(&local_key);
        }
    }
    END_IT

}
END_DESCRIBE


DESCRIBE(ed448_sig_derive_public_key, "ed448_suite: ed448_sig_derive_public_key")
{
    IT("Invalid/insufficient input")
    {
        wickr_buffer_t *private_key_data = NULL;
        wickr_buffer_t *result = ed448_sig_derive_public_key(private_key_data);
        SHOULD_BE_NULL(result)

        private_key_data = openssl_crypto_random(EDDSA_448_PRIVATE_KEY_LENGTH - 5);
        // Wrong private key length
        result = ed448_sig_derive_public_key(private_key_data);
        SHOULD_BE_NULL(result)
        wickr_buffer_destroy(&private_key_data);
    }
    END_IT

}
END_DESCRIBE

wickr_buffer_t *dh_from_keys(const wickr_ec_key_t *local_key, const wickr_ec_key_t *peer_key,
    const wickr_kdf_meta_t *kdf_info)
{
    if (!local_key || !peer_key || !kdf_info)
        return NULL;

    wickr_ec_key_t *local_key_cpy = wickr_ec_key_copy(local_key);
    wickr_ec_key_t *peer_key_cpy = wickr_ec_key_copy(peer_key);

    if(peer_key_cpy->pri_data)    
        wickr_buffer_destroy(&peer_key_cpy->pri_data);  // Make sure the peer private key is gone;

    wickr_kdf_meta_t *kdf_info_cpy = wickr_kdf_meta_copy(kdf_info);
    wickr_ecdh_params_t *params = wickr_ecdh_params_create(local_key_cpy, peer_key_cpy, kdf_info_cpy);
    wickr_buffer_t *result = ed448_dh_shared_secret(params);
    SHOULD_NOT_BE_NULL(result)
    SHOULD_EQUAL(result->length, kdf_info->algo.output_size)

    wickr_ecdh_params_destroy(&params);
    return result;
}

wickr_ec_key_t *dh_random_key_pair()
{
    wickr_ec_curve_t curve = EC_CURVE_ED448_GOLDILOCKS;
    wickr_buffer_t *private_key_data = openssl_crypto_random(DH_448_PRIVATE_KEY_LENGTH);
    wickr_buffer_t *public_key_data = ed448_dh_derive_public_key(private_key_data);

    SHOULD_NOT_BE_NULL(public_key_data)
    SHOULD_EQUAL(public_key_data->length, DH_448_PUBLIC_KEY_LENGTH)
    
    wickr_ec_key_t *result = wickr_ec_key_create(curve, public_key_data, private_key_data);
    return result;  
}

void test_dh_triplet(const wickr_ec_key_t *alice_key,
                     const wickr_ec_key_t *bob_key,
                     const wickr_ec_key_t *eve_key,
                     const wickr_kdf_meta_t *kdf_info) 
{
    wickr_buffer_t *alice_bob = dh_from_keys(alice_key, bob_key, kdf_info);
    SHOULD_NOT_BE_NULL(alice_bob)

    wickr_buffer_t *bob_alice = dh_from_keys(bob_key, alice_key, kdf_info);
    SHOULD_NOT_BE_NULL(bob_alice)

    wickr_buffer_t *alice_eve = dh_from_keys(alice_key, eve_key, kdf_info);
    SHOULD_NOT_BE_NULL(bob_alice)
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_bob, bob_alice, NULL))
    SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_bob, alice_eve, NULL))

    wickr_buffer_destroy(&alice_bob);
    wickr_buffer_destroy(&bob_alice);
    wickr_buffer_destroy(&alice_eve);
}

wickr_kdf_meta_t *random_hkdf_info()
{
    wickr_kdf_algo_t algo = KDF_HKDF_SHA256;
    wickr_buffer_t *salt = openssl_crypto_random(algo.salt_size);
    wickr_buffer_t *info = openssl_crypto_random(20);
    wickr_kdf_meta_t *kdf_info = wickr_kdf_meta_create(algo, salt, info);
    return kdf_info;
}

DESCRIBE(ed448_dh_derive_public_key, "ed448_suite: ed448_dh_derive_public_key")
{
    IT("Invalid/insufficient input")
    {
        wickr_buffer_t *private_key_data = NULL;
        wickr_buffer_t *result = ed448_dh_derive_public_key(private_key_data);
        SHOULD_BE_NULL(result)

        private_key_data = openssl_crypto_random(DH_448_PRIVATE_KEY_LENGTH - 5);
        // Wrong private key length
        result = ed448_dh_derive_public_key(private_key_data);
        SHOULD_BE_NULL(result)
        wickr_buffer_destroy(&private_key_data);
    }
    END_IT

}
END_DESCRIBE


DESCRIBE(ed448_dh_shared_secret, "ed448_suite: ed448_dh_shared_secret")
{
    IT("Invalid/insufficient input")
    {
        wickr_buffer_t *result = ed448_dh_shared_secret(NULL);
        SHOULD_BE_NULL(result)
  
        wickr_ecdh_params_t *params = wickr_ecdh_params_create(dh_random_key_pair(),
                                                               dh_random_key_pair(), NULL);
        result = ed448_dh_shared_secret(params);
        wickr_ecdh_params_destroy(&params);
        SHOULD_BE_NULL(result)

        params = wickr_ecdh_params_create(dh_random_key_pair(), NULL, random_hkdf_info());
        result = ed448_dh_shared_secret(params);
        wickr_ecdh_params_destroy(&params);
        SHOULD_BE_NULL(result)

        params = wickr_ecdh_params_create(NULL, dh_random_key_pair(), random_hkdf_info());
        result = ed448_dh_shared_secret(params);
        wickr_ecdh_params_destroy(&params);
        SHOULD_BE_NULL(result)
    }
    END_IT

    IT("Valid output; shared secret agrees precisely when it should")
    {
        for (uint16_t i = 0; i < 100; i++) {
            wickr_kdf_meta_t *kdf_info = random_hkdf_info();
    
            SHOULD_NOT_BE_NULL(kdf_info)
            
            wickr_ec_key_t *alice_key = dh_random_key_pair();
            wickr_ec_key_t *bob_key = dh_random_key_pair();
            wickr_ec_key_t *eve_key = dh_random_key_pair();
    
            test_dh_triplet(alice_key, bob_key, eve_key, kdf_info);
    
            wickr_kdf_meta_destroy(&kdf_info);
            wickr_ec_key_destroy(&alice_key);
            wickr_ec_key_destroy(&bob_key);
            wickr_ec_key_destroy(&eve_key);
        }
    }
    END_IT

}
END_DESCRIBE

void test_shake_result(uint8_t *msg_raw, uint16_t msg_len, uint16_t output_length, uint8_t *answer)
{        
    wickr_buffer_t *message = wickr_buffer_create(msg_raw, msg_len);    
    wickr_buffer_t *output = ed448_shake256_raw(message, output_length);

    SHOULD_NOT_BE_NULL(output)    
           
    wickr_buffer_t *correct_output = wickr_buffer_create(answer, output_length);

    SHOULD_BE_TRUE(wickr_buffer_is_equal(output, correct_output, NULL))

    wickr_buffer_destroy(&output);
    wickr_buffer_destroy(&message);
    wickr_buffer_destroy(&correct_output);

}

DESCRIBE(ed448_shake256_raw, "ed448_suite: ed448_shake256_raw")
{
    IT("Invalid/insufficient input")
    {
        wickr_buffer_t *output;
        output = ed448_shake256_raw(NULL, 10);
        SHOULD_BE_NULL(output)

        wickr_buffer_t *message = openssl_crypto_random(15);
        output = ed448_shake256_raw(message, 0);
        SHOULD_BE_NULL(output)

        wickr_buffer_destroy(&message);
    }
    END_IT
    IT("Correctness")
    {
        // Compared to Python3.6 hashlib implementation
        uint8_t msg_raw1[10] = "helloworld";
        uint8_t answer1[10] = {0x05,0x99,0xdf,0x85,0x01,0x88,0xc1,0x93,0x3b,0x38};
        test_shake_result(msg_raw1, 10, 10, answer1);    
        
        uint8_t msg_raw2[12] = "some message";
        uint8_t answer2[7] = {0x62,0xd4,0xef,0xf4,0x78,0xeb,0x34};
        test_shake_result(msg_raw2, 12, 7, answer2);
            
        uint8_t msg_raw3[12] = "   spaces   ";
        uint8_t answer3[4] = {0x10,0x1a,0x3e,0x3a};
        test_shake_result(msg_raw3, 12, 4, answer3);
            
        uint8_t msg_raw4[1] = "\n";
        uint8_t answer4[20] = {0x45,0x54,0x46,0x0a,0xd5,0x3f,0x18,0x58,0x1c,0x65,0x39,0x37,0xbe,0x5d,0x7c,0x5f,0x57,0xa5,0xb7,0x11};
        test_shake_result(msg_raw4, 1, 20, answer4);  
    }
    END_IT

}
END_DESCRIBE

void test_shake_salt(uint8_t *msg_raw, uint16_t msg_len, uint8_t *salt_raw, uint16_t salt_len,
    uint8_t *info_raw, uint16_t info_len)
{
    wickr_buffer_t *msg = wickr_buffer_create(msg_raw, msg_len);
    wickr_buffer_t *salt = wickr_buffer_create(salt_raw, salt_len);
    wickr_buffer_t *info = wickr_buffer_create(info_raw, info_len);

    wickr_buffer_t *array[3] = {salt, info, msg};
    wickr_buffer_t *concat = wickr_buffer_concat_multi(array, 3);

    uint16_t output_length = 64;
    wickr_buffer_t *answer1 = ed448_shake256_raw(concat, output_length);
    wickr_buffer_t *answer2 = ed448_shake256(msg, salt, info, output_length);

    SHOULD_NOT_BE_NULL(answer1)
    SHOULD_NOT_BE_NULL(answer2)

    SHOULD_BE_TRUE(wickr_buffer_is_equal(answer1, answer2, NULL))

    wickr_buffer_destroy(&msg);
    wickr_buffer_destroy(&salt);
    wickr_buffer_destroy(&info);
    wickr_buffer_destroy(&concat);
}

DESCRIBE(ed448_shake256, "ed448_suite: ed448_shake256")
{
    IT("Insiffucient input")
    {
        SHOULD_BE_NULL(ed448_shake256(NULL, NULL, NULL, 10))
    }
    END_IT
    IT("Same output as concatenated version")
    {
        uint8_t msg_raw1[5] = "hello";
        uint8_t salt_raw1[5] = "world";
        uint8_t info_raw1[1] = "!";
        test_shake_salt(msg_raw1, 5, salt_raw1, 5, info_raw1, 1);
        
        uint8_t msg_raw2[3] = "abc";
        uint8_t salt_raw2[3] = "def";
        uint8_t info_raw2[3] = "ghi";
        test_shake_salt(msg_raw2, 3, salt_raw2, 3, info_raw2, 3);
        
        uint8_t msg_raw3[3] = "abc";
        uint8_t *salt_raw3 = NULL;
        uint8_t info_raw3[3] = "ghi";
        test_shake_salt(msg_raw3, 3, salt_raw3, 0, info_raw3, 3);
        
        uint8_t msg_raw4[4] = "abcd";
        uint8_t salt_raw4[3] = "def";
        uint8_t *info_raw4 = NULL;
        test_shake_salt(msg_raw4, 4, salt_raw4, 3, info_raw4, 0);
        
        uint8_t msg_raw5[1] = "a";
        uint8_t *salt_raw5 = NULL;
        uint8_t *info_raw5 = NULL;
        test_shake_salt(msg_raw5, 1, salt_raw5, 0, info_raw5, 0);
    }
    END_IT

}
END_DESCRIBE