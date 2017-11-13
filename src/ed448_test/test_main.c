#include "ed448_suite.h"
#include <stdlib.h>
#include <assert.h>

void fill_bytes_with_random(uint8_t *bytes, size_t length)
{ 
  for (uint32_t i = 0; i < length; i++)
    bytes[i] = rand();
}

wickr_buffer_t *wickr_buffer_random(size_t length)
{
    wickr_buffer_t *result = wickr_buffer_create_empty_zero(length);
    fill_bytes_with_random(result->bytes, length);
    return result;    
}

void print_buffer_hex(const wickr_buffer_t *buffer)
{
    for (uint32_t i = 0; i < buffer->length; i++)
        printf("%02X", buffer->bytes[i]);
}

bool test_sig_scheme()
{
    bool all_tests_passed = true;
    uint8_t message_length = 100;
    wickr_ec_curve_t curve = EC_CURVE_ED448_GOLDILOCKS;
    wickr_digest_t digest_mode = DIGEST_NONE_ED448;

    for (uint16_t j = 0; j < 100; j++) {

        wickr_buffer_t *private_key = wickr_buffer_random(EDDSA_448_PRIVATE_KEY_LENGTH);
        wickr_buffer_t *public_key = ed448_sig_derive_public_key(private_key);

        if (!public_key) {
            printf("ed448_sig_derive_public_key failed");
            all_tests_passed = false;
        }

       
        wickr_ec_key_t *key_pair = wickr_ec_key_create(curve, public_key, private_key);
        
        wickr_buffer_t *message = wickr_buffer_random(message_length);
        wickr_ecdsa_result_t *signature = ed448_sig_sign(key_pair, message, digest_mode);

        if (!signature) {
            printf("ed448_sig_derive_public_key failed");
            all_tests_passed = false;
        }

        bool success = ed448_sig_verify(signature, key_pair, message);        

        if (!success) {
            printf("Sh*t! Verification failed with correct pubkey!\n");
            all_tests_passed = false;
        }
        
        for (uint16_t i = 0; i < 100; i++) {
            wickr_buffer_t *random_pub_key_data = wickr_buffer_random(EDDSA_448_PUBLIC_KEY_LENGTH);
            wickr_ec_key_t *random_pub_key =  wickr_ec_key_create(curve, random_pub_key_data, NULL);
            success = ed448_sig_verify(signature, random_pub_key, message);
            if (success) {
                printf("Sh*t! Verification succeeded on random pub key!\n");
                all_tests_passed = false;
            }

            wickr_ec_key_destroy(&random_pub_key);

        }

        for (uint16_t i = 0; i < 100; i++) {
            wickr_buffer_t *random_message = wickr_buffer_random(message_length);
            
            success = ed448_sig_verify(signature, key_pair, random_message);
            if (success) {
                printf("Sh*t! Verification succeeded on random message!\n");
                all_tests_passed = false;
            }

            wickr_buffer_destroy(&random_message);

        }

        wickr_buffer_destroy(&message);
        wickr_ecdsa_result_destroy(&signature);
        wickr_ec_key_destroy(&key_pair);
    }
    return all_tests_passed;
}

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
    wickr_ecdh_params_destroy(&params);
    return result;
}

wickr_ec_key_t *dh_random_key_pair()
{
    wickr_ec_curve_t curve = EC_CURVE_ED448_GOLDILOCKS;
    wickr_buffer_t *private_key_data = wickr_buffer_random(DH_448_PRIVATE_KEY_LENGTH);
    wickr_buffer_t *public_key_data = ed448_dh_derive_public_key(private_key_data);

    if (!public_key_data) {
        printf("ed448_dh_derive_public_key failed");
        wickr_buffer_destroy(&private_key_data);
        return NULL;
    }
    wickr_ec_key_t * result = wickr_ec_key_create(curve, public_key_data, private_key_data);
    return result;  
}

bool test_dh_triplet(const wickr_ec_key_t *alice_key,
                     const wickr_ec_key_t *bob_key,
                     const wickr_ec_key_t *eve_key,
                     const wickr_kdf_meta_t *kdf_info) 
{
    wickr_buffer_t * alice_bob = dh_from_keys(alice_key, bob_key, kdf_info);
    if (!alice_bob)
        return false;

    wickr_buffer_t * bob_alice = dh_from_keys(bob_key, alice_key, kdf_info);
    if (!bob_alice) {
        wickr_buffer_destroy(&alice_bob);
        return false;
    }
    wickr_buffer_t * alice_eve = dh_from_keys(alice_key, eve_key, kdf_info);
    if (!alice_eve) {
        wickr_buffer_destroy(&alice_bob);
        wickr_buffer_destroy(&bob_alice);
        return false;
    }
    bool equal1 = wickr_buffer_is_equal(alice_bob, bob_alice, NULL);
    bool equal2 = wickr_buffer_is_equal(alice_bob, alice_eve, NULL);

    wickr_buffer_destroy(&alice_bob);
    wickr_buffer_destroy(&bob_alice);
    wickr_buffer_destroy(&alice_eve);

    if (!equal1)
        printf("Shared secret not agreed!\n");

    if (equal2)
        printf("Shared secret collision!\n");
    return (equal1 && !equal2);

}
wickr_kdf_meta_t *random_hkdf_info()
{
    wickr_kdf_algo_t algo = KDF_HKDF_SHA256;
    wickr_buffer_t *salt = wickr_buffer_random(algo.salt_size);
    wickr_buffer_t *info = wickr_buffer_random(20);
    wickr_kdf_meta_t *kdf_info = wickr_kdf_meta_create(algo, salt, info);
    return kdf_info;
}

bool test_dh(uint16_t iterations)
{
    for (uint16_t i = 0; i < iterations; i++) {
        wickr_kdf_meta_t *kdf_info = random_hkdf_info();

        if (!kdf_info) {
            printf("hkdf init failed!\n");
            return false;
        }
        
        wickr_ec_key_t *alice_key = dh_random_key_pair();
        wickr_ec_key_t *bob_key = dh_random_key_pair();
        wickr_ec_key_t *eve_key = dh_random_key_pair();

        bool passed = test_dh_triplet(alice_key, bob_key, eve_key, kdf_info);

        wickr_kdf_meta_destroy(&kdf_info);
        wickr_ec_key_destroy(&alice_key);
        wickr_ec_key_destroy(&bob_key);
        wickr_ec_key_destroy(&eve_key);

        if (!passed)
            return false;
    }
    return true;
}

int main(void)
{
    uint8_t msg[2] = "aa";

    wickr_buffer_t *some_message = wickr_buffer_create(msg, 2);
    wickr_buffer_t *output = ed448_shake256(some_message, 10);
    print_buffer_hex(output);
    wickr_buffer_destroy(&output);
    wickr_buffer_destroy(&some_message);
    
    srand(time(0));
    bool all_tests_passed = true;
    all_tests_passed &= test_sig_scheme();
    printf("Signature scheme tested...\n");
    all_tests_passed &= test_dh(10000);
    printf("Diffie-Helmam tested...\n");

    if (all_tests_passed)
        printf("All tests passed!\n");
    else
        printf("Some tests failed!\n");
    
    return 0;
}
