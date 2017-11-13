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
    printf("\n");
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

bool test_shake_result(uint8_t *msg_raw, uint16_t msg_len, uint16_t output_length, uint8_t *answer)
{        
    wickr_buffer_t *message = wickr_buffer_create(msg_raw, msg_len);    
    wickr_buffer_t *output = ed448_shake256_raw(message, output_length);

    if (!output) {
        printf("Shake computation failed!\n");
        wickr_buffer_destroy(&message);
        return false;
    }
           
    wickr_buffer_t *correct_output = wickr_buffer_create(answer, output_length);

    bool equal = wickr_buffer_is_equal(output, correct_output, NULL);

    if (!equal) {
        printf("Shake failed on test vector %s\n", msg_raw);
        print_buffer_hex(output);
        print_buffer_hex(correct_output);
    }
    wickr_buffer_destroy(&output);
    wickr_buffer_destroy(&message);
    wickr_buffer_destroy(&correct_output);
    
    return equal;
}

bool test_shake_all()
{
    bool all_tests_passed = true;

    uint8_t msg_raw1[10] = "helloworld";
    uint8_t answer1[10] = {0x05,0x99,0xdf,0x85,0x01,0x88,0xc1,0x93,0x3b,0x38};
    all_tests_passed &= test_shake_result(msg_raw1, 10, 10, answer1);    
    
    uint8_t msg_raw2[12] = "some message";
    uint8_t answer2[7] = {0x62,0xd4,0xef,0xf4,0x78,0xeb,0x34};
    all_tests_passed &= test_shake_result(msg_raw2, 12, 7, answer2);
        
    uint8_t msg_raw3[12] = "   spaces   ";
    uint8_t answer3[4] = {0x10,0x1a,0x3e,0x3a};
    all_tests_passed &= test_shake_result(msg_raw3, 12, 4, answer3);
        
    uint8_t msg_raw4[1] = "\n";
    uint8_t answer4[20] = {0x45,0x54,0x46,0x0a,0xd5,0x3f,0x18,0x58,0x1c,0x65,0x39,0x37,0xbe,0x5d,0x7c,0x5f,0x57,0xa5,0xb7,0x11};
    all_tests_passed &= test_shake_result(msg_raw4, 1, 20, answer4);        

    return all_tests_passed;
}

bool test_shake_salt(uint8_t *msg_raw, uint16_t msg_len, uint8_t *salt_raw, uint16_t salt_len,
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

    bool equal = false;
    if (answer1 && answer2) {
        equal = wickr_buffer_is_equal(answer1, answer2, NULL);
        if (!equal)
            printf("Salt results not equal!\n");
    }
    else
        printf("Shake call failed!\n");

    wickr_buffer_destroy(&msg);
    wickr_buffer_destroy(&salt);
    wickr_buffer_destroy(&info);
    wickr_buffer_destroy(&concat);

    if (answer1)
        wickr_buffer_destroy(&answer1);
    if (answer2)
        wickr_buffer_destroy(&answer2);

    return equal;
}

bool test_shake_salt_all()
{
    bool all_tests_passed = true;

    uint8_t msg_raw1[5] = "hello";
    uint8_t salt_raw1[5] = "world";
    uint8_t info_raw1[1] = "!";
    all_tests_passed &= test_shake_salt(msg_raw1, 5, salt_raw1, 5, info_raw1, 1);
    
    uint8_t msg_raw2[3] = "abc";
    uint8_t salt_raw2[3] = "def";
    uint8_t info_raw2[3] = "ghi";
    all_tests_passed &= test_shake_salt(msg_raw2, 3, salt_raw2, 3, info_raw2, 3);
    
    uint8_t msg_raw3[3] = "abc";
    uint8_t *salt_raw3 = NULL;
    uint8_t info_raw3[3] = "ghi";
    all_tests_passed &= test_shake_salt(msg_raw3, 3, salt_raw3, 0, info_raw3, 3);
    
    uint8_t msg_raw4[4] = "abcd";
    uint8_t salt_raw4[3] = "def";
    uint8_t *info_raw4 = NULL;
    all_tests_passed &= test_shake_salt(msg_raw4, 4, salt_raw4, 3, info_raw4, 0);
    
    uint8_t msg_raw5[1] = "a";
    uint8_t *salt_raw5 = NULL;
    uint8_t *info_raw5 = NULL;
    all_tests_passed &= test_shake_salt(msg_raw5, 1, salt_raw5, 0, info_raw5, 0);

    return all_tests_passed;
}

bool test_shake()
{
    bool all_tests_passed = true;
    all_tests_passed &= test_shake_salt_all();
    all_tests_passed &= test_shake_all();
    return all_tests_passed;
}

int main(void)
{
    
    srand(time(0));
    bool all_tests_passed = true;
    all_tests_passed &= test_shake();
    printf("Shake256 tested...\n");
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
