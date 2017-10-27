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

    for (uint16_t j = 0; j < 100; j++) {

        wickr_buffer_t *private_key = wickr_buffer_random(EDDSA_448_PRIVATE_KEY_LENGTH);
        wickr_buffer_t *public_key = ed448_sig_derive_public_key(private_key);

        if (!public_key) {
            printf("ed448_sig_derive_public_key failed");
            all_tests_passed = false;
        }

        wickr_ec_curve_t wc;
        wickr_ec_key_t *key_pair = wickr_ec_key_create(wc, public_key, private_key);
        
        wickr_buffer_t *message = wickr_buffer_random(message_length);
        wickr_buffer_t *signature = ed448_sig_sign(key_pair, message);

        if (!signature) {
            printf("ed448_sig_derive_public_key failed");
            all_tests_passed = false;
        }

        bool success = ed448_sig_verify(signature, key_pair, message);        

        if (!success) {
            printf("Sh*t! Verification failed with correct pubkey!\n");
            all_tests_passed = false;
        }
        
        for (uint16_t i = 0; i < 1000; i++) {
            wickr_buffer_t *random_pub_key_data = wickr_buffer_random(EDDSA_448_PUBLIC_KEY_LENGTH);
            wickr_ec_key_t *random_pub_key =  wickr_ec_key_create(wc, random_pub_key_data, NULL);
            success = ed448_sig_verify(signature, random_pub_key, message);
            if (success) {
                printf("Sh*t! Verification succeeded on random pub key!\n");
                all_tests_passed = false;
            }

            wickr_ec_key_destroy(&random_pub_key);

        }

        for (uint16_t i = 0; i < 1000; i++) {
            wickr_buffer_t *random_message = wickr_buffer_random(message_length);
            
            success = ed448_sig_verify(signature, key_pair, random_message);
            if (success) {
                printf("Sh*t! Verification succeeded on random message!\n");
                all_tests_passed = false;
            }

            wickr_buffer_destroy(&random_message);

        }

        wickr_buffer_destroy(&message);
        wickr_buffer_destroy(&signature);
        wickr_ec_key_destroy(&key_pair);
    }
    return all_tests_passed;
}

bool test_dh()
{
    bool all_tests_passed = true;

    for (uint16_t j = 0; j < 10000; j++) {

        wickr_ec_key_t *keypair[3];
        for (uint8_t i = 0; i < 3; i++) {
        
            wickr_buffer_t *private_key_data = wickr_buffer_random(DH_448_PRIVATE_KEY_LENGTH);
            wickr_buffer_t *public_key_data = ed448_dh_derive_public_key(private_key_data);

            if (!public_key_data) {
                printf("ed448_dh_derive_public_key failed");
                all_tests_passed = false;
            }
            wickr_ec_curve_t wc;
            keypair[i] = wickr_ec_key_create(wc, public_key_data, private_key_data);  
        }

        wickr_buffer_t *shared_secret[3];
        for (uint8_t i = 0; i < 3; i++) {
            shared_secret[i] = ed448_dh_shared_secret(keypair[(i+1)%3], keypair[(i+2)%3]);
            wickr_buffer_t *check = ed448_dh_shared_secret(keypair[(i+2)%3], keypair[(i+1)%3]);

            if (!shared_secret[i] || !check) {
                printf("ed448_dh_shared_secret failed");
                all_tests_passed = false;
            }
            bool equal = wickr_buffer_is_equal(shared_secret[i], check, NULL);            

            if (!equal) {
                printf("Shared secrets not equal!");
                all_tests_passed = false;
            }

            wickr_buffer_destroy(&check);
        }

        for (uint8_t i = 0; i < 3; i++) {
            bool equal = wickr_buffer_is_equal(shared_secret[i], shared_secret[(i+1)%3], NULL);
            
            if (equal) {
                printf("Shared secrets equal when they shouldn't be.");
                all_tests_passed = false;
            }    
        }

        for (uint8_t i = 0; i < 3; i++) {
            wickr_buffer_destroy(&shared_secret[i]);
            wickr_ec_key_destroy(&keypair[i]);
        }

    }
    return all_tests_passed;
}

int main(void)
{
    srand(time(0));
    bool all_tests_passed = true;
    all_tests_passed |= test_sig_scheme();
    printf("Signature scheme tested...\n");
    all_tests_passed |= test_dh();
    printf("Diffie-Helmam tested...\n");

    
    if (all_tests_passed)
        printf("All tests passed!\n");
    else
        printf("Some tests failed!\n");
    
    return 0;
}
