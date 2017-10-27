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


int main(void)
{
    bool all_tests_passed = true;
    srand(time(0));

    
    for (uint16_t j = 0; j < 1000; j++) {

        wickr_buffer_t *private_key = wickr_buffer_random(EDDSA_448_PRIVATE_KEY_LENGTH);
        wickr_buffer_t *public_key = ed448_sig_gen_key(private_key);

        wickr_ec_curve_t wc;
        wickr_ec_key_t *key_pair = wickr_ec_key_create(wc, public_key, private_key);

        uint8_t message_length = 100;
        wickr_buffer_t *message = wickr_buffer_random(message_length);

        wickr_buffer_t *signature = ed448_sig_sign(key_pair, message);

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

        wickr_buffer_destroy(&message);
        wickr_buffer_destroy(&signature);
        wickr_ec_key_destroy(&key_pair);
    }
    if (all_tests_passed)
        printf("All tests passed!\n");
    else
        printf("Some tests failed!\n");
    
    return 0;
}
