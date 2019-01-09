
#include "test_b32.h"
#include "b32.h"
#include "string.h"

DESCRIBE(base32_encode, "base32 encoding")
{
    const char *test_string = "00-base32-wickr-crypto-c";
    const char *test_encoded = "60R2TRK1EDJK6CHDEXMP6TVJ5NHQ4YBGEHQJTRR";
    
    wickr_buffer_t test_buffer = { .bytes = (uint8_t *)test_string, .length = strlen(test_string) };
    wickr_buffer_t test_encoded_buffer = { .bytes = (uint8_t *)test_encoded, .length = strlen(test_encoded) };
    
    IT("should be able to encode and decode buffers")
    {
        /* Encode and verify it matches the sample data */
        wickr_buffer_t *encoded_buffer = base32_encode(&test_buffer);
        SHOULD_NOT_BE_NULL(encoded_buffer);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(&test_encoded_buffer, encoded_buffer, NULL));
        
        /* Decode and verify that it matches the original input */
        wickr_buffer_t *decoded_buffer = base32_decode(&test_encoded_buffer);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(decoded_buffer, &test_buffer, NULL));
        
        /* Cleanup */
        wickr_buffer_destroy(&encoded_buffer);
        wickr_buffer_destroy(&decoded_buffer);
    }
    END_IT
    
    IT("should handle decode errors")
    {
        SHOULD_BE_NULL(base32_decode(NULL));
        SHOULD_BE_NULL(base32_decode(&test_buffer));
    }
    END_IT
    
}
END_DESCRIBE
