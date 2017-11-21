#include "cspec.h"
#include "test_buffer.h"
#include "buffer.h"
#include <string.h>

int opposite_compare_func(const volatile void *p1, const volatile void *p2, size_t len)
{
    return memcmp((const void *)p1, (const void *)p2, len) == 0 ? 1 : 0;
}

DESCRIBE(wickr_buffer_tests, "buffer.c")
{
    
    IT("should be able to be created with an existing pointer")
    {
        const uint8_t test_int = 0;
        SHOULD_BE_NULL(wickr_buffer_create(&test_int, SIZE_MAX));
        SHOULD_BE_NULL(wickr_buffer_create(&test_int, MAX_BUFFER_SIZE + 1));
        SHOULD_BE_NULL(wickr_buffer_create(NULL, 0));
        SHOULD_BE_NULL(wickr_buffer_create(&test_int, 0));
        
        wickr_buffer_t *test_buffer = wickr_buffer_create(&test_int, sizeof(uint8_t));
        SHOULD_NOT_BE_NULL(test_buffer);
        
        SHOULD_EQUAL(sizeof(uint8_t), test_buffer->length);
        SHOULD_EQUAL(test_buffer->bytes[0], test_int);
        
        wickr_buffer_destroy(&test_buffer);
        
        SHOULD_BE_NULL(test_buffer);
    }
    END_IT
    
    IT("should be able to be created with empty bytes")
    {
        SHOULD_BE_NULL(wickr_buffer_create_empty(SIZE_MAX));
        SHOULD_BE_NULL(wickr_buffer_create_empty(MAX_BUFFER_SIZE + 1));
        SHOULD_BE_NULL(wickr_buffer_create_empty(0));
        
        wickr_buffer_t *test_buffer = wickr_buffer_create_empty(1024);
        SHOULD_EQUAL(test_buffer->length, 1024);
        SHOULD_NOT_BE_NULL(test_buffer->bytes);
        
        wickr_buffer_destroy(&test_buffer);
        
        SHOULD_BE_NULL(test_buffer);
    }
    END_IT
    
    IT("should be able to be created and destroyed with zeroed bytes")
    {
        SHOULD_BE_NULL(wickr_buffer_create_empty_zero(SIZE_MAX));
        SHOULD_BE_NULL(wickr_buffer_create_empty_zero(MAX_BUFFER_SIZE + 1));
        SHOULD_BE_NULL(wickr_buffer_create_empty(0));

        wickr_buffer_t *test_buffer = wickr_buffer_create_empty_zero(1024);
        SHOULD_EQUAL(test_buffer->length, 1024);
        SHOULD_NOT_BE_NULL(test_buffer->bytes);
        
        uint8_t test_zeros[1024] = { '\0' };
        
        SHOULD_BE_TRUE(memcmp(test_buffer->bytes, test_zeros, 1024) == 0);
        
        wickr_buffer_destroy_zero(&test_buffer);
        
        SHOULD_BE_NULL(test_buffer);
    }
    END_IT
    
    const char *test_data = "wickr";
    wickr_buffer_t *test_buffer = wickr_buffer_create((uint8_t *)test_data, strlen(test_data));
    
    IT("should be able to tell you if two buffers are equal")
    {
        SHOULD_BE_FALSE(wickr_buffer_is_equal(NULL, test_buffer, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, NULL, NULL));
        
        wickr_buffer_t *test_buffer_not_equal = wickr_buffer_create_empty_zero(strlen(test_data));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, test_buffer_not_equal, NULL));
        
        wickr_buffer_t *test_buffer_equal = wickr_buffer_create((uint8_t *)test_data, strlen(test_data));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_buffer, test_buffer_equal, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, test_buffer_equal, opposite_compare_func));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_buffer, test_buffer_not_equal, opposite_compare_func));
        
        wickr_buffer_destroy(&test_buffer_equal);
        wickr_buffer_destroy(&test_buffer_not_equal);
    }
    END_IT
    
    const char *lib_str = "lib";
    wickr_buffer_t lib_buffer = { strlen(lib_str), (uint8_t *)lib_str };
    
    const char *crypto_str = "crypto";
    wickr_buffer_t crypto_buffer = { strlen(crypto_str), (uint8_t *)crypto_str };
    
    const char *wickrcrypto_str = "wickrcrypto";
    wickr_buffer_t wickrcrypto_buffer = { strlen(wickrcrypto_str), (uint8_t *)wickrcrypto_str };
    
    const char *libwickrcrypto_str = "libwickrcrypto";
    wickr_buffer_t libwickrcrypto_buffer = { strlen(libwickrcrypto_str), (uint8_t *)libwickrcrypto_str };
    
    
    IT("should allow the concatenation of two buffers into one")
    {
        SHOULD_BE_NULL(wickr_buffer_concat(NULL, test_buffer));
        SHOULD_BE_NULL(wickr_buffer_concat(test_buffer, NULL));
        
        wickr_buffer_t *combined = wickr_buffer_concat(test_buffer, &crypto_buffer);
        
        SHOULD_NOT_BE_NULL(combined);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(combined, &wickrcrypto_buffer, NULL));
        
        wickr_buffer_destroy(&combined);
    }
    END_IT
    
    IT("should allow the concatenation of multiple buffers into one")
    {
        wickr_buffer_t *buffers[] = { &lib_buffer, test_buffer, &crypto_buffer };
        SHOULD_BE_NULL(wickr_buffer_concat_multi(NULL, 0));
        SHOULD_BE_NULL(wickr_buffer_concat_multi(buffers, 0));
        
        wickr_buffer_t *combined = wickr_buffer_concat_multi(buffers, BUFFER_ARRAY_LEN(buffers));
        SHOULD_NOT_BE_NULL(combined);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(combined, &libwickrcrypto_buffer, NULL));
        
        wickr_buffer_destroy(&combined);
    }
    END_IT
    
    IT("should allow you to make a deep copy")
    {
        wickr_buffer_t *copy_buffer = wickr_buffer_copy(test_buffer);
        SHOULD_NOT_EQUAL(copy_buffer, test_buffer);
        SHOULD_NOT_EQUAL(copy_buffer->bytes, test_buffer->bytes);
        SHOULD_EQUAL(copy_buffer->length, test_buffer->length);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_buffer, test_buffer, NULL));
        
        wickr_buffer_destroy(&copy_buffer);
    }
    END_IT
    
    IT("should allow you to copy out a subsection to a new buffer")
    {
        SHOULD_BE_NULL(wickr_buffer_copy_section(NULL, 0, 0));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, 0, 0));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, SIZE_MAX, SIZE_MAX));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, libwickrcrypto_buffer.length + 1, 1));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, libwickrcrypto_buffer.length, 1));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, libwickrcrypto_buffer.length - 1, 2));
        SHOULD_BE_NULL(wickr_buffer_copy_section(&libwickrcrypto_buffer, 0, libwickrcrypto_buffer.length + 1));
        
        wickr_buffer_t *sub_buffer = wickr_buffer_copy_section(&libwickrcrypto_buffer, 0, 3);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(&lib_buffer, sub_buffer, NULL));
        wickr_buffer_destroy_zero(&sub_buffer);
        
        sub_buffer = wickr_buffer_copy_section(&libwickrcrypto_buffer, strlen(lib_str), strlen(test_data));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_buffer, sub_buffer, NULL));
        wickr_buffer_destroy_zero(&sub_buffer);
        
        sub_buffer = wickr_buffer_copy_section(&libwickrcrypto_buffer, strlen(lib_str) + strlen(test_data), strlen(crypto_str));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(&crypto_buffer, sub_buffer, NULL));
        wickr_buffer_destroy_zero(&sub_buffer);
    }
    END_IT
    
    IT("should allow you to modify a subsection")
    {
        wickr_buffer_t *mutable_buffer = wickr_buffer_copy(&libwickrcrypto_buffer);
        
        SHOULD_BE_FALSE(wickr_buffer_modify_section(mutable_buffer, NULL, 0, 1));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(NULL, (uint8_t *)crypto_str, 0, 1));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, SIZE_MAX, SIZE_MAX));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, 0, 0));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, mutable_buffer->length + 1, 1));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, mutable_buffer->length, 1));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, mutable_buffer->length - 1, 2));
        SHOULD_BE_FALSE(wickr_buffer_modify_section(&libwickrcrypto_buffer, (uint8_t *)crypto_str, 0, mutable_buffer->length + 1));
        
        const char *replace_data_str = "***";
        SHOULD_BE_TRUE(wickr_buffer_modify_section(mutable_buffer, (uint8_t *)replace_data_str, 0, strlen(replace_data_str)));
        
        const char *expected_data_str = "***wickrcrypto";
        wickr_buffer_t expected_data_buffer = { strlen(expected_data_str), (uint8_t *)expected_data_str };
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(&expected_data_buffer, mutable_buffer, NULL));
        
        wickr_buffer_destroy(&mutable_buffer);
    }
    END_IT
    
    wickr_buffer_destroy(&test_buffer);
    
}
END_DESCRIBE
