#include "cspec.h"
#include "openssl_suite.h"
#include "openssl_file_suite.h"
#include "cipher.h"
#include "memory.h"

#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>

#define DATA_SIZE   10000000

DESCRIBE(encodePlainFile, "openssl_file_suite: encodePlainFile")
{

    char *testPlaintextFileName = "test.data";
    char *testCipherFileName = "test.enc";
    wickr_buffer_t *testData = openssl_crypto_random(DATA_SIZE);

    // Open the file for writing
    FILE *sourceHandle = NULL;
#if defined(_WIN32)
    sourceHandle = windowsOpenFile(testPlaintextFileName, L"wb");
#elif defined(__ANDROID__)
    sourceHandle = fopen(testPlaintextFileName, "wb");
#else
    sourceHandle = fopen(testPlaintextFileName, "wb");
#endif

    // Write the data to the plaintext file
    fwrite(testData->bytes, testData->length, 1, sourceHandle);
    fclose(sourceHandle);

    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    wickr_cipher_key_t *cipherKey = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);

    bool retVal =  openssl_aes256_file_encrypt(cipherKey, testPlaintextFileName, testCipherFileName);

    // Calculate length of crypto header
    wickr_buffer_t *iv_f = openssl_crypto_random(CIPHER_AES256_GCM.iv_len);
    wickr_buffer_t *auth_tag = wickr_buffer_create_empty(CIPHER_AES256_GCM.auth_tag_len);
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_create(CIPHER_AES256_GCM, iv_f, NULL, auth_tag);
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    wickr_cipher_result_destroy(&cipher_result);
    
    IT( "returns true when encode plain text file" )
    {
        SHOULD_BE_TRUE( retVal )
    }
    END_IT

    IT( "plain test file size is correct number of bytes" )
    {
        struct stat st;
        stat(testPlaintextFileName, &st);
        int size = st.st_size;
        SHOULD_BE_TRUE( size == DATA_SIZE )
    }
    END_IT

    IT( "encrypted file should be plain test file size plus serialized data" )
    {
        struct stat st;
        stat(testCipherFileName, &st);
        int size = st.st_size;
        int targetSize = DATA_SIZE + serialized->length;
        SHOULD_BE_TRUE( size == targetSize )
    }
    END_IT
    
    IT( "pass null values to function" ) {
        SHOULD_BE_FALSE( openssl_aes256_file_encrypt(NULL, testPlaintextFileName, testCipherFileName) )
        SHOULD_BE_FALSE( openssl_aes256_file_encrypt(cipherKey, NULL, testCipherFileName) )
        SHOULD_BE_FALSE( openssl_aes256_file_encrypt(cipherKey, testPlaintextFileName, NULL) )
    } END_IT

    // Clean up
    wickr_buffer_destroy(&serialized);
    wickr_buffer_destroy(&testData);
    wickr_cipher_key_destroy(&cipherKey);
    remove(testPlaintextFileName);
    remove(testCipherFileName);
}
END_DESCRIBE


DESCRIBE(decodeCipherFile, "openssl_file_suite: decodeCipherFile")
{
    char *testPlaintextFileName = "test.data";
    char *testCipherFileName = "test.enc";
    char *testDecryptedFileName = "decrypted_test.data";
    wickr_buffer_t *testData = openssl_crypto_random(DATA_SIZE);

    // Open the file for writing
    FILE *sourceHandle = NULL;
    #if defined(_WIN32)
    sourceHandle = windowsOpenFile(testPlaintextFileName, L"wb");
    #elif defined(__ANDROID__)
    sourceHandle = fopen(testPlaintextFileName, "wb");
    #else
    sourceHandle = fopen(testPlaintextFileName, "wb");
    #endif

    // Write the data to the plaintext file
    fwrite(testData->bytes, testData->length, 1, sourceHandle);
    fclose(sourceHandle);

    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    wickr_cipher_key_t *cipherKey = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);

    bool retVal = openssl_aes256_file_encrypt(cipherKey, testPlaintextFileName, testCipherFileName);

    // Decrypt the encrypted file
    retVal = openssl_aes256_file_decrypt(cipherKey, testCipherFileName, testDecryptedFileName, true);
    
    IT( "returns true when decode cipher file" )
    {
        SHOULD_BE_TRUE( retVal )
    }
    END_IT
    
    IT( "plain test file size is correct number of bytes" )
    {
        struct stat st;
        stat(testDecryptedFileName, &st);
        int size = st.st_size;
        SHOULD_BE_TRUE( size == DATA_SIZE )
    }
    END_IT
    
    IT( "should be binary compatable with memory based GCM encryption")
    {
        struct stat st;
        stat(testCipherFileName, &st);
        int size = st.st_size;
        
        wickr_buffer_t *wholeFileBuffer = wickr_buffer_create_empty_zero(size);
		if (wholeFileBuffer != NULL) {
			FILE *encFile = fopen(testCipherFileName, "rb");

			// Read in all of the bytes, do not assume that the fread will read all at once
			size_t count = 0;
			uint8_t *curbyte = wholeFileBuffer->bytes;

			while (count < wholeFileBuffer->length) {
				size_t bytesRead = fread(curbyte, sizeof(char), wholeFileBuffer->length - count, encFile);
				count += bytesRead;
				curbyte = &wholeFileBuffer->bytes[count];
			}
			fclose(encFile);

			SHOULD_EQUAL(count, wholeFileBuffer->length);

			if (count == wholeFileBuffer->length) {
				wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(wholeFileBuffer);
				wickr_buffer_destroy(&wholeFileBuffer);

				wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();

				wickr_buffer_t *decode = engine.wickr_crypto_engine_cipher_decrypt(cipher_result, NULL, cipherKey, true);

				SHOULD_NOT_BE_NULL(decode);
				SHOULD_BE_TRUE(wickr_buffer_is_equal(decode, testData, NULL));
				wickr_cipher_result_destroy(&cipher_result);
				wickr_buffer_destroy(&decode);
			}
		}
    }
    END_IT

    // Clean up
    wickr_buffer_destroy(&testData);
    wickr_cipher_key_destroy(&cipherKey);
    remove(testPlaintextFileName);
    remove(testCipherFileName);
    remove(testDecryptedFileName);
}
END_DESCRIBE
