/*
 * Copyright © 2012-2018 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef openssl_file_suite_h
#define openssl_file_suite_h

#include <stdlib.h>
#include <stdio.h>
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif
    

/**  @addtogroup openssl_file_encryption File Encryption With OpenSSL */

/**
 @ingroup openssl_file_encryption
 
 Encrypt a file to another file
 
 Utilizes a small amount of stack memory to encrypt a large file. This function is byte-format compatible with standard memory-based AES functions from this library.

 @param key the cipher key to use for the encryption operation
 @param sourceFilePath the path to the source file to encrypt
 @param destinationFilePath the location to save the encrypted file
 @return true if the encryption succeeds, false if the sourceFilePath, or destinationFilePath is inaccessible, or the encryption operation fails.
 */
bool openssl_aes256_file_encrypt(const wickr_cipher_key_t *key, const char *sourceFilePath, const char *destinationFilePath);

/**
 
 @ingroup openssl_file_encryption

 Decrypt a file to another file
 
 Utilizes a small amount of stack memory to decrypt a large file. This function is byte-format compatible with standard memory-based AES functions from this library.

 @param key the cipher key to use for the decryption operation
 @param sourceFilePath the path to the source file to decrypt
 @param destinationFilePath the location to save the decrypted file
 @param only_auth_ciphers if true, only authenticated ciphers may be used for decryption
 @return true if the decryption succeeds, false if the sourceFilePath, or destinationFilePath is inaccessible, or the incorrect key is presented
 */
bool openssl_aes256_file_decrypt(const wickr_cipher_key_t *key, const char *sourceFilePath, const char *destinationFilePath, bool only_auth_ciphers);

#ifdef __cplusplus
}
#endif

#endif /* openssl_file_suite_h */
