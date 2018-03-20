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

#ifndef buffer_h
#define buffer_h

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "array.h"
#include "limits.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 
 @addtogroup wickr_buffer wickr_buffer_t
 
 @struct wickr_buffer
 @ingroup wickr_buffer

 @brief Represents an array of bytes and the length of the allocation associated with those bytes
 
 Buffers are the fundamental building block of many wickr structures, and the preferred way of passing around pointers to data in a safe way.
 
 @var wickr_buffer::length 
 the length of the allocation pointed to by bytes. Length should always be a non-zero value
 @var wickr_buffer::bytes 
 an array of bytes of size length. bytes should not be NULL
 */
struct wickr_buffer {
    size_t length;
    uint8_t *bytes;
};

typedef struct wickr_buffer wickr_buffer_t;

/**
 
 @ingroup wickr_buffer
 
 @brief Determine the number of elements in an array of buffers (wickr_buffer_t **).
 
 NOTE: This function will only work on stack allocated arrays. It is meant only to be used in cases where the length of the array of buffers is determined at compile time, on the stack. 
 
 EXAMPLE: wickr_buffer_t *elements[] = { b1, b2 b3 }.

 @param x pointer to an array of wickr_buffer_t elements
 @return The number of elements in the array pointed to by x
 */
#define BUFFER_ARRAY_LEN(x) (sizeof(x) / sizeof(wickr_buffer_t *))

/* Define a MAX_BUFFER_SIZE that limits the total memory consumed by a buffer to INT32_MAX (~2GB) */
static const size_t MAX_BUFFER_SIZE = INT32_MAX - sizeof(wickr_buffer_t);

typedef int (*wickr_buffer_compare_func)(const volatile void *, const volatile void *, size_t);

/**
 
 @ingroup wickr_buffer
 
 @brief Creates an empty buffer of size length
 
 The bytes in the output are uninitialized

 @param len the number of bytes the buffer should hold.
 @return a newly allocated buffer holding len bytes, or NULL if allocation fails or len is 0.
 */
wickr_buffer_t *wickr_buffer_create_empty(size_t len);

/**
 
 @ingroup wickr_buffer
 
 @brief Creates an zeroed empty buffer of size length
 
 The bytes in the output are initialized to 0
 
 @param len the number of bytes the buffer should hold.
 @return a newly allocated buffer holding len bytes, or NULL if allocation fails or len is 0.
 */
wickr_buffer_t *wickr_buffer_create_empty_zero(size_t len);

/**
 
 @ingroup wickr_buffer
 
 @brief Creates a buffer by copying an existing pointer to bytes of a specified length len
 
 @param bytes a valid pointer to bytes of at least size len
 @param len the number of bytes the buffer should hold.
 @return a newly allocated buffer holding len bytes copied from bytes.
 */
wickr_buffer_t *wickr_buffer_create(const uint8_t *bytes, size_t len);

/**
 
 @ingroup wickr_buffer
 
 @brief Copy a buffer

 @param source the buffer to copy
 @return a newly allocated buffer containing a copy of the bytes held in source. The new buffer maintains ownership of the copied bytes
 */
wickr_buffer_t *wickr_buffer_copy(const wickr_buffer_t *source);

/**
 
 @ingroup wickr_buffer
 
 @brief Create a buffer using a subsection of another buffer

 @param source the buffer to copy bytes out of
 @param start the offset to start the copy process. Must be within the bounds 0 to source->length - 1
 @param len the number of bytes to copy out of 'source'. start + len must be less than source->length
 @return a newly allocated buffer containing the bytes within the range of start to start + len. NULL if start + len exceeds the length of source, or if start is out of bounds
 */
wickr_buffer_t *wickr_buffer_copy_section(const wickr_buffer_t *source, size_t start, size_t len);

/**
 
 @ingroup wickr_buffer
 
 @brief Modify a subsection of a buffer.
 
 NOTE: Buffers will not grow to accomidate extra bytes. The size of a buffer is currently fixed and cannot be modified

 @param buffer buffer to modify
 @param bytes pointer to bytes to copy into 'buffer'
 @param start the position to start overwriting the bytes held by buffer with 'bytes'. Must be within the bounds 0 to source->length - 1
 @param len the number of bytes from 'bytes' to copy into the bytes held by 'buffer'. start + len must be less than source->length.
 @return true if the modification succeeds. false if start is out of range, or start + len is greater than source->length
 */
bool wickr_buffer_modify_section(const wickr_buffer_t *buffer, const uint8_t *bytes, size_t start, size_t len);


/**
 
 @ingroup wickr_buffer
 
 @brief Concatenate two buffers into one new buffer

 @param buffer1 first source buffer
 @param buffer2 second source buffer
 @return a newly allocated buffer containing copied bytes from 'buffer1' followed by copied bytes from 'buffer2'. NULL if the length of 'buffer1' combind with the length of 'buffer2' exceeds MAX_BUFFER_SIZE
 */
wickr_buffer_t *wickr_buffer_concat(const wickr_buffer_t *buffer1, const wickr_buffer_t *buffer2);

/**
 
 @ingroup wickr_buffer
 
 @brief Concatenate n buffers

 @param buffers a pointer to an array of buffers of n length
 @param n_buffers the number of buffers in the array pointed to by buffers
 @return a newly allocated buffer containing copied bytes from each buffer in 'buffers'. NULL if 'buffers' contains a NULL or the total number of bytes held by 'buffers' exceeds MAX_BUFFER_SIZE
 */
wickr_buffer_t *wickr_buffer_concat_multi(wickr_buffer_t **buffers, uint8_t n_buffers);

/**
 
 @ingroup wickr_buffer
 
 @brief Compare buffers for equality

 @param b1 buffer to compare to b2
 @param b2 buffer to compare to b1
 @param compare_func the function that will be used to compare the buffers. Passing NULL will result in memcmp being used. Function takes input as const volatile to support constant time memory comparison implemented by many crypto libraries
 @return true if the buffers are equal in length and in content
 */
bool wickr_buffer_is_equal(const wickr_buffer_t *b1,
                           const wickr_buffer_t *b2,
                           wickr_buffer_compare_func compare_func);
/**
 
 @ingroup wickr_buffer
 
 @brief Destroy a buffer

 NOTE: This function does not modify the contents of buffer and simply calls free to deallocate the memory held. To zero out memory before deallocation use 'wickr_buffer_destroy_zero'
 
 @param buffer the buffer to destroy
 */
void wickr_buffer_destroy(wickr_buffer_t **buffer);


/**
 
 @ingroup wickr_buffer
 
 @brief Zero-then-deallocate a buffer

 @param buffer the buffer to zero out and then destroy
 */
void wickr_buffer_destroy_zero(wickr_buffer_t **buffer);

#ifdef __cplusplus
}
#endif

#endif /* buffer_h */
