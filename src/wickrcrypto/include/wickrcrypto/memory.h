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

#ifndef memory_h
#define memory_h

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup memory_functions memory management functions
 
 */

/**
 
 @ingroup memory_functions
 
 Allocate memory from the system

 @param len the number of bytes to allocate
 @return a pointer to 'len' bytes of newly allocated memory, or NULL if the underlying system allocation fails
 */
void *wickr_alloc(size_t len);

/**
 
 @ingroup memory_functions
 
 Allocate zeroed memory from the system

 @param len the number of bytes of zeroed memory to allocate
 @return a pointer to 'len' bytes of newly allocated memory filled with 0s, or NULL if the underlying system allocation fails
 */
void *wickr_alloc_zero(size_t len);

/**
 
 @ingroup memory_functions
 
 Free memory

 @param buf the pointer to memory that needs to be freed
 */
void wickr_free(void *buf);

/**
 
 @ingroup memory_functions
 
 Zero-then-free memory

 @param buf the buffer to fill with 0s and then free
 @param len the number of bytes to fill with 0s before freeing 'buf'
 */
void wickr_free_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* memory_h */
