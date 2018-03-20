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

#ifndef array_h
#define array_h

#include <stdlib.h>
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup wickr_array wickr_array_t */

struct wickr_array;
typedef struct wickr_array wickr_array_t;

typedef void *(*wickr_array_copy_func)(void*);
typedef void (*wickr_array_destroy_func)(void**);

/**
 @ingroup wickr_array
 
 Create a new array

 @param item_count number of items the array will hold
 @param item_type an integer that will designate the type of item the array will hold. All items in the array must be of the same type
 @param item_copy_func a function that will provide a deep copy of an item in the array
 @param item_destroy_func a function that will provide freeing memory consumed by an item in the array
 @return a newly allocated array
 */
wickr_array_t *wickr_array_new(uint32_t item_count,
                               uint8_t item_type,
                               wickr_array_copy_func item_copy_func,
                               wickr_array_destroy_func item_destroy_func);


/**
 @ingroup wickr_array 
 
 Fetch the size of the array
 
 Note that null values in the array, or uninitialized values in the array will still be counted. The size of the array remains static after it has been created with wickr_array_new. Increasing or decreasing the size of the array is not yet supported

 @param array an array to get the item count of
 @return the number of items contained in the array
 */
uint32_t wickr_array_get_item_count(const wickr_array_t *array);

/**
 @ingroup wickr_array
 
 Assign an item to a specified index in the array

 @param array the array the item is being set into
 @param index the position in the array the item is being set into
 @param item the item that will be set in the array at the specified index
 @param copy if true, a deep copy of the item will be made, and the copy will be inserted into the array
 @return true if the index is within the bounds of the array, and item points to a valid pointer, will return false if copy is set and the copy operation fails
 */
bool wickr_array_set_item(wickr_array_t *array, uint32_t index, void *item, bool copy);


/**
 
 @ingroup wickr_array
 
 Fetch an item at a specified index

 @param array the array from which an item will be fetched
 @param index the position in the array the item will be fetched from
 @param copy if true, a deep copy will be made and returned instead of the item stored in the array
 @return the item in the array at position 'index'. NULL is returned if the index is not within the bounds of the array, if the item at position 'index' is NULL because it was never set with 'wickr_array_set_item', or because copy was true and the copy operation failed
 */
void *wickr_array_fetch_item(const wickr_array_t *array, uint32_t index, bool copy);

/**
 
 @ingroup wickr_array
 
 Make a copy

 @param array the array that is being copied
 @param deep_copy if true, items inserted into the copied array will be a deep copy of items in the original array. If false, items in the original array will be inserted into the new array without transferring ownership
 @return a copy of the array, or NULL if either allocating the copied array fails, or the deep_copy flag is set, and the copy operation fails on one of the items in the source array
 */
wickr_array_t *wickr_array_copy(const wickr_array_t *array, bool deep_copy);

/**
 Free an array
 
 @ingroup wickr_array

 @param array the array to destroy
 @param destroy_items if true, the destroy function specified in 'wickr_array_create' will be called on each item in the array before destroying the array itself
 */
void wickr_array_destroy(wickr_array_t **array, bool destroy_items);

#ifdef __cplusplus
}
#endif

#endif /* array_h */
