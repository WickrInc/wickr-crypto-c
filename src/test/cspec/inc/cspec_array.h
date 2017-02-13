#ifndef ARRAY_H
#define ARRAY_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /** size of an element */
    size_t element_size;
    /** size of the number of elements held in the array */
    size_t size;
    /** size of allocated storage capacity */
    size_t capacity;
    /** real data */
    char* data;
} array_t;

/** construct array */
array_t* array_new(size_t element_size);
/** destruct array */
void array_delete(array_t** const array);
/** add an element into the array */
int array_add(array_t* const array, const void* const data);
/** get specified value */
void* array_get_element(array_t* const array, size_t idx);

#ifdef __cplusplus
}
#endif

#endif
