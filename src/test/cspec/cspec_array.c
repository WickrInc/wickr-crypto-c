#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "cspec_array.h"

#define N 10

array_t* array_new(size_t element_size)
{
    array_t* array;
    if (0 == element_size) {
        return NULL;
    }
    array = malloc(sizeof(array_t));
    if (NULL == array) {
        return NULL;
    }
    array->element_size = element_size;
    array->size = 0;
    array->capacity = 0;
    array->data = NULL;
    return array;
}
void array_delete(array_t** const array)
{
    void* p;

    if ((NULL == array) || (NULL == *array)) {
        return;
    }
    (*array)->element_size = 0;
    (*array)->size = 0;
    (*array)->capacity = 0;
    if (NULL != (*array)->data) {
        free((*array)->data);
        (*array)->data = NULL;
    }
    p = *array;
    free(p);
    *array = NULL;
}
int array_add(array_t* const array, const void* const data)
{
    if ((NULL == array) || (NULL == data)) {
        return 1;
    }

    if (0 == (array->size % N)) {
        size_t new_size = (array->size + N) * array->element_size;
        char* p = realloc(array->data, new_size);
        if (NULL == p) {
            return -1;
        }
        array->data = p;
        array->capacity = new_size;
    }
    assert((array->size + 1) * array->element_size < array->capacity);
    memcpy(array->data + array->size * array->element_size, data, array->element_size);
    ++array->size;

    return 0;
}
void* array_get_element(array_t* const array, size_t idx)
{
    if ((NULL == array) || (array->size <= idx) || (NULL == array->data)) {
        return NULL;
    }
    return array->data + idx * array->element_size;
}

