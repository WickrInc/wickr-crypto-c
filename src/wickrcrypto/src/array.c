
#include "array.h"
#include "memory.h"

struct wickr_array {
    uint32_t size;
    uint8_t item_type;
    void * (*item_copy_func) (void *);
    void (*item_destroy_func)(void **);
    wickr_buffer_t *item_store;
};

typedef struct wickr_array_item wickr_array_item_t;

wickr_array_t *wickr_array_new(uint32_t item_count,
                               uint8_t item_type,
                               wickr_array_copy_func item_copy_func,
                               wickr_array_destroy_func item_destroy_func)
{
    if (!item_copy_func || !item_destroy_func) {
        return NULL;
    }
    
    wickr_buffer_t *item_store = NULL;
    
    if (item_count != 0) {
        item_store = wickr_buffer_create_empty_zero(sizeof(uintptr_t) * item_count);
        
        if (!item_store) {
            return NULL;
        }
    }
    
    wickr_array_t *new_array = wickr_alloc_zero(sizeof(wickr_array_t));
    
    if (!new_array) {
        wickr_buffer_destroy(&item_store);
        return NULL;
    }
    
    new_array->size = item_count;
    new_array->item_type = item_type;
    new_array->item_store = item_store;
    new_array->item_copy_func = item_copy_func;
    new_array->item_destroy_func = item_destroy_func;
    
    return new_array;
}

uint32_t wickr_array_get_item_count(const wickr_array_t *array)
{
    if (!array) {
        return 0;
    }
    
    return array->size;
}

static bool __wickr_array_index_in_bounds(const wickr_array_t *array, uint32_t index)
{
    if (!array || array->size <= index) {
        return false;
    }
    
    return true;
}

static void *__wickr_array_pointer_to_index(const wickr_array_t *array, uint32_t index)
{
    if (!__wickr_array_index_in_bounds(array, index)) {
        return NULL;
    }
    uintptr_t *item_list = (uintptr_t *)array->item_store->bytes;
    return (void *)(item_list[index]);
}

bool wickr_array_set_item(wickr_array_t *array, uint32_t index, void *item, bool copy)
{
    if (!__wickr_array_index_in_bounds(array, index)) {
        return false;
    }
    
    void *item_to_write = NULL;
    
    if (item) {
        item_to_write = copy ? array->item_copy_func(item) : item;
        
        if (!item_to_write) {
            return false;
        }
    }
    
    void *one_item = __wickr_array_pointer_to_index(array, index);
    
    if (one_item && copy) {
        array->item_destroy_func(&one_item);
    }
    
	uintptr_t ptr_to_write = (uintptr_t)item_to_write;
    return wickr_buffer_modify_section(array->item_store, (uint8_t *)&ptr_to_write, index * sizeof(uintptr_t), sizeof(uintptr_t));
}

void *wickr_array_fetch_item(const wickr_array_t *array, uint32_t index, bool copy)
{
    void *item = __wickr_array_pointer_to_index(array, index);
    
    if (!item) {
        return NULL;
    }
    
    if (copy) {
        return array->item_copy_func(item);
    }
    
    return item;
    
}

wickr_array_t *wickr_array_copy(const wickr_array_t *array, bool deep_copy)
{
    if (!array) {
        return NULL;
    }
    
    wickr_array_t *copy_array = wickr_array_new(array->size, array->item_type, array->item_copy_func, array->item_destroy_func);
    
    for (unsigned int i = 0; i < array->size; i++) {
        void *one_item = __wickr_array_pointer_to_index(array, i);
        
        if (!wickr_array_set_item(copy_array, i, one_item, deep_copy)) {
            wickr_array_destroy(&copy_array, deep_copy);
            return NULL;
        }
    }
    
    return copy_array;
}

void wickr_array_destroy(wickr_array_t **array, bool destroy_items)
{
    if (!array || !*array) {
        return;
    }
    
    if (destroy_items) {
        for (unsigned int i = 0; i < (*array)->size; i++) {
            void *one_item = __wickr_array_pointer_to_index(*array, i);
            if (one_item) {
                (*array)->item_destroy_func(&one_item);
            }
           
        }
    }
    
    wickr_buffer_destroy(&(*array)->item_store);
    free(*array);
    *array = NULL;
    
}
