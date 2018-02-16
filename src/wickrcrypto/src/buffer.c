
#include "buffer.h"
#include "memory.h"
#include <string.h>

static bool __validate_buffer_range(const wickr_buffer_t *buffer, size_t start, size_t len)
{
    if (!buffer) {
        return NULL;
    }
    
    if (start >= MAX_BUFFER_SIZE || len >= MAX_BUFFER_SIZE || len == 0) {
        return false;
    }
    
    if (len > (MAX_BUFFER_SIZE - start)) {
        return false;
    }
    
    if (buffer->length < start + len) {
        return false;
    }
    
    return true;
}

static wickr_buffer_t *__wickr_buffer_create_empty(size_t len, void *(*alloc_func)(size_t))
{
    if (len > MAX_BUFFER_SIZE || len == 0 || !alloc_func) {
        return NULL;
    }
    
    uint8_t *bytes = alloc_func(len + sizeof(wickr_buffer_t));
    
    if (!bytes) {
        return NULL;
    }
    
    wickr_buffer_t *new_buffer = (wickr_buffer_t *)bytes;
    
    new_buffer->bytes = (uint8_t *)(new_buffer + 1);
    new_buffer->length = len;
    
    return new_buffer;
}

wickr_buffer_t *wickr_buffer_create_empty(size_t len)
{
    return __wickr_buffer_create_empty(len, wickr_alloc);
}

wickr_buffer_t *wickr_buffer_create_empty_zero(size_t len)
{
    return __wickr_buffer_create_empty(len, wickr_alloc_zero);
}

wickr_buffer_t *wickr_buffer_create(const uint8_t *bytes, size_t len)
{
    if (!bytes) {
        return NULL;
    }
    
    wickr_buffer_t *new_buffer = wickr_buffer_create_empty(len);
    
    if (!new_buffer) {
        return NULL;
    }
    
    memcpy(new_buffer->bytes, bytes, len);
    
    return new_buffer;
}

wickr_buffer_t *wickr_buffer_copy(const wickr_buffer_t *source)
{
    if (!source) {
        return NULL;
    }
    return wickr_buffer_create(source->bytes, source->length);
}

wickr_buffer_t *wickr_buffer_copy_section(const wickr_buffer_t *source, size_t start, size_t len)
{
    if (!source) {
        return NULL;
    }
    
    if (!__validate_buffer_range(source, start, len)) {
        return NULL;
    }
    
    return wickr_buffer_create(source->bytes + start, len);
}

wickr_buffer_t *wickr_buffer_concat(const wickr_buffer_t *buffer1, const wickr_buffer_t *buffer2)
{
    if (!buffer1 || !buffer2) {
        return NULL;
    }
    
    if (buffer1->length > MAX_BUFFER_SIZE || buffer2->length > MAX_BUFFER_SIZE) {
        return NULL;
    }
    
    if ((MAX_BUFFER_SIZE - buffer1->length) < buffer2->length) {
        return NULL;
    }
    
    wickr_buffer_t *new_buffer = wickr_buffer_create_empty(buffer1->length + buffer2->length);
    
    if (!new_buffer) {
        return NULL;
    }
    
    memcpy(new_buffer->bytes, buffer1->bytes, buffer1->length);
    memcpy(new_buffer->bytes + buffer1->length, buffer2->bytes, buffer2->length);
    
    return new_buffer;
}

wickr_buffer_t *wickr_buffer_concat_multi(wickr_buffer_t **buffers, uint8_t n_buffers)
{
    if (!buffers || n_buffers == 0) {
        return NULL;
    }
    
    size_t count = 0;
    
    /* Determine the required byte count of the merged buffer, and make sure it doesn't overflow MAX_BUFFER_SIZE */
    for (uint8_t i = 0; i < n_buffers; i++) {
        wickr_buffer_t *one_buffer = buffers[i];
        
        if (!one_buffer || one_buffer->length == 0) {
            continue;
        }
        
        if (one_buffer->length > MAX_BUFFER_SIZE || MAX_BUFFER_SIZE - count < one_buffer->length) {
            return NULL;
        }
        
        count += one_buffer->length;
    }
    
    wickr_buffer_t *merged_buffer = wickr_buffer_create_empty(count);
    
    if (!merged_buffer) {
        return NULL;
    }
    
    /* Copy the data out of each buffer into the merged buffer */
    
    count = 0;

    for (uint8_t i = 0; i < n_buffers; i++) {
        wickr_buffer_t *one_buffer = buffers[i];
        
        if (!one_buffer || one_buffer->length == 0) {
            continue;
        }
        
        memcpy(merged_buffer->bytes + count, one_buffer->bytes, one_buffer->length);
        count += one_buffer->length;
    }
    
    return merged_buffer;
}

bool wickr_buffer_modify_section(const wickr_buffer_t *buffer, const uint8_t *bytes, size_t start, size_t len)
{
    if (!buffer || !bytes) {
        return NULL;
    }
    
    if (!__validate_buffer_range(buffer, start, len)) {
        return false;
    }
    
    memcpy(buffer->bytes + start, bytes, len);
    
    return true;
}

bool wickr_buffer_is_equal(const wickr_buffer_t *b1,
                           const wickr_buffer_t *b2,
                           wickr_buffer_compare_func compare_func)
{
    if (!b1 || !b2) {
        return false;
    }
    
    if (b1->length != b2->length) {
        return false;
    }
    
    /* If we don't provide a comparison function, use the standard memcmp function */
    if (!compare_func) {
        if (memcmp(b1->bytes, b2->bytes, b1->length) != 0) {
            return false;
        }
    }
    else if (compare_func(b1->bytes, b2->bytes, b1->length) != 0) {
        return false;
    }
    
    return true;
}

void wickr_buffer_destroy_zero(wickr_buffer_t **buffer)
{
    if (!buffer || !*buffer) {
        return;
    }
    
    wickr_free_zero(*buffer, (*buffer)->length);
    *buffer = NULL;
}

void wickr_buffer_destroy(wickr_buffer_t **buffer)
{
    if (!buffer || !*buffer) {
        return;
    }
    
    wickr_free(*buffer);
    *buffer = NULL;
}
