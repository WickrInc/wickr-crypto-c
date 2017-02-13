
#include "memory.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "Windows.h"
#endif

void *wickr_alloc(size_t len)
{
    if (len == 0) {
        return NULL;
    }
    return malloc(len);
}

void *wickr_alloc_zero(size_t len)
{
    if (len == 0) {
        return NULL;
    }
    return calloc(1, len);
}

void wickr_free(void *buf)
{
    if (!buf) {
        return;
    }
    free(buf);
}

void wickr_free_zero(void *buf, size_t len)
{
    if (!buf || len == 0) {
        return;
    }
    
#ifdef __STDC_WANT_LIB_EXT1__
    if (memset_s(buf, (rsize_t)len, 0, (rsize_t)len) != 0) {
        abort();
    }
#elif _WIN32
    SecureZeroMemory(buf, len);
#else
    volatile unsigned char *volatile volatile_buf = (volatile unsigned char * volatile) buf;
    size_t i = 0;
    
    while (i < len) {
        volatile_buf[i++] = 0;
    }
#endif
    wickr_free(buf);
}
