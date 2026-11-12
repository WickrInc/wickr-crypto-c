
#include "memory.h"
#include "private/memory_priv.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* WICKR_SECURE_MEMORY: zero every allocation before freeing it, so freed key material
   doesn't stay readable in the heap. The size comes from the allocator itself. */
#ifdef WICKR_SECURE_MEMORY
#if defined(__APPLE__)
#include <malloc/malloc.h>
#define WICKR_ALLOCATION_SIZE(buf) malloc_size(buf)
#elif defined(_WIN32)
#include <malloc.h>
#define WICKR_ALLOCATION_SIZE(buf) _msize(buf)
#else
#include <malloc.h>
#define WICKR_ALLOCATION_SIZE(buf) malloc_usable_size(buf)
#endif

#include <stdbool.h>
#include <sodium.h>

#ifdef _WIN32
static SRWLOCK __secure_lock = SRWLOCK_INIT;
#define SECURE_LOCK() AcquireSRWLockExclusive(&__secure_lock)
#define SECURE_UNLOCK() ReleaseSRWLockExclusive(&__secure_lock)
#define SECURE_COUNT_LOAD() InterlockedCompareExchange(&__secure_count, 0, 0)
static volatile LONG __secure_count = 0;
#else
#include <pthread.h>
static pthread_mutex_t __secure_lock = PTHREAD_MUTEX_INITIALIZER;
#define SECURE_LOCK() pthread_mutex_lock(&__secure_lock)
#define SECURE_UNLOCK() pthread_mutex_unlock(&__secure_lock)
#define SECURE_COUNT_LOAD() __atomic_load_n(&__secure_count, __ATOMIC_ACQUIRE)
static long __secure_count = 0;
#endif

/* Pointers from sodium_malloc, so wickr_free knows to release them with sodium_free.
   Only a handful of long-lived keys use it, so a small array is enough. */
static void **__secure_ptrs = NULL;
static size_t __secure_capacity = 0;

static bool __wickr_secure_track(void *buf)
{
    SECURE_LOCK();
    if ((size_t)__secure_count == __secure_capacity) {
        size_t new_capacity = __secure_capacity ? __secure_capacity * 2 : 16;
        void **grown = realloc(__secure_ptrs, new_capacity * sizeof(void *));
        if (!grown) {
            SECURE_UNLOCK();
            return false;
        }
        __secure_ptrs = grown;
        __secure_capacity = new_capacity;
    }
    __secure_ptrs[__secure_count] = buf;
#ifdef _WIN32
    InterlockedIncrement(&__secure_count);
#else
    __atomic_add_fetch(&__secure_count, 1, __ATOMIC_RELEASE);
#endif
    SECURE_UNLOCK();
    return true;
}

static bool __wickr_secure_untrack(void *buf)
{
    if (SECURE_COUNT_LOAD() == 0) {
        return false;
    }
    bool found = false;
    SECURE_LOCK();
    for (size_t i = 0; i < (size_t)__secure_count; i++) {
        if (__secure_ptrs[i] == buf) {
            __secure_ptrs[i] = __secure_ptrs[__secure_count - 1];
#ifdef _WIN32
            InterlockedDecrement(&__secure_count);
#else
            __atomic_sub_fetch(&__secure_count, 1, __ATOMIC_RELEASE);
#endif
            found = true;
            break;
        }
    }
    SECURE_UNLOCK();
    return found;
}
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

void *wickr_alloc_secure(size_t len)
{
    if (len == 0) {
        return NULL;
    }
#ifdef WICKR_SECURE_MEMORY
    if (sodium_init() < 0) {
        return NULL;
    }
    void *buf = sodium_malloc(len);
    if (!buf) {
        return NULL;
    }
    if (!__wickr_secure_track(buf)) {
        sodium_free(buf);
        return NULL;
    }
    return buf;
#else
    return wickr_alloc_zero(len);
#endif
}

void wickr_free(void *buf)
{
    if (!buf) {
        return;
    }
#ifdef WICKR_SECURE_MEMORY
    if (__wickr_secure_untrack(buf)) {
        sodium_free(buf);
        return;
    }
    wickr_zero(buf, WICKR_ALLOCATION_SIZE(buf));
#endif
    free(buf);
}

void wickr_zero(void *buf, size_t len)
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
}

static void *__wickr_protobuf_alloc(void *allocator_data, size_t size)
{
    (void)allocator_data;
    return malloc(size ? size : 1);
}

static void __wickr_protobuf_free(void *allocator_data, void *pointer)
{
    (void)allocator_data;
    wickr_free(pointer);
}

ProtobufCAllocator wickr_protobuf_allocator = {
    .alloc = __wickr_protobuf_alloc,
    .free = __wickr_protobuf_free,
    .allocator_data = NULL
};
