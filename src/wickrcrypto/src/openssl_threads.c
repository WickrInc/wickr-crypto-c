#include "private/openssl_threads.h"
#include <openssl/crypto.h>
#include <stdbool.h>

#ifdef FIPS
#ifndef _WIN32
#include <pthread.h>

static pthread_mutex_t *lock_cs = NULL;
static long *lock_count = NULL;

static void __openssl_thread_id(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

static void __openssl_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void openssl_thread_initialize_if_necessary(void)
{
    if (lock_cs == NULL) {
                
        int i;

        lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
        lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
        for (i = 0; i < CRYPTO_num_locks(); i++) {
            lock_count[i] = 0;
            pthread_mutex_init(&(lock_cs[i]), NULL);
        }

        CRYPTO_THREADID_set_callback(__openssl_thread_id);
        CRYPTO_set_locking_callback(__openssl_locking_callback);
    }
}

void openssl_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

#else

#include <windows.h>

static HANDLE *lock_cs = NULL;

void __openssl_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        WaitForSingleObject(lock_cs[type], INFINITE);
    } else {
        ReleaseMutex(lock_cs[type]);
    }
}

void openssl_thread_initialize_if_necessary(void)
{
    if (lock_cs == NULL) {
        int i;

        lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
        for (i = 0; i < CRYPTO_num_locks(); i++) {
            lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
        }

        CRYPTO_set_locking_callback((void (*)(int, int, char *, int))
                                    __openssl_locking_callback);
    }
}

void openssl_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        CloseHandle(lock_cs[i]);
    OPENSSL_free(lock_cs);
}

#endif
#endif
