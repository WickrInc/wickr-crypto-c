/**
 * @cond internal
 * @file spongerng.c
 * @copyright
 *   Copyright (c) 2015-2017 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Spongerng instances (STROBE removed)
 * @warning The SpongeRNG code isn't stable.  Future versions are likely to
 * have different outputs.  Of course, this only matters in deterministic mode.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "keccak_internal.h"
#include <decaf/spongerng.h>

/* to open and read from /dev/urandom */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/** Get entropy from a CPU, preferably in the form of RDRAND, but possibly instead from RDTSC. */
static void get_cpu_entropy(uint8_t *entropy, size_t len) {
# if (defined(__i386__) || defined(__x86_64__))
    static char tested = 0, have_rdrand = 0;
    if (!tested) {
        uint32_t a,b,c,d;
#if defined(__i386__) && defined(__PIC__)
        /* Don't clobber ebx.  The compiler doesn't like when when __PIC__ */
        __asm__("mov %%ebx, %[not_ebx]\n\t"
                "cpuid\n\t"
                "xchg %%ebx, %[not_ebx]" : "=a"(a), [not_ebx]"=r"(b), "=c"(c), "=d"(d) : "0"(1));
#elif defined(__x86_64__) && defined(__PIC__)
        /* Don't clobber rbx.  The compiler doesn't like when when __PIC__ */
        uint64_t b64;
        __asm__("mov %%rbx, %[not_rbx]\n\t"
                "cpuid\n\t"
                "xchg %%rbx, %[not_rbx]" : "=a"(a), [not_rbx]"=r"(b64), "=c"(c), "=d"(d) : "0"(1));
        b = b64;
#else
        __asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(1));
#endif
        (void)a; (void)b; (void)d;
        have_rdrand = (c>>30)&1;
        tested = 1;
    }

    if (have_rdrand) {
        # if defined(__x86_64__)
            uint64_t out, a=0, *eo = (uint64_t *)entropy;
        # elif defined(__i386__)
            uint32_t out, a=0, *eo = (uint32_t *)entropy;
        #endif
        len /= sizeof(out);

        uint32_t tries;
        for (tries = 100+len; tries && len; len--, eo++) {
            for (a = 0; tries && !a; tries--) {
                __asm__ __volatile__ ("rdrand %0\n\tsetc %%al" : "=r"(out), "+a"(a) :: "cc" );
            }
            *eo ^= out;
        }
    } else if (len>=8) {
#ifndef __has_builtin
#define __has_builtin(X) 0
#endif
#if defined(__clang__) && __has_builtin(__builtin_readcyclecounter)
        *(uint64_t*) entropy ^= __builtin_readcyclecounter();
#elif defined(__x86_64__)
        uint32_t lobits, hibits;
        __asm__ __volatile__ ("rdtsc" : "=a"(lobits), "=d"(hibits));
        *(uint64_t*) entropy ^= (lobits | ((uint64_t)(hibits) << 32));
#elif defined(__i386__)
        uint64_t __value;
        __asm__ __volatile__ ("rdtsc" : "=A"(__value));
        *(uint64_t*) entropy ^= __value;
#endif
    }

#else
    (void) entropy;
    (void) len;
#endif
}

void decaf_spongerng_next (
    decaf_keccak_prng_t prng,
    uint8_t * __restrict__ out,
    size_t len
) {
    if (prng->sponge->params->remaining) {
        /* nondet */
        uint8_t cpu_entropy[32] = {0};
        get_cpu_entropy(cpu_entropy, sizeof(cpu_entropy));
        decaf_spongerng_stir(prng,cpu_entropy,sizeof(cpu_entropy));
        decaf_bzero(cpu_entropy,sizeof(cpu_entropy));
    }
    
    uint8_t lenx[8];
    size_t len1 = len;
    for (unsigned i=0; i<sizeof(lenx); i++) {
        lenx[i] = len1;
        len1 >>= 8;
    }
    decaf_sha3_update(prng->sponge,lenx,sizeof(lenx));
    decaf_sha3_output(prng->sponge,out,len);
    
    const uint8_t nope;
    decaf_spongerng_stir(prng,&nope,0);
}

void decaf_spongerng_stir (
    decaf_keccak_prng_t prng,
    const uint8_t * __restrict__ in,
    size_t len
) {
    uint8_t seed[32];
    decaf_sha3_output(prng->sponge,seed,sizeof(seed));
    uint8_t nondet = prng->sponge->params->remaining;
    
    decaf_sha3_reset(prng->sponge);
    decaf_sha3_update(prng->sponge,seed,sizeof(seed));
    decaf_sha3_update(prng->sponge,in,len);
    
    prng->sponge->params->remaining = nondet;
    decaf_bzero(seed,sizeof(seed));
}

void decaf_spongerng_init_from_buffer (
    decaf_keccak_prng_t prng,
    const uint8_t * __restrict__ in,
    size_t len,
    int deterministic
) {
    decaf_sha3_init(prng->sponge,&DECAF_SHAKE256_params_s);
    prng->sponge->params->remaining = !deterministic; /* A bit of a hack; this param is ignored for SHAKE */
    decaf_spongerng_stir(prng, in, len);
}

decaf_error_t decaf_spongerng_init_from_file (
    decaf_keccak_prng_t prng,
    const char *file,
    size_t len,
    int deterministic
) {
    decaf_sha3_init(prng->sponge,&DECAF_SHAKE256_params_s);
    prng->sponge->params->remaining = !deterministic; /* A bit of a hack; this param is ignored for SHAKE */
    if (!len) return DECAF_FAILURE;

    int fd = open(file, O_RDONLY);
    if (fd < 0) return DECAF_FAILURE;
    
    uint8_t buffer[128];
    while (len) {
        ssize_t red = read(fd, buffer, (len > sizeof(buffer)) ? sizeof(buffer) : len);
        if (red <= 0) {
            close(fd);
            return DECAF_FAILURE;
        }
        decaf_sha3_update(prng->sponge,buffer,red);
        len -= red;
    };
    close(fd);
    const uint8_t nope;
    decaf_spongerng_stir(prng,&nope,0);
    
    return DECAF_SUCCESS;
}

decaf_error_t decaf_spongerng_init_from_dev_urandom (
    decaf_keccak_prng_t decaf_sponge
) {
    return decaf_spongerng_init_from_file(decaf_sponge, "/dev/urandom", 64, 0);
}
