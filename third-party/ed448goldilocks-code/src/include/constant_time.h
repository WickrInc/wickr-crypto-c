/**
 * @file constant_time.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 *
 * @brief Constant-time routines.
 */

#ifndef __CONSTANT_TIME_H__
#define __CONSTANT_TIME_H__ 1

#include "word.h"
#include <string.h>

/*
 * Constant-time operations on hopefully-compile-time-sized memory
 * regions.  Needed for flexibility / demagication: not all fields
 * have sizes which are multiples of the vector width, necessitating
 * a change from the Ed448 versions.
 *
 * These routines would be much simpler to define at the byte level,
 * but if not vectorized they would be a significant fraction of the
 * runtime.  Eg on NEON-less ARM, constant_time_lookup is like 15% of
 * signing time, vs 6% on Haswell with its fancy AVX2 vectors.
 *
 * If the compiler could do a good job of autovectorizing the code,
 * we could just leave it with the byte definition.  But that's unlikely
 * on most deployed compilers, especially if you consider that pcmpeq[size]
 * is much faster than moving a scalar to the vector unit (which is what
 * a naive autovectorizer will do with constant_time_lookup on Intel).
 *
 * Instead, we're putting our trust in the loop unroller and unswitcher.
 */


/**
 * Unaligned big (vector?) register.
 */
typedef struct {
    big_register_t unaligned;
} __attribute__((packed)) unaligned_br_t;

/**
 * Unaligned word register, for architectures where that matters.
 */
typedef struct {
    word_t unaligned;
} __attribute__((packed)) unaligned_word_t;

/**
 * @brief Constant-time conditional swap.
 *
 * If doswap, then swap elem_bytes between *a and *b.
 *
 * *a and *b must not alias.  Also, they must be at least as aligned
 * as their sizes, if the CPU cares about that sort of thing.
 */
static __inline__ void
__attribute__((unused,always_inline))
constant_time_cond_swap (
    void *__restrict__ a_,
    void *__restrict__ b_,
    word_t elem_bytes,
    mask_t doswap
) {
    word_t k;
    unsigned char *a = (unsigned char *)a_;
    unsigned char *b = (unsigned char *)b_;
    
    big_register_t br_mask = br_set_to_mask(doswap);
    for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
        if (elem_bytes % sizeof(big_register_t)) {
            /* unaligned */
            big_register_t xor =
                ((unaligned_br_t*)(&a[k]))->unaligned
              ^ ((unaligned_br_t*)(&b[k]))->unaligned;
            xor &= br_mask;
            ((unaligned_br_t*)(&a[k]))->unaligned ^= xor;
            ((unaligned_br_t*)(&b[k]))->unaligned ^= xor;
        } else {
            /* aligned */
            big_register_t xor =
                *((big_register_t*)(&a[k]))
              ^ *((big_register_t*)(&b[k]));
            xor &= br_mask;
            *((big_register_t*)(&a[k])) ^= xor;
            *((big_register_t*)(&b[k])) ^= xor;
        }
    }

    if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
        for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
            if (elem_bytes % sizeof(word_t)) {
                /* unaligned */
                word_t xor =
                    ((unaligned_word_t*)(&a[k]))->unaligned
                  ^ ((unaligned_word_t*)(&b[k]))->unaligned;
                xor &= doswap;
                ((unaligned_word_t*)(&a[k]))->unaligned ^= xor;
                ((unaligned_word_t*)(&b[k]))->unaligned ^= xor;
            } else {
                /* aligned */
                word_t xor =
                    *((word_t*)(&a[k]))
                  ^ *((word_t*)(&b[k]));
                xor &= doswap;
                *((word_t*)(&a[k])) ^= xor;
                *((word_t*)(&b[k])) ^= xor;
            }
        }
    }
    
    if (elem_bytes % sizeof(word_t)) {
        for (; k<elem_bytes; k+=1) {
            unsigned char xor = a[k] ^ b[k];
            xor &= doswap;
            a[k] ^= xor;
            b[k] ^= xor;
        }
    }
}

/**
 * @brief Constant-time equivalent of memcpy(out, table + elem_bytes*idx, elem_bytes);
 *
 * The table must be at least as aligned as elem_bytes.  The output must be word aligned,
 * and if the input size is vector aligned it must also be vector aligned.
 *
 * The table and output must not alias.
 */
static __inline__ void
__attribute__((unused,always_inline))
constant_time_lookup (
    void *__restrict__ out_,
    const void *table_,
    word_t elem_bytes,
    word_t n_table,
    word_t idx
) {
    big_register_t big_one = br_set_to_mask(1), big_i = br_set_to_mask(idx);
    
    /* Can't do pointer arithmetic on void* */
    unsigned char *out = (unsigned char *)out_;
    const unsigned char *table = (const unsigned char *)table_;
    word_t j,k;
    
    memset(out, 0, elem_bytes);
    for (j=0; j<n_table; j++, big_i-=big_one) {        
        big_register_t br_mask = br_is_zero(big_i);
        for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
            if (elem_bytes % sizeof(big_register_t)) {
                /* unaligned */
                ((unaligned_br_t *)(out+k))->unaligned
			|= br_mask & ((const unaligned_br_t*)(&table[k+j*elem_bytes]))->unaligned;
            } else {
                /* aligned */
                *(big_register_t *)(out+k) |= br_mask & *(const big_register_t*)(&table[k+j*elem_bytes]);
            }
        }

        word_t mask = word_is_zero(idx^j);
        if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
            for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
                if (elem_bytes % sizeof(word_t)) {
                    /* input unaligned, output aligned */
                    *(word_t *)(out+k) |= mask & ((const unaligned_word_t*)(&table[k+j*elem_bytes]))->unaligned;
                } else {
                    /* aligned */
                    *(word_t *)(out+k) |= mask & *(const word_t*)(&table[k+j*elem_bytes]);
                }
            }
        }
        
        if (elem_bytes % sizeof(word_t)) {
            for (; k<elem_bytes; k+=1) {
                out[k] |= mask & table[k+j*elem_bytes];
            }
        }
    }
}

/**
 * @brief Constant-time equivalent of memcpy(table + elem_bytes*idx, in, elem_bytes);
 *
 * The table must be at least as aligned as elem_bytes.  The input must be word aligned,
 * and if the output size is vector aligned it must also be vector aligned.
 *
 * The table and input must not alias.
 */
static __inline__ void
__attribute__((unused,always_inline))
constant_time_insert (
    void *__restrict__ table_,
    const void *in_,
    word_t elem_bytes,
    word_t n_table,
    word_t idx
) {
    big_register_t big_one = br_set_to_mask(1), big_i = br_set_to_mask(idx);
    
    /* Can't do pointer arithmetic on void* */
    const unsigned char *in = (const unsigned char *)in_;
    unsigned char *table = (unsigned char *)table_;
    word_t j,k;
    
    for (j=0; j<n_table; j++, big_i-=big_one) {        
        big_register_t br_mask = br_is_zero(big_i);
        for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
            if (elem_bytes % sizeof(big_register_t)) {
                /* unaligned */
                ((unaligned_br_t*)(&table[k+j*elem_bytes]))->unaligned
                    = ( ((unaligned_br_t*)(&table[k+j*elem_bytes]))->unaligned & ~br_mask )
                    | ( ((const unaligned_br_t *)(in+k))->unaligned & br_mask );
            } else {
                /* aligned */
                *(big_register_t*)(&table[k+j*elem_bytes])
                    = ( *(big_register_t*)(&table[k+j*elem_bytes]) & ~br_mask )
                    | ( *(const big_register_t *)(in+k) & br_mask );
            }
        }

        word_t mask = word_is_zero(idx^j);
        if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
            for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
                if (elem_bytes % sizeof(word_t)) {
                    /* output unaligned, input aligned */
                    ((unaligned_word_t*)(&table[k+j*elem_bytes]))->unaligned
                        = ( ((unaligned_word_t*)(&table[k+j*elem_bytes]))->unaligned & ~mask )
                        | ( *(const word_t *)(in+k) & mask );
                } else {
                    /* aligned */
                    *(word_t*)(&table[k+j*elem_bytes])
                        = ( *(word_t*)(&table[k+j*elem_bytes]) & ~mask )
                        | ( *(const word_t *)(in+k) & mask );
                }
            }
        }
        
        if (elem_bytes % sizeof(word_t)) {
            for (; k<elem_bytes; k+=1) {
                table[k+j*elem_bytes]
                    = ( table[k+j*elem_bytes] & ~mask )
                    | ( in[k] & mask );
            }
        }
    }
}

/**
 * @brief Constant-time a = b&mask.
 *
 * The input and output must be at least as aligned as elem_bytes.
 */
static __inline__ void
__attribute__((unused,always_inline))
constant_time_mask (
    void * a_,
    const void *b_,
    word_t elem_bytes,
    mask_t mask
) {
    unsigned char *a = (unsigned char *)a_;
    const unsigned char *b = (const unsigned char *)b_;
    
    word_t k;
    big_register_t br_mask = br_set_to_mask(mask);
    for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
        if (elem_bytes % sizeof(big_register_t)) {
            /* unaligned */
            ((unaligned_br_t*)(&a[k]))->unaligned = br_mask & ((const unaligned_br_t*)(&b[k]))->unaligned;
        } else {
            /* aligned */
            *(big_register_t *)(a+k) = br_mask & *(const big_register_t*)(&b[k]);
        }
    }

    if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
        for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
            if (elem_bytes % sizeof(word_t)) {
                /* unaligned */
                ((unaligned_word_t*)(&a[k]))->unaligned = mask & ((const unaligned_word_t*)(&b[k]))->unaligned;
            } else {
                /* aligned */
                *(word_t *)(a+k) = mask & *(const word_t*)(&b[k]);
            }
        }
    }
    
    if (elem_bytes % sizeof(word_t)) {
        for (; k<elem_bytes; k+=1) {
            a[k] = mask & b[k];
        }
    }
}

/**
 * @brief Constant-time a = mask ? bTrue : bFalse.
 *
 * The input and output must be at least as aligned as alignment_bytes
 * or their size, whichever is smaller.
 *
 * Note that the output is not __restrict__, but if it overlaps either
 * input, it must be equal and not partially overlap.
 */
static __inline__ void
__attribute__((unused,always_inline))
constant_time_select (
    void *a_,
    const void *bFalse_,
    const void *bTrue_,
    word_t elem_bytes,
    mask_t mask,
    size_t alignment_bytes
) {
    unsigned char *a = (unsigned char *)a_;
    const unsigned char *bTrue = (const unsigned char *)bTrue_;
    const unsigned char *bFalse = (const unsigned char *)bFalse_;
    
    alignment_bytes |= elem_bytes;

    word_t k;
    big_register_t br_mask = br_set_to_mask(mask);
    for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
        if (alignment_bytes % sizeof(big_register_t)) {
            /* unaligned */
            ((unaligned_br_t*)(&a[k]))->unaligned =
		  ( br_mask & ((const unaligned_br_t*)(&bTrue [k]))->unaligned)
		| (~br_mask & ((const unaligned_br_t*)(&bFalse[k]))->unaligned);
        } else {
            /* aligned */
            *(big_register_t *)(a+k) =
		  ( br_mask & *(const big_register_t*)(&bTrue [k]))
		| (~br_mask & *(const big_register_t*)(&bFalse[k]));
        }
    }

    if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
        for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
            if (alignment_bytes % sizeof(word_t)) {
                /* unaligned */
                ((unaligned_word_t*)(&a[k]))->unaligned =
		    ( mask & ((const unaligned_word_t*)(&bTrue [k]))->unaligned)
		  | (~mask & ((const unaligned_word_t*)(&bFalse[k]))->unaligned);
            } else {
                /* aligned */
                *(word_t *)(a+k) =
		    ( mask & *(const word_t*)(&bTrue [k]))
		  | (~mask & *(const word_t*)(&bFalse[k]));
            }
        }
    }
    
    if (elem_bytes % sizeof(word_t)) {
        for (; k<elem_bytes; k+=1) {
            a[k] = ( mask & bTrue[k]) | (~mask & bFalse[k]);
        }
    }
}

#endif /* __CONSTANT_TIME_H__ */
