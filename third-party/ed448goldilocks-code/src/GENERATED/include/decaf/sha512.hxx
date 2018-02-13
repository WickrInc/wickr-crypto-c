/**
 * @file decaf/sha512.hxx
 * @copyright
 *   Based on public domain code by Dan Bernstein \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA512 instance, C++ wrapper.
 */

#ifndef __DECAF_SHA512_HXX__
#define __DECAF_SHA512_HXX__

#include <decaf/secure_buffer.hxx>
#include <decaf/sha512.h>
#include <sys/types.h>

/** @cond internal */
#if __cplusplus >= 201103L
    #define DECAF_NOEXCEPT noexcept
#else
    #define DECAF_NOEXCEPT throw()
#endif
/** @endcond */

namespace decaf {
  
/** SHA512 wrapper function */
class SHA512 {
protected:
    /** @cond internal */
    /** The C-wrapper sponge state */
    decaf_sha512_ctx_t wrapped;
    /** @endcond */

public:
    /** Number of bytes ouf output */
    static const size_t OUTPUT_BYTES = 64;
    
    /** Number of bytes of output */
    static const size_t MAX_OUTPUT_BYTES = OUTPUT_BYTES;
    
    /** Default number of bytes to output */
    static const size_t DEFAULT_OUTPUT_BYTES = OUTPUT_BYTES;
    
    /** Constructor */
    inline SHA512() DECAF_NOEXCEPT { decaf_sha512_init(wrapped); }
    
    /** Add more data to running hash */
    inline void update(const uint8_t *__restrict__ in, size_t len) DECAF_NOEXCEPT { decaf_sha512_update(wrapped,in,len); }

    /** Add more data to running hash, C++ version. */
    inline void update(const Block &s) DECAF_NOEXCEPT { update(s.data(),s.size()); }

    /** Add more data, stream version. */
    inline SHA512 &operator<<(const Block &s) { update(s); return *this; }

    /** Same as <<. */
    inline SHA512 &operator+=(const Block &s) { return *this << s; }
    
    /** @brief Output bytes from the SHA context, and resets it. */
    inline void final(Buffer b) /*throw(LengthException)*/ {
        if (b.size() > OUTPUT_BYTES) throw LengthException();
        decaf_sha512_final(wrapped,b.data(),b.size());
    }
    
    /** Resets the SHA context */
    inline void reset() DECAF_NOEXCEPT { decaf_sha512_init(wrapped); }

    /** @brief Output bytes from the sponge. */
    inline SecureBuffer final(size_t len = OUTPUT_BYTES) /*throw(LengthException)*/ {
        if (len > OUTPUT_BYTES) throw LengthException();
        SecureBuffer buffer(len);
        decaf_sha512_final(wrapped,buffer.data(),len);
        return buffer;
    }

    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const DECAF_NOEXCEPT { return OUTPUT_BYTES; }

    /** @brief Return the sponge's maximum output size. */
    inline size_t max_output_size() const DECAF_NOEXCEPT { return MAX_OUTPUT_BYTES; }

    /** @brief Hash a message in one pass */
    static inline SecureBuffer hash (
        const Block &message,
        size_t outlen = OUTPUT_BYTES
    ) /*throw(LengthException, std::bad_alloc)*/ {
        if (outlen > OUTPUT_BYTES) throw LengthException();
        SecureBuffer buffer(outlen);
        decaf_sha512_hash(buffer.data(),outlen,message.data(),message.size());
        return buffer;
    }

    /** Destructor zeroizes state */
    inline ~SHA512() DECAF_NOEXCEPT { decaf_sha512_destroy(wrapped); }
};
  
} /* namespace decaf */

#undef DECAF_NOEXCEPT

#endif /* __DECAF_SHA512_HXX__ */
