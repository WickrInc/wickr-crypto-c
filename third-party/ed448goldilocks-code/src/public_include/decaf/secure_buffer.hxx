/**
 * @file decaf/secure_buffer.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ self-zeroizing buffer.
 */
#ifndef __DECAF_SECURE_BUFFER_HXX__
#define __DECAF_SECURE_BUFFER_HXX__ 1

#include <string>
#include <sys/types.h>
#include <stdio.h>
#include <vector>
#include <stdexcept>
#include <cstddef>
#include <limits>

/** @cond internal */
#if __cplusplus >= 201103L
#define DECAF_NOEXCEPT noexcept
#define DECAF_DELETE = delete
#else
#define DECAF_NOEXCEPT throw()
#define DECAF_DELETE
#endif
/** @endcond */

namespace decaf {

/**
* Securely zeroize contents of memory.
*/
static inline void really_bzero(void *data, size_t size) { decaf_bzero(data,size); }

/** @brief An allocator which zeros its memory on free */
template<typename T, size_t alignment = 0> class SanitizingAllocator {
/** @cond internal */
/* Based on http://www.codeproject.com/Articles/4795/C-Standard-Allocator-An-Introduction-and-Implement */
public: 
   typedef T value_type;
   typedef T* pointer;
   typedef const T* const_pointer;
   typedef T& reference;
   typedef const T& const_reference;
   typedef size_t size_type;
   typedef std::ptrdiff_t difference_type;
   
   template<typename U> struct rebind { typedef SanitizingAllocator<U> other; };
   inline SanitizingAllocator() DECAF_NOEXCEPT {}
   inline ~SanitizingAllocator() DECAF_NOEXCEPT {}
   inline SanitizingAllocator(const SanitizingAllocator &) DECAF_NOEXCEPT {}
   template<typename U, size_t a> inline SanitizingAllocator(const SanitizingAllocator<U, a> &) DECAF_NOEXCEPT {}
   
   inline T* address(T& r) const DECAF_NOEXCEPT { return &r; }
   inline const T* address(const T& r) const DECAF_NOEXCEPT { return &r; }
   inline T* allocate (
       size_type cnt,
       typename std::allocator<void>::const_pointer = 0
    ) /*throw(std::bad_alloc)*/;
   inline void deallocate(T* p, size_t size) DECAF_NOEXCEPT;
   inline size_t max_size() const DECAF_NOEXCEPT { return std::numeric_limits<size_t>::max() / sizeof(T); }
   inline void construct(T* p, const T& t) { new(p) T(t); }
   inline void destroy(T* p) { p->~T(); }
   
   inline bool operator==(SanitizingAllocator const&) const DECAF_NOEXCEPT { return true; }
   inline bool operator!=(SanitizingAllocator const&) const DECAF_NOEXCEPT { return false; }
/** @endcond */
};

/** A variant of std::vector which securely zerozes its state when destructed. */
typedef std::vector<unsigned char, SanitizingAllocator<unsigned char, 0> > SecureBuffer;

/** Constant-time compare two buffers */
template<class T,class U, class V, class W>
inline bool memeq(const std::vector<T,U> &a, const std::vector<V,W> &b) {
    if (a.size() != b.size()) return false;
    return decaf_memeq(a.data(),b.data(),a.size());
}

/** Base class of objects which support serialization */
template<class Base> class Serializable {
public:
    /** @brief Return the number of bytes needed to serialize this object */
    inline size_t ser_size() const DECAF_NOEXCEPT { return static_cast<const Base*>(this)->ser_size(); }
    
    /** @brief Serialize this object into a buffer */
    inline void serialize_into(unsigned char *buf) const DECAF_NOEXCEPT {
        static_cast<const Base*>(this)->serialize_into(buf);
    }
    
    /** @brief Serialize this object into a SecureBuffer and return it */
    inline SecureBuffer serialize() const /*throw(std::bad_alloc)*/ {
        SecureBuffer out(ser_size());
        serialize_into(out.data());
        return out;
    }
    
    /** Cast operator */
#if __cplusplus >= 201103L
    explicit inline operator SecureBuffer() const /*throw(std::bad_alloc)*/ {
        return serialize();
    }
#endif
};

/**@cond internal*/
class Buffer;
/**@endcond*/
    
/** @brief An exception for when crypto (ie point decode) has failed. */
class CryptoException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const DECAF_NOEXCEPT { return "CryptoException"; }
};

/** @brief An exception for when crypto (ie point decode) has failed. */
class LengthException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const DECAF_NOEXCEPT { return "LengthException"; }
};

/** @brief Passed to constructors to avoid (conservative) initialization */
struct NOINIT {};

/** @brief Prototype of a random number generator.
 * FUTURE: Are the noexcept methods really noexcept?  What about self-reseeding RNGs?
 */
class Rng {
protected:
    /** Empty initializer */
    Rng() {}
    
    /** Not copyable */
    Rng(const Rng &) DECAF_DELETE;
    
    /** Not copyable */
    Rng &operator=(const Rng &) DECAF_DELETE;
    
public:
    /** @brief Read into a Buffer */
    virtual void read(Buffer buffer) DECAF_NOEXCEPT = 0;

    /** @brief Read into a SecureBuffer. */
    inline SecureBuffer read(size_t length) /*throw(std::bad_alloc)*/;
};


/** A reference to a block of data, which (when accessed through this base class) is const. */
class Block {
protected:
    /** @cond internal */
    unsigned char *data_;
    size_t size_;
    const bool zero_on_destroy_;
    /** @endcond */

public:
    /** Null initialization */
    inline Block() : data_(NULL), size_(0), zero_on_destroy_(false) {}
    
    /** Init from C string */
    inline Block(const char *data) DECAF_NOEXCEPT : data_((unsigned char *)data),
        size_(strlen(data)), zero_on_destroy_(false) {}

    /** Unowned init */
    inline Block(const unsigned char *data, size_t size, bool zero_on_destroy=false) DECAF_NOEXCEPT : data_((unsigned char *)data),
        size_(size), zero_on_destroy_(zero_on_destroy) {}
    
    /** Block from std::string */
    inline Block(const std::string &s) : data_(
    #if __cplusplus >= 201103L
        ((unsigned char *)&(s)[0])
    #else
        ((unsigned char *)(s.data()))
    #endif
    ), size_(s.size()), zero_on_destroy_(false) {}
    
    /** Block from std::vector */
    template<class alloc> inline Block(const std::vector<unsigned char,alloc> &s)
        : data_(((unsigned char *)&(s)[0])), size_(s.size()), zero_on_destroy_(false) {}

    /** Get const data */
    inline const unsigned char *data() const DECAF_NOEXCEPT { return data_; }
    
    /** Subscript */
    inline const unsigned char &operator[](size_t off) const /*throw(std::out_of_range)*/ {
        if (off >= size()) throw(std::out_of_range("decaf::Block"));
        return data_[off];
    }

    /** Get the size */
    inline size_t size() const DECAF_NOEXCEPT { return size_; }

    /** Convert to C++ string */
    inline std::string get_string() const {
        return std::string((const char *)data_,size_);
    }

    /** Slice the buffer*/
    inline Block slice(size_t off, size_t length) const /*throw(LengthException)*/ {
        if (off > size() || length > size() - off) throw LengthException();
        return Block(data()+off, length);
    }
    
    /** Content-wise comparison; constant-time if they are the same length. */ 
    inline decaf_bool_t contents_equal(const Block &b) const DECAF_NOEXCEPT {
        if (b.size() != size()) return false;
        return decaf_memeq(b.data(),data(),size());
    }
    
    /** Create new block from this */
    inline operator SecureBuffer() const /*throw(std::bad_alloc)*/ {
        return SecureBuffer(data_,data_+size_);
    }

    /** Securely set the buffer to 0. */
    inline void zeroize() DECAF_NOEXCEPT { really_bzero(data_,size()); }
    
    /** Debugging print in hex */
    inline void debug_print_hex(const char *name = NULL) {
        if (name) printf("%s = ", name);
        for (size_t s = 0; s < size(); s++) printf("%02x", data_[s]);
        printf("\n");
    }
    
private:
    /** @cond internal */
    inline decaf_bool_t operator>=(const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    inline decaf_bool_t operator<=(const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    inline decaf_bool_t operator> (const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    inline decaf_bool_t operator< (const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    inline void operator= (const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    /** @endcond */
};

/** A fixed-size block */
template<size_t Size> class FixedBlock : public Block {
public:
    /** Check a block's length. */
    inline FixedBlock(const Block &b) /*throw(LengthException)*/ : Block(b.data(),Size) {
        if (Size != b.size()) throw LengthException();
    }
    
    /** Block from std::vector */
    template<class alloc> inline FixedBlock(const std::vector<unsigned char,alloc> &s) : Block(s) {
        if (Size != s.size()) throw LengthException();
    }
    
    /** Explicitly pass a C buffer. */
    inline explicit FixedBlock(const uint8_t data[Size]) DECAF_NOEXCEPT : Block(data,Size) {}
};

/** A reference to a writable block of data */
class Buffer : public Block {
public:
    /** Null init */
    inline Buffer() DECAF_NOEXCEPT : Block() {}

    /** Unowned init */
    inline Buffer(unsigned char *data, size_t size, bool zero_on_destroy=false) DECAF_NOEXCEPT : Block(data,size,zero_on_destroy) {}
    
    /** Block from std::vector */
    template<class alloc> inline Buffer(std::vector<unsigned char,alloc> &s) : Block(s) {}

    /** Get const data */
    inline const unsigned char *data() const DECAF_NOEXCEPT { return data_; }

    /** Cast to unsigned char */
    inline unsigned char* data() DECAF_NOEXCEPT { return data_; }

    /** Slice the buffer*/
    inline Buffer slice(size_t off, size_t length) /*throw(LengthException)*/;
    
    /** Subscript */
    inline unsigned char &operator[](size_t off) /*throw(std::out_of_range)*/ {
        if (off >= size()) throw(std::out_of_range("decaf::Buffer"));
        return data_[off];
    }
    
    /** Copy from another block */
    inline void assign(const Block b) /*throw(LengthException)*/ {
        if (b.size() != size()) throw LengthException();
        memmove(data(),b.data(),size());
    }
    
private:
    /** @cond internal */
    inline void operator= (const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    /** @endcond */
};


/** A fixed-size block */
template<size_t Size> class FixedBuffer : public Buffer {
public:
    /** Check a block's length. */
    inline FixedBuffer(Buffer b) /*throw(LengthException)*/ : Buffer(b) {
        if (Size != b.size()) throw LengthException();
    }
    
    /** Check a block's length. */
    inline FixedBuffer(SecureBuffer &b) /*throw(LengthException)*/ : Buffer(b) {
        if (Size != b.size()) throw LengthException();
    }
    
    /** Explicitly pass a C buffer. */
    inline explicit FixedBuffer(uint8_t dat[Size],bool zero_on_destroy = false) DECAF_NOEXCEPT : Buffer(dat,Size,zero_on_destroy) {}
    
    /** Cast to a FixedBlock. */
    inline operator FixedBlock<Size>() const DECAF_NOEXCEPT {
        return FixedBlock<Size>(data());
    }
    
private:
    /** @cond internal */
    inline void operator= (const Block &b) const DECAF_NOEXCEPT DECAF_DELETE;
    /** @endcond */
};

/** A fixed-size stack-allocated buffer (for DECAF_NOEXCEPT semantics) */
template<size_t Size> class FixedArrayBuffer : public FixedBuffer<Size> {
private:
    uint8_t storage[Size];
public:
    using Buffer::zeroize;
    
    /** New buffer initialized to zero. */
    inline explicit FixedArrayBuffer() DECAF_NOEXCEPT : FixedBuffer<Size>(storage,true) { memset(storage,0,Size); }

    /** New uninitialized buffer. */
    inline explicit FixedArrayBuffer(const NOINIT &) DECAF_NOEXCEPT : FixedBuffer<Size>(storage,true) { }
    
    /** New random buffer */
    inline explicit FixedArrayBuffer(Rng &r) DECAF_NOEXCEPT : FixedBuffer<Size>(storage,true) { r.read(*this); }
    
    /** Copy constructor */
    inline explicit FixedArrayBuffer(const FixedBlock<Size> &b) DECAF_NOEXCEPT : FixedBuffer<Size>(storage,true) {
        memcpy(storage,b.data(),Size);
    }
    
    /** Copy operator */
    inline FixedArrayBuffer& operator=(const FixedBlock<Size> &b) DECAF_NOEXCEPT {
        memcpy(storage,b.data(),Size); return *this;
    }
    
    /** Copy operator */
    inline FixedArrayBuffer& operator=(const FixedArrayBuffer<Size> &b) DECAF_NOEXCEPT {
        memcpy(storage,b.data(),Size); return *this;
    }
    
    /** Copy operator */
    inline FixedArrayBuffer& operator=(const Block &b) /*throw(LengthException)*/ {
        *this = FixedBlock<Size>(b);
    }
    
    /** Copy constructor */
    inline explicit FixedArrayBuffer(const Block &b) /*throw(LengthException)*/ : FixedBuffer<Size>(storage,true) {
        if (b.size() != Size) throw LengthException();
        memcpy(storage,b.data(),Size);
    }
    
    /** Copy constructor */
    inline explicit FixedArrayBuffer(const FixedArrayBuffer<Size> &b) DECAF_NOEXCEPT : FixedBuffer<Size>(storage,true) {
        memcpy(storage,b.data(),Size);
    }
    
    /** Destroy the buffer */
    ~FixedArrayBuffer() DECAF_NOEXCEPT { zeroize(); }
};

/** @cond internal */
Buffer Buffer::slice(size_t off, size_t length) /*throw(LengthException)*/ {
    if (off > size() || length > size() - off) throw LengthException();
    return Buffer(data()+off, length);
}

inline SecureBuffer Rng::read(size_t length) /*throw(std::bad_alloc)*/ {
    SecureBuffer out(length); read(out); return out;
}
/** @endcond */

/** @cond internal */
/** A secure buffer which stores an owned or unowned underlying value.
 * If it is owned, it will be securely zeroed.
 */
template <class T, class Wrapped>
class OwnedOrUnowned {
protected:
    union {
        Wrapped *mine;
        const Wrapped *yours;
    } ours;
    bool is_mine;

    inline void clear() DECAF_NOEXCEPT {
        if (is_mine) {
            really_bzero(ours.mine, T::size());
            free(ours.mine);
            ours.yours = T::default_value();
            is_mine = false;
        }
    }
    inline void alloc() /*throw(std::bad_alloc)*/ {
        if (is_mine) return;
        int ret = posix_memalign((void**)&ours.mine, T::alignment(), T::size());
        if (ret || !ours.mine) {
            is_mine = false;
            throw std::bad_alloc();
        }
        is_mine = true;
    }
    inline const Wrapped *get() const DECAF_NOEXCEPT { return is_mine ? ours.mine : ours.yours; }

    inline OwnedOrUnowned(
        const Wrapped &yours = *T::default_value()
    ) DECAF_NOEXCEPT {
        ours.yours = &yours;
        is_mine = false;
    }

   /**
    * @brief Assign.  This may require an allocation and memcpy.
    */ 
   inline T &operator=(const OwnedOrUnowned &it) /*throw(std::bad_alloc)*/ {
       if (this == &it) return *(T*)this;
       if (it.is_mine) {
           alloc();
           memcpy(ours.mine,it.ours.mine,T::size());
       } else {
           clear();
           ours.yours = it.ours.yours;
       }
       is_mine = it.is_mine;
       return *(T*)this;
   }

#if __cplusplus >= 201103L
    inline T &operator=(OwnedOrUnowned &&it) DECAF_NOEXCEPT {
        if (this == &it) return *(T*)this;
        clear();
        ours = it.ours;
        is_mine = it.is_mine;
        it.is_mine = false;
        it.ours.yours = T::default_value;
        return *this;
    }
#endif
};
/** @endcond */

/*******************************************/
/* Inline implementations below this point */
/*******************************************/

/** @cond internal */
template<typename T, size_t alignment>
T* SanitizingAllocator<T,alignment>::allocate (
    size_type cnt, 
    typename std::allocator<void>::const_pointer
) /*throw(std::bad_alloc)*/ { 
    void *v;
    int ret = 0;
 
    if (alignment) ret = posix_memalign(&v, alignment, cnt * sizeof(T));
    else v = malloc(cnt * sizeof(T));
 
    if (ret || v==NULL) throw(std::bad_alloc());
    return reinterpret_cast<T*>(v);
}

template<typename T, size_t alignment>
void SanitizingAllocator<T,alignment>::deallocate(T* p, size_t size) DECAF_NOEXCEPT {
    if (p==NULL) return;
    really_bzero(reinterpret_cast<void*>(p), size);
    free(reinterpret_cast<void*>(p));
}

/** @endcond */

} /* namespace decaf */


#undef DECAF_NOEXCEPT
#undef DECAF_DELETE

#endif /* __DECAF_SECURE_BUFFER_HXX__ */
