/*
 * Example Decaf cyrpto routines, C++ wrapper.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#include <decaf/eddsa.hxx>
#include <decaf/point_$(gf_bits).hxx>
#include <decaf/ed$(gf_bits).h>

#include <decaf/shake.hxx>
#include <decaf/sha512.hxx>

/** @cond internal */
#if __cplusplus >= 201103L
#define DECAF_NOEXCEPT noexcept
#else
#define DECAF_NOEXCEPT throw()
#endif
/** @endcond */

/** Namespace for all libdecaf C++ objects. */
namespace decaf {

/** A public key for crypto over some Group */
template <typename Group> struct EdDSA;

/** A public key for crypto over $(name) */
template<> struct EdDSA<$(cxx_ns)> {

/** @cond internal */
template<class CRTP, Prehashed> class Signing;
template<class CRTP, Prehashed> class Verification;
class PublicKeyBase;
class PrivateKeyBase;
typedef class PrivateKeyBase PrivateKey, PrivateKeyPure, PrivateKeyPh;
typedef class PublicKeyBase PublicKey, PublicKeyPure, PublicKeyPh;
/** @endcond */

/**
 * Signatures support a "context" block, which allows you to domain separate them if
 * (for some reason) it's annoying to domain separate the message itself.  The default
 * is no context.  For Ed25519, the spec defining contexts is an extension, and the
 * default is not to use that extension.  This makes "no context" different from
 * the empty string.  For Ed448, contexts are built-in and mandatory, so "no context"
 * is the same as the empty string.
 */
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTLESS_SIGS
static inline const Block NO_CONTEXT() { return Block(DECAF_ED$(gf_shortname)_NO_CONTEXT,0); }
#else
static inline const Block NO_CONTEXT() { return Block(NULL,0); }
#endif

/** Prehash context for EdDSA. */
class Prehash : public $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) {
private:
    /** @cond internal */
    typedef $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) Super;
    SecureBuffer context_;
    template<class T, Prehashed Ph> friend class Signing;
    template<class T, Prehashed Ph> friend class Verification;
    
    void init() /*throw(LengthException)*/ {
        Super::reset();
        
        if (context_.size() > 255) {
            throw LengthException();
        }

        decaf_ed$(gf_shortname)_prehash_init((decaf_$(eddsa_hash)_ctx_s *)wrapped);
    }
    /** @endcond */
    
public:
    /** Number of output bytes in prehash */
    static const size_t OUTPUT_BYTES = Super::DEFAULT_OUTPUT_BYTES;
    
    /** Create the prehash */
    Prehash(const Block &context = NO_CONTEXT()) /*throw(LengthException)*/ {
        context_ = context;
        init();
    }

    /** Reset this hash */
    void reset() DECAF_NOEXCEPT { init(); }
    
    /** Output from this hash */
    SecureBuffer final() /*throw(std::bad_alloc)*/ {
        SecureBuffer ret = Super::final(OUTPUT_BYTES);
        reset();
        return ret;
    }
    
    /** Output from this hash */
    void final(Buffer &b) /*throw(LengthException)*/ {
        if (b.size() != OUTPUT_BYTES) throw LengthException();
        Super::final(b);
        reset();
    }
};

/** Signing (i.e. private) key class template */
template<class CRTP, Prehashed ph> class Signing;

/** Signing (i.e. private) key class, PureEdDSA version */
template<class CRTP> class Signing<CRTP,PURE>  {
public:
    /**
     * Sign a message.
     * @param [in] message The message to be signed.
     * @param [in] context A context for the signature; must be at most 255 bytes.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline SecureBuffer sign (
        const Block &message,
        const Block &context = NO_CONTEXT()
    ) const /* throw(LengthException, std::bad_alloc) */ {
        if (context.size() > 255) {
            throw LengthException();
        }
        
        SecureBuffer out(CRTP::SIG_BYTES);
        decaf_ed$(gf_shortname)_sign (
            out.data(),
            ((const CRTP*)this)->priv_.data(),
            ((const CRTP*)this)->pub_.data(),
            message.data(),
            message.size(),
            0,
            context.data(),
            context.size()
        );
        return out;
    }
};

/** Signing (i.e. private) key class, prehashed version */
template<class CRTP> class Signing<CRTP,PREHASHED> {
public:
    /** Sign a prehash context, and reset the context */
    inline SecureBuffer sign_prehashed ( const Prehash &ph ) const /*throw(std::bad_alloc)*/ {
        SecureBuffer out(CRTP::SIG_BYTES);
        decaf_ed$(gf_shortname)_sign_prehash (
            out.data(),
            ((const CRTP*)this)->priv_.data(),
            ((const CRTP*)this)->pub_.data(),
            (const decaf_ed$(gf_shortname)_prehash_ctx_s*)ph.wrapped,
            ph.context_.data(),
            ph.context_.size()
        );
        return out;
    }
    
    /** Sign a message using the prehasher */
    inline SecureBuffer sign_with_prehash (
        const Block &message,
        const Block &context = NO_CONTEXT()
    ) const /*throw(LengthException,CryptoException)*/ {
        Prehash ph(context);
        ph += message;
        return sign_prehashed(ph);
    }
};

/** Signing (i.e. private) key base class */
class PrivateKeyBase
    : public Serializable<PrivateKeyBase>
    , public Signing<PrivateKeyBase,PURE>
    , public Signing<PrivateKeyBase,PREHASHED> {
public:
    /** Type of public key corresponding to this private key */
    typedef class PublicKeyBase PublicKey;
private:
/** @cond internal */
    friend class PublicKeyBase;
    friend class Signing<PrivateKey,PURE>;
    friend class Signing<PrivateKey,PREHASHED>;
/** @endcond */
    
    /** The pre-expansion form of the signing key. */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES> priv_;
    
    /** The post-expansion public key. */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES> pub_;
    
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES;
    
    
    /** Create but don't initialize */
    inline explicit PrivateKeyBase(const NOINIT&) DECAF_NOEXCEPT : priv_((NOINIT())), pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PrivateKeyBase(const FixedBlock<SER_BYTES> &b) DECAF_NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PrivateKeyBase(const PrivateKey &k) DECAF_NOEXCEPT { *this = k; }
    
    /** Create at random */
    inline explicit PrivateKeyBase(Rng &r) DECAF_NOEXCEPT : priv_(r) {
        decaf_ed$(gf_shortname)_derive_public_key(pub_.data(), priv_.data());
    }
    
    /** Assignment from string */
    inline PrivateKeyBase &operator=(const FixedBlock<SER_BYTES> &b) DECAF_NOEXCEPT {
        memcpy(priv_.data(),b.data(),b.size());
        decaf_ed$(gf_shortname)_derive_public_key(pub_.data(), priv_.data());
        return *this;
    }
    
    /** Copy assignment */
    inline PrivateKeyBase &operator=(const PrivateKey &k) DECAF_NOEXCEPT {
        memcpy(priv_.data(),k.priv_.data(), priv_.size());
        memcpy(pub_.data(),k.pub_.data(), pub_.size());
        return *this;
    }
    
    /** Serialization size. */
    inline size_t ser_size() const DECAF_NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const DECAF_NOEXCEPT {
        memcpy(x,priv_.data(), priv_.size());
    }
    
    /** Convert to X format (to be used for key exchange) */
    inline SecureBuffer convert_to_x() const {
        SecureBuffer out(DECAF_X$(gf_shortname)_PRIVATE_BYTES);
        decaf_ed$(gf_shortname)_convert_private_key_to_x$(gf_shortname)(out.data(), priv_.data());
        return out;
    }
    
    /** Return the corresponding public key */
    inline PublicKey pub() const DECAF_NOEXCEPT {
        PublicKey pub(*this);
        return pub;
    }
}; /* class PrivateKey */

/** Verification (i.e. public) EdDSA key, PureEdDSA version. */
template<class CRTP> class Verification<CRTP,PURE> {
public:
    /** Verify a signature, returning DECAF_FAILURE if verification fails */
    inline decaf_error_t DECAF_WARN_UNUSED verify_noexcept (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = NO_CONTEXT()
    ) const /*DECAF_NOEXCEPT*/ {
        if (context.size() > 255) {
            return DECAF_FAILURE;
        }
        
        return decaf_ed$(gf_shortname)_verify (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            message.data(),
            message.size(),
            0,
            context.data(),
            context.size()
        );
    }
    
    /** Verify a signature, throwing an exception if verification fails
     * @param [in] sig The signature.
     * @param [in] message The signed message.
     * @param [in] context A context for the signature; must be at most 255 bytes.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline void verify (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = NO_CONTEXT()
    ) const /*throw(LengthException,CryptoException)*/ {
        if (context.size() > 255) {
            throw LengthException();
        }
        
        if (DECAF_SUCCESS != verify_noexcept( sig, message, context )) {
            throw CryptoException();
        }
    }
};

/** Verification (i.e. public) EdDSA key, prehashed version. */
template<class CRTP> class Verification<CRTP,PREHASHED> {
public:
    /** Verify that a signature is valid for a given prehashed message, given the context. */
    inline decaf_error_t DECAF_WARN_UNUSED verify_prehashed_noexcept (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Prehash &ph
    ) const /*DECAF_NOEXCEPT*/ {
        return decaf_ed$(gf_shortname)_verify_prehash (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            (const decaf_ed$(gf_shortname)_prehash_ctx_s*)ph.wrapped,
            ph.context_.data(),
            ph.context_.size()
        );
    }

    /** Verify that a signature is valid for a given prehashed message, given the context. */
    inline void verify_prehashed (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Prehash &ph
    ) const /*throw(CryptoException)*/ {
        if (DECAF_SUCCESS != decaf_ed$(gf_shortname)_verify_prehash (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            (const decaf_ed$(gf_shortname)_prehash_ctx_s*)ph.wrapped,
            ph.context_.data(),
            ph.context_.size()
        )) {
            throw CryptoException();
        }
    }
    
    /** Hash and verify a message, using the prehashed verification mode. */
    inline void verify_with_prehash (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = NO_CONTEXT()
    ) const /*throw(LengthException,CryptoException)*/ {
        Prehash ph(context);
        ph += message;
        verify_prehashed(sig,ph);
    }
};

/** EdDSA Public key base class. */
class PublicKeyBase
    : public Serializable<PublicKeyBase>
    , public Verification<PublicKeyBase,PURE>
    , public Verification<PublicKeyBase,PREHASHED> {
public:
    /** Private key corresponding to this type of public key */
    typedef class PrivateKeyBase PrivateKey;
    
private:
/** @cond internal */
    friend class PrivateKeyBase;
    friend class Verification<PublicKey,PURE>;
    friend class Verification<PublicKey,PREHASHED>;

private:
    /** The pre-expansion form of the signature */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES> pub_;
/** @endcond */
    
public:
    /* PERF FUTURE: Pre-cached decoding? Precomputed table?? */
  
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES;
    
    /** Create but don't initialize */
    inline explicit PublicKeyBase(const NOINIT&) DECAF_NOEXCEPT : pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PublicKeyBase(const FixedBlock<SER_BYTES> &b) DECAF_NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PublicKeyBase(const PublicKeyBase &k) DECAF_NOEXCEPT { *this = k; }
    
    /** Copy constructor */
    inline explicit PublicKeyBase(const PrivateKey &k) DECAF_NOEXCEPT { *this = k; }

    /** Assignment from string */
    inline PublicKey &operator=(const FixedBlock<SER_BYTES> &b) DECAF_NOEXCEPT {
        memcpy(pub_.data(),b.data(),b.size());
        return *this;
    }

    /** Assignment from private key */
    inline PublicKey &operator=(const PublicKey &p) DECAF_NOEXCEPT {
        return *this = p.pub_;
    }

    /** Assignment from private key */
    inline PublicKey &operator=(const PrivateKey &p) DECAF_NOEXCEPT {
        return *this = p.pub_;
    }

    /** Serialization size. */
    inline size_t ser_size() const DECAF_NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const DECAF_NOEXCEPT {
        memcpy(x,pub_.data(), pub_.size());
    }
    
    /** Convert to X format (to be used for key exchange) */
    inline SecureBuffer convert_to_x() const {
        SecureBuffer out(DECAF_X$(gf_shortname)_PRIVATE_BYTES);
        decaf_ed$(gf_shortname)_convert_public_key_to_x$(gf_shortname)(out.data(), pub_.data());
        return out;
    }
}; /* class PublicKey */

}; /* template<> struct EdDSA<$(cxx_ns)> */

#undef DECAF_NOEXCEPT
} /* namespace decaf */
