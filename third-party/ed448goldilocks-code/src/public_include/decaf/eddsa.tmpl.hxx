/**
 * EdDSA crypto routines, metaheader.
 */

/** Namespace for all libdecaf C++ objects. */
namespace decaf {
    /** How signatures handle hashing. */
    enum Prehashed {
        PURE,     /**< Sign the message itself.  This can't be done in one pass. */
        PREHASHED /**< Sign the hash of the message. */
    };
}

$("\n".join([
    "#include <decaf/ed%s.hxx>" % g for g in sorted([c["bits"] for _,c in curve.items()])
]))
