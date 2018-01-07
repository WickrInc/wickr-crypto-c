/**
 * Master header for Decaf library.
 * 
 * The Decaf library implements cryptographic operations on a elliptic curve
 * groups of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Ed448-Goldilocks or Ed25519) and wiping out the cofactor.
 * 
 * The formulas are all complete and have no special cases.  However, some
 * functions can fail.  For example, decoding functions can fail because not
 * every string is the encoding of a valid group element.
 * 
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_XXX_base_double_scalarmul_non_secret.
 */

$("\n".join([
    "#include <decaf/point_%s.h>" % g for g in sorted([c["bits"] for _,c in curve.items()])
]))
