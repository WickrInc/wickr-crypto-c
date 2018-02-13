/**
 * Example Decaf crypto routines, C++ metaheader.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 */

$("\n".join([
    "#include <decaf/crypto_%s.hxx>" % g for g in sorted([c["bits"] for _,c in curve.items()])
]))
