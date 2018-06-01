%module digest

%{
#include <wickrcrypto/digest.h>
%}

%ignore wickr_digest_find_with_id;
%nodefaultctor wickr_digest;
%nodefaultdtor wickr_digest;

%immutable;

%include "wickrcrypto/digest.h"

%extend struct wickr_digest {
  static const wickr_digest_t *sha256() {
      return &DIGEST_SHA_256;
  }
  static const wickr_digest_t *sha384() {
      return &DIGEST_SHA_384;
  }
  static const wickr_digest_t *sha512() {
      return &DIGEST_SHA_512;
  }
}
