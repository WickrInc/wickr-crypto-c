%module eckey

%{
#include <wickrcrypto/eckey.h>
%}

%ignore wickr_ec_key_create;
%ignore wickr_ec_key_copy;
%ignore wickr_ec_key_destroy;
%ignore wickr_ec_curve_find;

%nodefaultctor wickr_ec_curve;
%nodefaultdtor wickr_ec_curve;

%immutable;

%include "wickrcrypto/eckey.h"

%extend struct wickr_ec_curve {
  static const wickr_ec_curve_t *p521() {
      return &EC_CURVE_NIST_P521;
  }
}

%extend struct wickr_ec_key{

 ~wickr_ec_key() {
   wickr_ec_key_destroy(&$self);
 }

};



