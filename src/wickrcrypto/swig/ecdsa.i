%module ecdsa

%{
#include <wickrcrypto/ecdsa.h>
%}

%ignore wickr_ecdsa_result_create;
%ignore wickr_ecdsa_result_serialize;
%ignore wickr_ecdsa_result_create_from_buffer;
%ignore wickr_ecdsa_result_copy;
%ignore wickr_ecdsa_result_copy_raw_signature;
%ignore wickr_ecdsa_result_destroy;

%immutable;

%include "wickrcrypto/ecdsa.h"

%extend struct wickr_ecdsa_result{

 ~wickr_ecdsa_result() {
   wickr_ecdsa_result_destroy(&$self);
 }

 %newobject create;
 %newobject create_from_buffer;
 %newobject serialize;
 
 wickr_buffer_t *serialize();

 static wickr_ecdsa_result_t *create_from_buffer(const wickr_buffer_t *buffer);
 static wickr_ecdsa_result_t *create(wickr_ec_curve_t curve, wickr_digest_t digest_mode, wickr_buffer_t *sig_data);
};
