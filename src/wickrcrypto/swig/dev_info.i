%module devinfo

%include engine.i

%{
#include <wickrcrypto/devinfo.h>	
%}

%immutable;

%ignore wickr_dev_info_create;
%ignore wickr_dev_info_create_new;
%ignore wickr_dev_info_derive;
%ignore wickr_dev_info_copy;
%ignore wickr_dev_info_destroy;

%include "wickrcrypto/devinfo.h"

%extend struct wickr_dev_info {

 ~wickr_dev_info() {
   wickr_dev_info_destroy(&$self);
 }

 %newobject gen;
 %newobject compute;

 static wickr_dev_info_t *gen(const wickr_buffer_t *system_id) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_dev_info_create_new(&engine, system_id);
 }

 static wickr_dev_info_t *compute(wickr_buffer_t *dev_salt, const wickr_buffer_t *system_id) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_dev_info_derive(&engine, dev_salt, system_id);
 }

};