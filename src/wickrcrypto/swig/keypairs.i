%module ephemeralkeys

%include engine.i

%{
#include <wickrcrypto/ephemeral_keypair.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *ec_key, SWIGTYPE *signature {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *ec_key, SWIGTYPE *signature {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%immutable;

%ignore wickr_ephemeral_keypair_create;
%ignore wickr_ephemeral_keypair_copy;
%ignore wickr_ephemeral_keypair_generate_identity;
%ignore wickr_ephemeral_keypair_verify_owner;
%ignore wickr_ephemeral_keypair_make_public;
%ignore wickr_ephemeral_keypair_destroy;

%include "wickrcrypto/ephemeral_keypair.h"

%extend struct wickr_ephemeral_keypair {

 %newobject from_values;
 %newobject gen;

 ~wickr_ephemeral_keypair() {
   wickr_ephemeral_keypair_destroy(&$self);
 }

 static wickr_ephemeral_keypair_t *from_values(uint64_t identifier, wickr_ec_key_t *ec_key, wickr_ecdsa_result_t *signature) {
 	wickr_ec_key_t *key_copy = wickr_ec_key_copy(ec_key);
 	wickr_ecdsa_result_t *signature_copy = wickr_ecdsa_result_copy(signature);
 	wickr_ephemeral_keypair_t *keypair = wickr_ephemeral_keypair_create(identifier, key_copy, signature_copy);

 	if (!keypair) {
 		wickr_ec_key_destroy(&key_copy);
 		wickr_ecdsa_result_destroy(&signature_copy);
 	}

 	return keypair;
 }

 static wickr_ephemeral_keypair_t *gen(uint64_t identifier, const wickr_identity_t *identity) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_ephemeral_keypair_generate_identity(&engine, identifier, identity);
 }

 bool verify(const wickr_ephemeral_keypair_t *keypair, const wickr_identity_t *owner) {
 	 wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	 return wickr_ephemeral_keypair_verify_owner($self, &engine, owner);
 }

 void make_public();
 

};