%module identity

%include engine.i
%include fingerprint.i
%include <stdint.i>

%{
#include <wickrcrypto/identity.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *sig_key, SWIGTYPE *signature, SWIGTYPE *root, SWIGTYPE *node {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *sig_key, SWIGTYPE *signature, SWIGTYPE *root, SWIGTYPE *node {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%immutable;

%ignore wickr_identity_create;
%ignore wickr_identity_sign;
%ignore wickr_node_identity_gen;
%ignore wickr_identity_copy;
%ignore wickr_identity_destroy;
%ignore wickr_identity_create_from_buffer;
%ignore wickr_identity_serialize;
%ignore wickr_identity_chain_create;
%ignore wickr_identity_chain_copy;
%ignore wickr_identity_chain_validate;
%ignore wickr_identity_chain_destroy;
%ignore wickr_identity_chain_serialize;
%ignore wickr_identity_chain_serialize_private;
%ignore wickr_identity_chain_create_from_buffer;
%ignore wickr_identity_get_fingerprint;
%ignore wickr_identity_get_bilateral_fingerprint;

%include "wickrcrypto/identity.h"

%extend struct wickr_identity {

 ~wickr_identity() {
   wickr_identity_destroy(&$self);
 }

 %newobject from_values;
 %newobject sign_data;
 %newobject gen_node;
 %newobject from_buffer;
 %newobject get_fingerprint;
 %newobject get_bilateral_fingerprint;
 %newobject serialize;

 static wickr_identity_t *from_buffer(const wickr_buffer_t *data) {
     const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
     return wickr_identity_create_from_buffer(data, &engine);
 }

 wickr_buffer_t *serialize();

 wickr_ecdsa_result_t *sign_data(const wickr_buffer_t *data) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_identity_sign($self, &engine, data);
 }

 wickr_identity_t *gen_node(const wickr_buffer_t *identifier) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_node_identity_gen(&engine, $self, identifier);
 }

 static wickr_identity_t *from_values(wickr_identity_type type, wickr_buffer_t *identifier, wickr_ec_key_t *sig_key, wickr_ecdsa_result_t *signature) {
 	wickr_ec_key_t *key_copy = wickr_ec_key_copy(sig_key);
 	wickr_ecdsa_result_t *sig_copy = wickr_ecdsa_result_copy(signature);
   	wickr_identity_t *identity = wickr_identity_create(type, identifier, key_copy, sig_copy);
   	if (!identity) {
   		wickr_ec_key_destroy(&key_copy);
   		wickr_ecdsa_result_destroy(&sig_copy);
   	}
   	return identity;
 }

 wickr_fingerprint_t *fingerprint() {
   wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
   return wickr_identity_get_fingerprint($self, engine);
 }

 wickr_fingerprint_t *bilateral_fingerprint(const wickr_identity_t *remote_identity) {
   wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
   return wickr_identity_get_bilateral_fingerprint($self, remote_identity, engine);
 }
 

};

%extend struct wickr_identity_chain {

 ~wickr_identity_chain() {
   wickr_identity_chain_destroy(&$self);
 }

 %newobject from_identities;
 %newobject from_buffer;
 %newobject serialize;
 %newobject serialize_private;

 static wickr_identity_chain_t *from_buffer(const wickr_buffer_t *data) {
     const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
     return wickr_identity_chain_create_from_buffer(data, &engine);
 }

 wickr_buffer_t *serialize();
 wickr_buffer_t *serialize_private();

 static wickr_identity_chain_t *from_identities(wickr_identity_t *root, wickr_identity_t *node) {
 	wickr_identity_t *root_copy = wickr_identity_copy(root);
 	wickr_identity_t *node_copy = wickr_identity_copy(node);

 	wickr_identity_chain_t *id_chain = wickr_identity_chain_create(root_copy, node_copy);

 	if (!id_chain) {
 		wickr_identity_destroy(&root_copy);
 		wickr_identity_destroy(&node_copy);
 	}

 	return id_chain;
 }

 bool is_valid() {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_identity_chain_validate($self, &engine);
 }
 

};