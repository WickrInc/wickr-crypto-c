%module rootkeys

%include engine.i

%{
#include <wickrcrypto/root_keys.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *node_signature_root, SWIGTYPE *node_storage_root, SWIGTYPE *remote_storage_root {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *node_signature_root, SWIGTYPE *node_storage_root, SWIGTYPE *remote_storage_root {
  if (jsresult->IsObject() && jsresult->ToObject()->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%ignore wickr_root_keys_create;
%ignore wickr_root_keys_generate;
%ignore wickr_root_keys_create_from_buffer;
%ignore wickr_root_keys_serialize;
%ignore wickr_root_keys_export;
%ignore wickr_root_keys_localize;
%ignore wickr_root_keys_copy;
%ignore wickr_root_keys_destroy;

%immutable;

%include "wickrcrypto/root_keys.h"

%extend struct wickr_root_keys {

 ~wickr_root_keys() {
   wickr_root_keys_destroy(&$self);
 }

 %newobject gen;
 %newobject from_buffer;
 %newobject serialize;
 %newobject from_keys;
 %newobject encrypt;
 %newobject to_storage_keys;
 
 static wickr_root_keys_t *gen() {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_root_keys_generate(&engine);
 }

 static wickr_root_keys_t *from_buffer(const wickr_buffer_t *buffer) {
  	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
  	return wickr_root_keys_create_from_buffer(&engine, buffer);
 }

 static wickr_root_keys_t *from_keys(wickr_ec_key_t *node_signature_root, wickr_cipher_key_t *node_storage_root, wickr_cipher_key_t *remote_storage_root) {
 	wickr_ec_key_t *copy_signature = wickr_ec_key_copy(node_signature_root);
 	wickr_cipher_key_t *copy_node_storage = wickr_cipher_key_copy(node_storage_root);
 	wickr_cipher_key_t *copy_remote_storage = wickr_cipher_key_copy(remote_storage_root);
 	wickr_root_keys_t *keys = wickr_root_keys_create(copy_signature, copy_node_storage, copy_remote_storage);

 	if (!keys) {
 		wickr_ec_key_destroy(&copy_signature);
 		wickr_cipher_key_destroy(&copy_node_storage);
 		wickr_cipher_key_destroy(&copy_remote_storage);
 	}

 	return keys;
 }

 wickr_buffer_t *serialize();

 wickr_cipher_result_t *encrypt(const wickr_cipher_key_t *export_key) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_root_keys_export($self, &engine, export_key);
 }

 wickr_storage_keys_t *to_storage_keys(const wickr_dev_info_t *dev_info) {
 	wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 	return wickr_root_keys_localize($self, &engine, dev_info);
 }
 

};