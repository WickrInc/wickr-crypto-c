%module ecdh_cipher

%include engine.i

%{
#include <wickrcrypto/ecdh_cipher_ctx.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *local_key {
  long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *local_key {
  if (jsresult->IsObject() && jsresult->ToObject()->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%ignore wickr_ecdh_cipher_ctx_create;
%ignore wickr_ecdh_cipher_ctx_create_key;
%ignore wickr_ecdh_cipher_ctx_copy;
%ignore wickr_ecdh_cipher_ctx_destroy;
%ignore wickr_ecdh_cipher_ctx_cipher;
%ignore wickr_ecdh_cipher_ctx_decipher;

%immutable;

%include "wickrcrypto/ecdh_cipher_ctx.h"

%extend struct wickr_ecdh_cipher_ctx {

 ~wickr_ecdh_cipher_ctx() {
   wickr_ecdh_cipher_ctx_destroy(&$self);
 }

 %newobject gen;
 %newobject from_components;
 %newobject encrypt;
 %newobject decrypt;

 static wickr_ecdh_cipher_ctx_t *gen(wickr_ec_curve_t curve, wickr_cipher_t cipher) {
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    return wickr_ecdh_cipher_ctx_create(engine, curve, cipher);
 }

 static wickr_ecdh_cipher_ctx_t *from_components(wickr_ec_key_t *key, wickr_cipher_t cipher) {
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_ec_key_t *key_copy = wickr_ec_key_copy(key);
    wickr_ecdh_cipher_ctx_t *ctx = wickr_ecdh_cipher_ctx_create_key(engine, key_copy, cipher);
    if (!ctx) {
        wickr_ec_key_destroy(&key_copy);
    }
    return ctx;
 }

 wickr_cipher_result_t *encrypt(const wickr_buffer_t *plaintext, const wickr_ec_key_t *remote_pub, const wickr_kdf_meta_t *kdf_params) {
   return wickr_ecdh_cipher_ctx_cipher($self, plaintext, remote_pub, kdf_params);
 }

 wickr_buffer_t *decrypt(const wickr_cipher_result_t *ciphertext, const wickr_ec_key_t *remote_pub, const wickr_kdf_meta_t *kdf_params) {
   return wickr_ecdh_cipher_ctx_decipher($self, ciphertext, remote_pub, kdf_params);
 }

};