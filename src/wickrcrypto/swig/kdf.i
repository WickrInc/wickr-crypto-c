%module kdf

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *meta {
  long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *meta {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%{
#include <wickrcrypto/kdf.h>
%}

%ignore wickr_kdf_meta_create;
%ignore wickr_kdf_meta_size_with_buffer;
%ignore wickr_kdf_meta_serialize;
%ignore wickr_kdf_meta_create_with_buffer;
%ignore wickr_kdf_meta_copy;
%ignore wickr_kdf_meta_destroy;
%ignore wickr_kdf_result_create;
%ignore wickr_kdf_result_copy;
%ignore wickr_kdf_result_destroy;
%ignore wickr_perform_kdf;
%ignore wickr_perform_kdf_meta;

%nodefaultctor wickr_kdf_algo;
%nodefaultdtor wickr_kdf_algo;

%immutable;

%include "wickrcrypto/kdf.h"

%extend struct wickr_kdf_algo {
  static const wickr_kdf_algo_t *scrypt_17() {
      return &KDF_SCRYPT_2_17;
  }
  static const wickr_kdf_algo_t *scrypt_18() {
      return &KDF_SCRYPT_2_18;
  }
  static const wickr_kdf_algo_t *scrypt_19() {
      return &KDF_SCRYPT_2_19;
  }
  static const wickr_kdf_algo_t *scrypt_20() {
      return &KDF_SCRYPT_2_20;
  }
  static const wickr_kdf_algo_t *bcrypt_15() {
      return &KDF_BCRYPT_15;
  }
  static const wickr_kdf_algo_t *hkdf_sha256() {
      return &KDF_HKDF_SHA256;
  }
  static const wickr_kdf_algo_t *hkdf_sha384() {
      return &KDF_HKDF_SHA384;
  }
  static const wickr_kdf_algo_t *hkdf_sha512() {
      return &KDF_HKDF_SHA512;
  }
}

%extend struct wickr_kdf_meta{

 %newobject from_components;
 %newobject create_with_buffer;
 %newobject serialize;
 
 static wickr_kdf_meta_t *from_components(wickr_kdf_algo_t algo, wickr_buffer_t *salt, wickr_buffer_t *info) {
   return wickr_kdf_meta_create(algo,salt, info);
 }

 ~wickr_kdf_meta() {
   wickr_kdf_meta_destroy(&$self);
 }

 wickr_buffer_t *serialize();

 static wickr_kdf_meta_t *create_with_buffer(const wickr_buffer_t *buffer);
 static uint8_t size_with_buffer(const wickr_buffer_t *buffer);

};
