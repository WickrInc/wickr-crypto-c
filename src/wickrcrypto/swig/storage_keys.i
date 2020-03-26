%module storagekeys

%include engine.i

%{
#include <wickrcrypto/storage.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *local, SWIGTYPE *remote {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *local, SWIGTYPE *remote {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%immutable;

%ignore wickr_storage_keys_create;
%ignore wickr_storage_keys_copy;
%ignore wickr_storage_keys_create_from_buffer;
%ignore wickr_storage_keys_serialize;
%ignore wickr_storage_keys_destroy;

%include "wickrcrypto/storage.h"

%extend struct wickr_storage_keys {

 ~wickr_storage_keys() {
   wickr_storage_keys_destroy(&$self);
 }

 %newobject create_from_buffer;
 %newobject create_from_keys;
 %newobject serialize;

 static wickr_storage_keys_t *create_from_keys(wickr_cipher_key_t *local, wickr_cipher_key_t *remote) {
   wickr_cipher_key_t *local_copy = wickr_cipher_key_copy(local);
   wickr_cipher_key_t *remote_copy = wickr_cipher_key_copy(remote);
   wickr_storage_keys_t *keys = wickr_storage_keys_create(local_copy, remote_copy);
   if (!keys) {
   		wickr_cipher_key_destroy(&local);
   		wickr_cipher_key_destroy(&remote);
   }
   return keys;
 }

 static wickr_storage_keys_t *create_from_buffer(const wickr_buffer_t *buffer);
 wickr_buffer_t *serialize();
 

};