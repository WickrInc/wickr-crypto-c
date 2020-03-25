%module key_exchange

%include engine.i

%{
#include <wickrcrypto/key_exchange.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *exchange_ciphertext {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *exchange_ciphertext {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%ignore wickr_key_exchange_create;
%ignore wickr_key_exchange_copy;
%ignore wickr_key_exchange_destroy;
%ignore wickr_exchange_array_new;
%ignore wickr_exchange_array_set_item;
%ignore wickr_exchange_array_fetch_item;
%ignore wickr_exchange_array_copy;
%ignore wickr_exchange_array_destroy;
%ignore wickr_key_exchange_set_create;
%ignore wickr_key_exchange_set_find;
%ignore wickr_key_exchange_set_copy;
%ignore wickr_key_exchange_set_destroy;
%ignore wickr_key_exchange_set_serialize;
%ignore wickr_key_exchange_set_create_from_buffer;
%ignore exchanges;

%immutable;

%include "wickrcrypto/key_exchange.h"

%extend struct wickr_key_exchange {

 ~wickr_key_exchange() {
   wickr_key_exchange_destroy(&$self);
 }

 %newobject from_values;

 static wickr_key_exchange_t *from_values(wickr_buffer_t *exchange_id, uint64_t key_id, wickr_cipher_result_t *exchange_ciphertext) {
 	wickr_cipher_result_t *ciphertext_copy = wickr_cipher_result_copy(exchange_ciphertext);
   	wickr_key_exchange_t *exchange = wickr_key_exchange_create(exchange_id, key_id, ciphertext_copy);
   	if (!exchange) {
   		wickr_cipher_result_destroy(&ciphertext_copy);
   	}
   	return exchange;
 }

};

%extend struct wickr_key_exchange_set {

 ~wickr_key_exchange_set() {
   wickr_key_exchange_set_destroy(&$self);
 }

 %newobject from_buffer;
 %newobject serialize;

 static wickr_key_exchange_set_t *from_buffer(const wickr_buffer_t *buffer) {
     const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
     return wickr_key_exchange_set_create_from_buffer(&engine, buffer);
 }

 wickr_buffer_t *serialize();
 

};