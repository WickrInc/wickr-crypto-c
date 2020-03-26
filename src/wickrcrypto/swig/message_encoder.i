%module message_encoder

%include engine.i

%{
#include <wickrcrypto/encoder_result.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *packet_key, SWIGTYPE *packet {
    long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *packet_key, SWIGTYPE *packet {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%ignore wickr_encoder_result_create;
%ignore wickr_encoder_result_copy;
%ignore wickr_encoder_result_destroy;

%immutable;

%include "wickrcrypto/encoder_result.h"

%extend struct wickr_encoder_result {

 ~wickr_encoder_result() {
   wickr_encoder_result_destroy(&$self);
 }

 %newobject from_values;

 static wickr_encoder_result_t *from_values(wickr_cipher_key_t *packet_key, wickr_packet_t *packet) {
    wickr_cipher_key_t *packet_key_copy = wickr_cipher_key_copy(packet_key);
    wickr_packet_t *packet_copy = wickr_packet_copy(packet);
    wickr_encoder_result_t *result = wickr_encoder_result_create(packet_key_copy, packet_copy);
    if (!result) {
        wickr_cipher_key_destroy(&packet_key_copy);
        wickr_packet_destroy(&packet_copy);
    }
    return result;
 }

};