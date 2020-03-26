%module wickr_payload

%include packet_meta.i
%include engine.i

%{
#include <wickrcrypto/payload.h> 
%}

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

%immutable;

%ignore wickr_payload_create;
%ignore wickr_payload_copy;
%ignore wickr_payload_destroy;
%ignore wickr_payload_serialize;
%ignore wickr_payload_create_from_buffer;
%ignore wickr_payload_encrypt;
%ignore wickr_payload_create_from_cipher;

%include "wickrcrypto/payload.h"

%extend struct wickr_payload {

    %newobject from_values;
    %newobject serialize;
    %newobject create_from_buffer;
    %newobject cipher;
    %newobject from_ciphertext;

    static wickr_payload_t *from_values(wickr_packet_meta_t *meta, wickr_buffer_t *body) {
        wickr_packet_meta_t *meta_copy = wickr_packet_meta_copy(meta);

        wickr_payload_t *payload = wickr_payload_create(meta_copy, body);

        if (!payload) {
            wickr_packet_meta_destroy(&meta_copy);
        }

        return payload;
    }

    wickr_buffer_t *serialize();
    static wickr_payload_t *create_from_buffer(const wickr_buffer_t *buffer);

    wickr_cipher_result_t *cipher(const wickr_cipher_key_t *key) {
        const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        return wickr_payload_encrypt($self, &engine, key);
    }

    static wickr_payload_t *from_ciphertext(const wickr_cipher_result_t *ciphertext, const wickr_cipher_key_t *key) {
        const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        return wickr_payload_create_from_cipher(&engine, ciphertext, key);
    }

    ~wickr_payload() {
        wickr_payload_destroy(&$self);
    }
}