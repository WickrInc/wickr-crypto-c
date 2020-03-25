%module wickr_packet_meta

%{
#include <wickrcrypto/packet_meta.h> 
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *ephemerality_settings {
  long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *ephemerality_settings {
  if (jsresult->IsObject() && jsresult->ToObject(v8::Isolate::GetCurrent())->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%immutable;

%ignore wickr_packet_meta_create;
%ignore wickr_packet_meta_copy;
%ignore wickr_packet_meta_destroy;

%include "wickrcrypto/packet_meta.h"

%extend struct wickr_ephemeral_info {
    
    %newobject from_values;

    static wickr_ephemeral_info_t *from_values(uint64_t ttl, uint64_t bor) {
        wickr_ephemeral_info_t *info = (wickr_ephemeral_info_t *)malloc(sizeof(wickr_ephemeral_info_t));
        if (!info) {
            return NULL;
        }
        info->ttl = ttl;
        info->bor = bor;
        return info;
    }
    ~wickr_ephemeral_info() {
        free($self);
    }
}

%extend struct wickr_packet_meta {
    %newobject from_values;
    static wickr_packet_meta_t *from_values(wickr_ephemeral_info_t ephemerality_settings, wickr_buffer_t *channel_tag, uint16_t content_type) {
        return wickr_packet_meta_create(ephemerality_settings, channel_tag, content_type);
    }
    ~wickr_packet_meta() {
        wickr_packet_meta_destroy(&$self);
    }
}