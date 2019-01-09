%module fingerprint

%include engine.i

%{
#include <wickrcrypto/fingerprint.h>
%}

%ignore wickr_fingerprint_gen;
%ignore wickr_fingerprint_gen_bilateral;
%ignore wickr_fingerprint_create;
%ignore wickr_fingerprint_copy;
%ignore wickr_fingerprint_destroy;
%ignore wickr_fingerprint_get_b32;
%ignore wickr_fingerprint_get_hex;

%immutable;

%include "wickrcrypto/fingerprint.h"

%extend struct wickr_fingerprint {

    %typemap(javacode) struct wickr_fingerprint %{

    public String getBase32String(FingerprintOutputType outputType) throws UnsupportedEncodingException {
        return new String(this.getB32(outputType), "UTF-8");
    }

    public String getHexString(FingerprintOutputType outputType) throws UnsupportedEncodingException {
        return new String(this.getHex(outputType), "UTF-8");
    }

    %}

    %typemap(javaimports) struct wickr_fingerprint %{
    import java.io.*;
    %}

    ~wickr_fingerprint() {
        wickr_fingerprint_destroy(&$self);
    }

    %newobject get_b32;
    %newobject get_hex;

    wickr_buffer_t *get_b32(wickr_fingerprint_output output_mode);
    wickr_buffer_t *get_hex(wickr_fingerprint_output output_mode);

};