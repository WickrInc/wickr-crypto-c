%include "typemaps.i"

%typemap(in) const wickr_buffer_t * ( const wickr_buffer_t * )
%{
  wickr_buffer_t temp$argnum;

  if ($input == NULL) {
    $1 = NULL;
  }
  else {    
    temp$argnum.length = (size_t)((*jenv)->GetArrayLength(jenv,$input));
    temp$argnum.bytes = (uint8_t *)((*jenv)->GetByteArrayElements(jenv,$input,0));
    $1 = &temp$argnum;
  }
  
%}

%typemap(in) wickr_buffer_t * ( wickr_buffer_t * )
%{

  if ($input != NULL) {
    jbyte *bytes = (*jenv)->GetByteArrayElements(jenv,$input,0);
    size_t length = (*jenv)->GetArrayLength(jenv,$input);
    $1 = wickr_buffer_create((uint8_t *)bytes, length);
  }
  
%}

%typemap(out) wickr_buffer_t * 
%{  
  if ($1 != NULL) {
    const jbyte *returnDataC = (jbyte *)result->bytes;
    jsize returnDataL = (jsize)result->length;
    jbyteArray returnDataJ = (*jenv)->NewByteArray(jenv, returnDataL);
    (*jenv)->SetByteArrayRegion(jenv,returnDataJ,0,returnDataL,returnDataC);
    return returnDataJ;
  }
%}

/* These 3 typemaps tell SWIG what JNI and Java types to use */
%typemap(jni) wickr_buffer_t * "jbyteArray"
%typemap(jtype) wickr_buffer_t * "byte[]"
%typemap(jstype) wickr_buffer_t * "byte[]"

%typemap(jni) const wickr_buffer_t * "jbyteArray"
%typemap(jtype) const wickr_buffer_t * "byte[]"
%typemap(jstype) const wickr_buffer_t * "byte[]"

/* These 2 typemaps handle the conversion of the jtype to jstype typemap type
   and vice versa */
%typemap(javain) wickr_buffer_t * "$javainput"
%typemap(javaout) wickr_buffer_t * {
    return $jnicall;
  }