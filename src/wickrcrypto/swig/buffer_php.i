
%include "typemaps.i"

%typemap(in) const wickr_buffer_t * ( const wickr_buffer_t * )
%{
  wickr_buffer_t temp$argnum;

  if (Z_TYPE($input) == IS_NULL) {
    $1 = NULL;
  }
  else {
    convert_to_string_ex(&$input);
    
    temp$argnum.length = (size_t)Z_STRLEN($input);
    temp$argnum.bytes = (uint8_t *)Z_STRVAL($input);
    $1 = &temp$argnum;
  }
  
%}

%typemap(in) wickr_buffer_t * ( wickr_buffer_t * )
%{

  if (Z_TYPE($input) == IS_NULL) {
    $1 = NULL;
  }
  else {
    convert_to_string_ex(&$input);
    $1 = wickr_buffer_create((uint8_t *)Z_STRVAL($input), (size_t)Z_STRLEN($input));
  }
  
%}

%typemap(out) wickr_buffer_t * 
%{  
  if ($1 != NULL) {
    RETVAL_STRINGL((const char *)result->bytes, result->length);
  }
%}