%include "typemaps.i"

%typemap(in) const wickr_buffer_t * ( const wickr_buffer_t * )
%{
  wickr_buffer_t temp$argnum;

  if (TYPE($input) == T_NIL) {
    $1 = NULL;
  }
  else {    
    temp$argnum.length = (size_t)RSTRING_LEN($input);
    temp$argnum.bytes = (uint8_t *)StringValuePtr($input);
    $1 = &temp$argnum;
  }
  
%}

%typemap(in) wickr_buffer_t * ( wickr_buffer_t * )
%{

  if (TYPE($input) == T_NIL) {
    $1 = NULL;
  }
  else {
    $1 = wickr_buffer_create((uint8_t *)StringValuePtr($input), (size_t)RSTRING_LEN($input));
  }
  
%}

%typemap(out) wickr_buffer_t * 
%{  
  if ($1 != NULL) {
    vresult = rb_str_new((const char *)result->bytes, result->length);
  }
%}