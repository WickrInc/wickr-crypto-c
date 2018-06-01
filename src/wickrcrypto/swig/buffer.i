%include "typemaps.i"

%typemap(newfree) wickr_buffer_t * {
   wickr_buffer_destroy(&$1);
}

#if defined(SWIGPHP)

%include "buffer_php.i"

#elif defined(SWIGRUBY)

%include "buffer_ruby.i"

#elif defined(SWIGJAVASCRIPT)

%include "buffer_js.i"

#elif defined(SWIGJAVA)

%include "buffer_java.i"

#endif