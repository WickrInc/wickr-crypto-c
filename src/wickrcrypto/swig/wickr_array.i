%module arrays;

%{
#include <wickrcrypto/array.h>
%}

%ignore wickr_array_new;
%ignore wickr_array_get_item_count;
%ignore wickr_array_set_item;
%ignore wickr_array_fetch_item;
%ignore wickr_array_copy;
%ignore wickr_array_destroy;

%nodefaultctor wickr_array;
%nodefaultdtor wickr_array;

%immutable;

struct wickr_array {};

%include "wickrcrypto/array.h"

%extend struct wickr_array {
    
    uint32_t get_item_count();

    ~wickr_array() {
        wickr_array_destroy(&$self, true);
    }

}
