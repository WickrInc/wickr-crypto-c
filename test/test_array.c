//
//  test_array.c
//  Crypto
//
//  Created by Tom Leavy on 11/3/16.
//
//

#include "test_array.h"
#include "array.h"
#include <string.h>

struct foo {
    bool copy;
    char *bar;
};

typedef struct foo foo_t;

foo_t *create_foo(bool copy, char *bar)
{
    foo_t *foo = malloc(sizeof(foo_t));
    foo->copy = copy;
    foo->bar = bar;
    
    return foo;
}

foo_t *copy_foo(foo_t *foo)
{
    char *bar_copy = malloc(16);
    memcpy(bar_copy, foo->bar, 16);
    
    return create_foo(true, bar_copy);
}

void destroy_foo(foo_t **foo)
{
    free((*foo)->bar);
    free(*foo);
    *foo = NULL;
}

wickr_array_t *test_zero_len_array_initialization(wickr_array_copy_func copy_func, wickr_array_destroy_func destroy_func)
{
    wickr_array_t *test_array = wickr_array_new(0, 0, copy_func, destroy_func);
    if (!copy_func || !destroy_func) {
        SHOULD_BE_NULL(test_array);
        return NULL;
    }
    
    SHOULD_NOT_BE_NULL(test_array);
    return test_array;
}

DESCRIBE(a_zero_length_array,"a zero length wickr_array_t")
{
    wickr_array_t *test_array = NULL;
    
    IT("can't be initialized without a copy function")
    {
        test_zero_len_array_initialization(NULL, (wickr_array_destroy_func)destroy_foo);
    }
    END_IT
    
    IT("can't be initialized without a destroy function")
    {
        test_zero_len_array_initialization((wickr_array_copy_func)copy_foo, NULL);
    }
    END_IT
    
    IT("can be initialized with copy and destroy functions")
    {
        test_array = test_zero_len_array_initialization((wickr_array_copy_func)copy_foo, (wickr_array_destroy_func)destroy_foo);
    }
    END_IT
    
    IT ("will give you a proper item count")
    {
        int count = wickr_array_get_item_count(test_array);
        SHOULD_EQUAL(0, count);
    }
    END_IT
    
    IT("won't allow you to set or get an item")
    {
        foo_t *test_foo = create_foo(false, malloc(16));
        bool success = wickr_array_set_item(test_array, 0, test_foo, true);
        SHOULD_BE_FALSE(success);
        destroy_foo(&test_foo);
        
        foo_t *item = wickr_array_fetch_item(test_array, 0, true);
        SHOULD_BE_NULL(item);
    }
    END_IT
    
    IT("will allow you to make a copy of it")
    {
        wickr_array_t *copy_array = wickr_array_copy(test_array, true);
        SHOULD_NOT_BE_NULL(copy_array);
        SHOULD_EQUAL(wickr_array_get_item_count(copy_array), wickr_array_get_item_count(test_array));
        wickr_array_destroy(&copy_array, true);
    }
    END_IT
    
    wickr_array_destroy(&test_array, true);
    SHOULD_BE_NULL(test_array);
}
END_DESCRIBE

DESCRIBE(an_array_of_items, "an array of items")
{
    wickr_array_t *test_array = wickr_array_new(2, 0, (wickr_array_copy_func)copy_foo, (wickr_array_destroy_func)destroy_foo);
    SHOULD_NOT_BE_NULL(test_array);
    
    IT("can tell you the item count")
    {
        int count = wickr_array_get_item_count(test_array);
        SHOULD_EQUAL(count, 2);
    }
    END_IT
    
    IT("should return an error if you try and set null for an item")
    {
        bool allowed = wickr_array_set_item(test_array, 0, NULL, true);
        SHOULD_BE_FALSE(allowed);
    }
    END_IT

    IT("allows you to make a copy of an object that you insert")
    {
        foo_t *test_foo_1 = create_foo(false,  malloc(16));
        memset(test_foo_1->bar, 1, 16);
        
        bool allowed = wickr_array_set_item(test_array, 0, test_foo_1, true);
        SHOULD_BE_TRUE(allowed);
        
        foo_t *test_foo_copy = wickr_array_fetch_item(test_array, 0, false);
        
        SHOULD_NOT_EQUAL((uintptr_t)test_foo_1, (uintptr_t)test_foo_copy);
        SHOULD_EQUAL(memcmp(test_foo_1->bar, test_foo_copy->bar, 16), 0);
        SHOULD_BE_TRUE(test_foo_copy->copy);
        
        destroy_foo(&test_foo_1);

    }
    END_IT
    
    IT("allows you to make a copy of an object that you fetch")
    {
        foo_t *test_foo_2 = create_foo(false,  malloc(16));
        memset(test_foo_2->bar, 2, 16);
        
        bool allowed = wickr_array_set_item(test_array, 1, test_foo_2, false);
        SHOULD_BE_TRUE(allowed);
        
        foo_t *test_foo_copy = wickr_array_fetch_item(test_array, 1, true);
        SHOULD_NOT_EQUAL((uintptr_t)test_foo_2, (uintptr_t)test_foo_copy);
        SHOULD_EQUAL(memcmp(test_foo_2->bar, test_foo_copy->bar, 16), 0);
        SHOULD_NOT_BE_NULL(test_foo_copy);
        SHOULD_BE_TRUE(test_foo_copy->copy);
        
        destroy_foo(&test_foo_copy);
        
        foo_t *test_foo_2_not_copied = wickr_array_fetch_item(test_array, 1, false);
        SHOULD_EQUAL((uintptr_t)test_foo_2, (uintptr_t)test_foo_2_not_copied);
        SHOULD_BE_FALSE(test_foo_2_not_copied->copy);
    }
    END_IT
    
    IT("allows you to insert an item only within the bounds it has allocated")
    {
        foo_t *test_foo_3 = create_foo(false,  malloc(16));
        
        bool allowed = wickr_array_set_item(test_array, 2, test_foo_3, true);
        SHOULD_BE_FALSE(allowed);
        
        destroy_foo(&test_foo_3);
    }
    END_IT
    
    IT("allows you to make a shallow copy")
    {
        wickr_array_t *test_shallow_copy = wickr_array_copy(test_array, false);
        SHOULD_NOT_BE_NULL(test_shallow_copy);
        
        foo_t *test_foo_1_not_copied = wickr_array_fetch_item(test_array, 1, false);
        SHOULD_BE_FALSE(test_foo_1_not_copied->copy);
        wickr_array_destroy(&test_shallow_copy, false);
    }
    END_IT
    
    IT("allows you to make a deep copy")
    {
        wickr_array_t *test_deep_copy = wickr_array_copy(test_array, true);
        SHOULD_NOT_BE_NULL(test_deep_copy);
        
        foo_t *test_foo_2_copy = wickr_array_fetch_item(test_deep_copy, 1, false);
        SHOULD_BE_TRUE(test_foo_2_copy->copy);
        wickr_array_destroy(&test_deep_copy, true);
    }
    END_IT
    
    wickr_array_destroy(&test_array, true);
    
}
END_DESCRIBE
