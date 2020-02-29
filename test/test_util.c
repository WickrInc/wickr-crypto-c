/*
 * Copyright © 2012-2020 Wickr Inc. All rights reserved.
 *
 * //Wickr License Header Start
 *
 * This file contains Original Code and/or Modifications of Original Code as defined in and that are subject to the Wickr License (hereinafter “License”). 
 * This file may not be used except in accordance with the License.  A copy of the License can be obtained at <URL>.
 *
 * The Original Code and all software distributed under the License are distributed on an “AS IS” basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED.  WICKR INC. HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.  Please review the License for specific language governing the rights and limitations of the software
 * distributed under the License.
 *
 * //Wickr License Header End
 */

#include "cspec.h"
#include "util.h"

#include <limits.h>
#include <string.h>

#define TEST1_DATA      "0a0b0c"
#define TEST1_BASE64    "MGEwYjBj"

#define TEST2_DATA      "alsijlasdncoaie9323ljrkjslijeflajsflk"
#define TEST2_BASE64    "YWxzaWpsYXNkbmNvYWllOTMyM2xqcmtqc2xpamVmbGFqc2Zsaw=="

DESCRIBE(getBase64FromData, "util.c: getBase64FromData")
{
    IT( "returns NULL when input is NULL" )
    {
		wickr_buffer_t *ret = getBase64FromData(NULL);
        SHOULD_BE_NULL( ret )
    }
    END_IT
    
    IT( "convert '0a0b0c' to 'MGEwYjBj'")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const uint8_t *)(TEST1_DATA), strlen(TEST1_DATA));
        wickr_buffer_t *ret = getBase64FromData(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), TEST1_BASE64)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
    
    IT( "convert 'alsijlasdncoaie9323ljrkjslijeflajsflk' to 'YWxzaWpsYXNkbmNvYWllOTMyM2xqcmtqc2xpamVmbGFqc2Zsaw=='")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const uint8_t *)(TEST2_DATA), strlen(TEST2_DATA));
        wickr_buffer_t *ret = getBase64FromData(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), TEST2_BASE64)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
}
END_DESCRIBE

DESCRIBE(getDataFromBase64, "util.c: getDataFromBase64")
{
    IT( "returns NULL when input is NULL" )
    {
        wickr_buffer_t *ret = getDataFromBase64(NULL);
        SHOULD_BE_NULL( ret )
    }
    END_IT

    IT( "convert 'MGEwYjBj' to '0a0b0c'")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const uint8_t *)(TEST1_BASE64), strlen(TEST1_BASE64)+1);
        wickr_buffer_t *ret = getDataFromBase64(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), TEST1_DATA)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT

    IT( "convert 'YWxzaWpsYXNkbmNvYWllOTMyM2xqcmtqc2xpamVmbGFqc2Zsaw==' to 'alsijlasdncoaie9323ljrkjslijeflajsflk'")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const uint8_t *)(TEST2_BASE64), strlen(TEST2_BASE64)+1);
        wickr_buffer_t *ret = getDataFromBase64(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), TEST2_DATA)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
}
END_DESCRIBE


#define HEX_STRING_1    "0a0b0c0d"
#define HEX_STRING_2    "0123456789abcdef"

DESCRIBE(getHexStringFromData, "util.c: getHexStringFromData")
{
    uint8_t test_data_1[4] = { 0xa, 0xb, 0xc, 0xd };
    uint8_t test_data_2[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    
    IT( "returns NULL when input is NULL" )
    {
        wickr_buffer_t *ret = getHexStringFromData(NULL);
        SHOULD_BE_NULL( ret )
    }
    END_IT
    
    IT( "convert 0x0a0b0c0d to '0A0B0C0D'")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create(test_data_1, sizeof(test_data_1));
        wickr_buffer_t *ret = getHexStringFromData(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), HEX_STRING_1)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
    
    IT( "convert 0x0123456789abcdef to '0123456789ABCDEF'")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create(test_data_2, sizeof(test_data_2));
        wickr_buffer_t *ret = getHexStringFromData(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            SHOULD_MATCH((const char *)(ret->bytes), HEX_STRING_2)
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
}
END_DESCRIBE


DESCRIBE(getDataFromHexString, "util.c: getDataFromHexString")
{
    uint8_t test_data_1[4] = { 0xa, 0xb, 0xc, 0xd };
    uint8_t test_data_2[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    
    IT( "returns NULL when input is NULL" )
    {
        wickr_buffer_t *ret = getDataFromHexString(NULL);
        SHOULD_BE_NULL( ret )
    }
    END_IT
    
    IT( "convert '0A0B0C0D' to 0x0a0b0c0d")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const unsigned char *)HEX_STRING_1, strlen(HEX_STRING_1)+1);
        wickr_buffer_t *ret = getDataFromHexString(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            bool lenTest = ret->length == ((strlen(HEX_STRING_1) / 2));
            SHOULD_BE_TRUE(lenTest)
            if (lenTest) {
                int cmpTest = memcmp(ret->bytes, test_data_1, ret->length-1);
                SHOULD_BE_TRUE(cmpTest == 0)
            }
            wickr_buffer_destroy(&ret);
            wickr_buffer_destroy(&inbuf);
        }
    }
    END_IT
    
    IT( "convert '0123456789ABCDEF' to 0x0123456789abcdef")
    {
        wickr_buffer_t *inbuf = wickr_buffer_create((const unsigned char *)HEX_STRING_2, strlen(HEX_STRING_2)+1);
        wickr_buffer_t *ret = getDataFromHexString(inbuf);
        wickr_buffer_destroy(&inbuf);
        
        SHOULD_NOT_BE_NULL(ret);
        if (ret) {
            bool lenTest = ret->length == ((strlen(HEX_STRING_2) / 2));
            SHOULD_BE_TRUE(lenTest)
            if (lenTest) {
                int cmpTest = memcmp(ret->bytes, test_data_2, ret->length-1);
                SHOULD_BE_TRUE(cmpTest == 0)
            }
            wickr_buffer_destroy(&inbuf);
            wickr_buffer_destroy(&ret);
        }
    }
    END_IT
}
END_DESCRIBE

