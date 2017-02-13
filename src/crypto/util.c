#include "buffer.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <string.h>


#ifndef INLINE
#ifdef _MSC_VER
#define INLINE __inline
#else
#define INLINE inline
#endif
#endif // INLINE

static const char _base64EncodingTable[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const short _base64DecodingTable[256] = {
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
	-2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
	-2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

wickr_buffer_t *
getBase64FromData(const wickr_buffer_t * objData)
{
    if (!objData) {
        return NULL;
    }
    
	const unsigned char * objRawData = (const unsigned char *)objData->bytes;
	char * objPointer;
    
	wickr_buffer_t * strResult;

	// Get the Raw Data length and ensure we actually have data
    size_t intLength = objData->length;
	if (intLength == 0) return NULL;

	// Setup the String-based Result placeholder and pointer within that placeholder
	strResult = wickr_buffer_create_empty(((intLength + 2) / 3) * 4 + 1);
    if (!strResult)
        return NULL;
	objPointer = (char *)strResult->bytes;

	// Iterate through everything
	while (intLength > 2) { // keep going until we have less than 24 bits
		*objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
		*objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
		*objPointer++ = _base64EncodingTable[((objRawData[1] & 0x0f) << 2) + (objRawData[2] >> 6)];
		*objPointer++ = _base64EncodingTable[objRawData[2] & 0x3f];

		// we just handled 3 octets (24 bits) of data
		objRawData += 3;
		intLength -= 3;
	}

	// now deal with the tail end of things
	if (intLength != 0) {
		*objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
		if (intLength > 1) {
			*objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
			*objPointer++ = _base64EncodingTable[(objRawData[1] & 0x0f) << 2];
			*objPointer++ = '=';
		} else {
			*objPointer++ = _base64EncodingTable[(objRawData[0] & 0x03) << 4];
			*objPointer++ = '=';
			*objPointer++ = '=';
		}
	}

	*objPointer++ = '\0';
    strResult->length = strlen((const char *)strResult->bytes);

    return strResult;
}

wickr_buffer_t *
getDataFromBase64(const wickr_buffer_t * strBase64)
{
    if (!strBase64) {
        return NULL;
    }
    
	const char * objPointer = (const char *)strBase64->bytes;
	if (objPointer == NULL)  return NULL;

	size_t intLength = strlen(objPointer);
    if (intLength > strBase64->length)
        intLength = strBase64->length;
    
	int intCurrent;
	int i = 0, j = 0, k;

    wickr_buffer_t *objResult;
	objResult = wickr_buffer_create_empty_zero(intLength);
    if (!objResult)
        return NULL;
    
	// Run through the whole string, converting as we go
	while ( ((intCurrent = *objPointer++) != '\0') && (intLength-- > 0) ) {
		if (intCurrent == '=') {
			if (*objPointer != '=' && ((i % 4) == 1)) {// || (intLength > 0)) {
				// the padding character is invalid at this point -- so this entire string is invalid
                wickr_buffer_destroy(&objResult);
				return NULL;
			}
			continue;
		}

		intCurrent = _base64DecodingTable[intCurrent];
		if (intCurrent == -1) {
			// we're at a whitespace -- simply skip over
			continue;
		} else if (intCurrent == -2) {
			// we're at an invalid character
            wickr_buffer_destroy(&objResult);
			return NULL;
		}

		switch (i % 4) {
			case 0:
				objResult->bytes[j] = intCurrent << 2;
				break;

			case 1:
				objResult->bytes[j++] |= intCurrent >> 4;
				objResult->bytes[j] = (intCurrent & 0x0f) << 4;
				break;

			case 2:
				objResult->bytes[j++] |= intCurrent >>2;
				objResult->bytes[j] = (intCurrent & 0x03) << 6;
				break;

			case 3:
				objResult->bytes[j++] |= intCurrent;
				break;
		}
		i++;
	}

	// mop things up if we ended on a boundary
	k = j;
	if (intCurrent == '=') {
		switch (i % 4) {
			case 1:
				// Invalid state
                wickr_buffer_destroy(&objResult);
				return NULL;

			case 2:
				k++;
				// flow through
			case 3:
				objResult->bytes[k] = 0;
		}
	}

    objResult->length = j;
	return objResult;
}


static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static int byteMapLen = sizeof(byteMap);

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
INLINE static char
nibbleToChar(uint8_t nibble)
{
    if(nibble < byteMapLen) return byteMap[nibble];
    return '*';
}

/**
 * Convert a buffer of binary values into a hex string representation
 */
wickr_buffer_t *
getHexStringFromData(const wickr_buffer_t *objData)
{
    if (!objData)
        return NULL;
    
    wickr_buffer_t *retval;
    unsigned int i;
    
    retval = wickr_buffer_create_empty(objData->length*2 + 1);
    if (retval) {
        for(i=0; i<objData->length; i++) {
            retval->bytes[i*2] = nibbleToChar(objData->bytes[i] >> 4);
            retval->bytes[i*2+1] = nibbleToChar(objData->bytes[i] & 0x0f);
        }
        retval->bytes[i*2] = '\0';
        
        // The length should only be the length of the data, not including the null byte
        retval->length--;
    }
    return retval;
}


unsigned char strToChar (char a, char b)
{
    char encoder[3] = {'\0','\0','\0'};
    encoder[0] = a;
    encoder[1] = b;
    return (char) strtol(encoder,NULL,16);
}

wickr_buffer_t *
getDataFromHexString(const wickr_buffer_t *hexString)
{
    if (!hexString)
        return NULL;
    
    const char * bytes = (const char *)hexString->bytes;
    size_t length = strlen(bytes);
    wickr_buffer_t *result = wickr_buffer_create_empty((length / 2));
    if (!result)
        return NULL;
    
    unsigned char * r = result->bytes;
    
    if (r != NULL) {
        unsigned char * index = r;
        
        while ((*bytes) && (*(bytes +1))) {
            *index = strToChar(*bytes, *(bytes +1));
            index++;
            bytes+=2;
        }
        
        return result;
    }
    
    return NULL;
}
