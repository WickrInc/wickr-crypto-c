#ifdef _WIN32
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include "openssl_suite.h"
#include "openssl_file_suite.h"
#include "memory.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>

#include <limits.h>

#include <string.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(__ANDROID__)
#include <wchar.h>
#else
#endif

typedef struct AESFileOperation {
    char *tempPath;
    FILE *sourceHandle;
    FILE *destinationHandle;
    const char *destination;
    const char *source;
} AESFileOperation;

#pragma mark - Private File Operation Supporting Struct

#if defined(_WIN32)
wchar_t *GetWC(const char *c)
{
    const size_t cSize = mbstowcs(NULL, c, 0) + 1;
    wchar_t* wc = (wchar_t *)wickr_alloc_zero(sizeof(wchar_t) * cSize);
    size_t copiedSize = mbstowcs(wc, c, cSize);

    if (copiedSize == (size_t)(-1)) {
        wickr_free(wc);
        return NULL;
    }

    return wc;
}

errno_t windowsOpenFile(FILE **fileHandle, char *fname, wchar_t *openOpts)
{

    // Need to convert the char string to a wide character string
    wchar_t *wSrc = GetWC(fname);
    
    if (!wSrc) {
        return -1;
    }

    errno_t error = _wfopen_s(fileHandle, wSrc, openOpts);
    wickr_free(wSrc);

    return error;
}

#endif

static AESFileOperation *createFileOperation(const char *source, const char *destination) {
    
    // Must have a source and destination file name
    if (!source || !destination) {
        return NULL;
    }
    
    // Initialize the locals, and values that are passed back in the AESFileOperation
    AESFileOperation *returnOp = NULL;
    char *tempPath = NULL;
    FILE *sourceHandle = NULL;
    FILE *destinationHandle = NULL;
    
    // Open the Source file for reading
#if defined(_WIN32)
	if (windowsOpenFile(&sourceHandle, source, L"rb") != 0 || !sourceHandle) {
        return NULL;
    }
#elif defined(__ANDROID__)
    sourceHandle = fopen(source, "rb");
#else
    sourceHandle = fopen(source, "rb");
#endif

    if (!sourceHandle) {
        return NULL;
    }
    
    // Open the Destination file for writing
    tempPath = wickr_alloc(strlen(destination) + 6);
    if (!tempPath)
        goto process_error;
    sprintf(tempPath, "%s.temp", destination);

#if defined(_WIN32)
    if (windowsOpenFile(&destinationHandle, tempPath, L"wb") != 0 || !destinationHandle) {
        goto process_error;
    }
#elif defined(__ANDROID__)
    destinationHandle = fopen(tempPath, "wb");
    if (! destinationHandle) {
        goto process_error;
    }
#else
    destinationHandle = fopen(tempPath, "wb");
    if (! destinationHandle) {
        goto process_error;
    }
#endif

    returnOp = wickr_alloc_zero(sizeof(AESFileOperation));
    if (returnOp) {
        returnOp->source = source;
        returnOp->destination = destination;
        returnOp->tempPath = tempPath;
        returnOp->sourceHandle = sourceHandle;
        returnOp->destinationHandle = destinationHandle;
        goto process_success;
    }
    
process_error:
    if (sourceHandle) {
        fclose(sourceHandle);
    }
    if (destinationHandle) {
        fclose(destinationHandle);
    }
    if (tempPath) {
        wickr_free(tempPath);
    }
    
process_success:
    return returnOp;
}

static void aesFileOpRemoveTempFile(AESFileOperation *operation) {
    remove(operation->tempPath);
}

static void aesFileOpCloseSourceAndDestination(AESFileOperation *operation) {
	if (operation->sourceHandle) {
		fclose(operation->sourceHandle);
		operation->sourceHandle = NULL;
	}
	if (operation->destinationHandle) {
		fclose(operation->destinationHandle);
		operation->destinationHandle = NULL;
	}
}

static bool aesFileOpMoveTempToDestination(AESFileOperation *operation) {
    aesFileOpCloseSourceAndDestination(operation);
    
    bool retVal = true;
#if defined(_WIN32)
    wchar_t *tmpFname = GetWC(operation->tempPath);
	wchar_t *dstFname = GetWC(operation->destination);

    if (_wrename(tmpFname, dstFname))
        retVal = false;

	wickr_free(tmpFname);
	wickr_free(dstFname);
#elif defined(__ANDROID__) || defined(__linux)
    if (rename(operation->tempPath, operation->destination)) {
        return false;
    }
#else
    if (rename(operation->tempPath, operation->destination))
        retVal = false;
#endif
    return retVal;
}

static void freeFileOperation(AESFileOperation **operation) {
    if (*operation) {
        aesFileOpRemoveTempFile((*operation));
        aesFileOpCloseSourceAndDestination((*operation));
        if ((*operation)->tempPath)
            wickr_free((*operation)->tempPath);
        wickr_free((*operation));
        *operation = NULL;
    }
}

bool openssl_aes256_file_encrypt(const wickr_cipher_key_t *key, const char *sourceFilePath, const char *destinationFilePath)
{    
    if (!key || !sourceFilePath || !destinationFilePath) {
        return false;
    }
    
    AESFileOperation *fileOp = createFileOperation(sourceFilePath, destinationFilePath);
    
    if (!fileOp) {
        return false;
    }
    
    bool result = openssl_encrypt_file(fileOp->sourceHandle, key, fileOp->destinationHandle);
    if (result) {
        result = aesFileOpMoveTempToDestination(fileOp);
    }
    
    freeFileOperation(&fileOp);
    
    return result;
}

bool openssl_aes256_file_decrypt(const wickr_cipher_key_t *key, const char *sourceFilePath, const char *destinationFilePath, bool only_auth_ciphers)
{
    if (!key || !sourceFilePath || !destinationFilePath) {
        return false;
    }
    
    AESFileOperation *fileOp = createFileOperation(sourceFilePath, destinationFilePath);
    if (!fileOp) {
        return false;
    }
    
    bool result = openssl_decrypt_file(fileOp->sourceHandle, key, fileOp->destinationHandle, only_auth_ciphers);
    if (result) {
        result = aesFileOpMoveTempToDestination(fileOp);
    }
    freeFileOperation(&fileOp);
    
    return result;
}



