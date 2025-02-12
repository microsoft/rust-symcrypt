//
// static_LinuxDefault.c
// Default implementation for Linux static shared object.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wrapper.h"
#include <sys/random.h>
#include <errno.h>

SYMCRYPT_ENVIRONMENT_POSIX_USERMODE;

// Exposing SymCryptModuleInit and under the covers calling SymCryptInit.
// Doing this allows us to use less #[cfg] attributes in the Rust code, and does not expose
// SymCryptInit to the public symcrypt-sys API.
VOID
SYMCRYPT_CALL
SymCryptModuleInit(
    _In_ UINT32 api,
    _In_ UINT32 minor) {
    SymCryptInit();
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    // aligned_alloc requires size to be integer multiple of alignment
    SIZE_T cbAllocation = (nBytes + (SYMCRYPT_ASYM_ALIGN_VALUE - 1)) & ~(SYMCRYPT_ASYM_ALIGN_VALUE - 1);

    return aligned_alloc(SYMCRYPT_ASYM_ALIGN_VALUE, cbAllocation);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree( VOID * pMem )
{
    free( pMem );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(unsigned char *pbBuffer, size_t cbBuffer)
{
    size_t total_received = 0;
    ssize_t result;

    while (total_received < cbBuffer) {
        result = getrandom(pbBuffer + total_received, cbBuffer - total_received, 0);
        if (result < 0) {
            if (errno == EINTR) {
                // Buffer is not yet full, continue to get more entropy
                continue;
            }
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        total_received += (size_t)result;
    }
    return SYMCRYPT_NO_ERROR;
}

// From Linux docs on getrandom:
// RETURN VALUE         top
//        On success, getrandom() returns the number of bytes that were
//        copied to the buffer buf.  This may be less than the number of
//        bytes requested via buflen if either GRND_RANDOM was specified in
//        flags and insufficient entropy was present in the random source or
//        the system call was interrupted by a signal.
//        On error, -1 is returned, and errno is set to indicate the error.
VOID 
SYMCRYPT_CALL
SymCryptRandom( PBYTE pbRandom, SIZE_T cbRandom) {
    size_t total_received = 0;
    ssize_t result;

    while (total_received < cbRandom) {
        result = getrandom(pbRandom + total_received, cbRandom - total_received, 0);
        if (result < 0) {
            if (errno == EINTR) {
                // Buffer is not yet full, continue to get more entropy
                continue;
            }
            SymCryptFatal(' rngs ');
        }
        total_received += (size_t)result;
    }
}
