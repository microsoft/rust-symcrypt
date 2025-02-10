#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wrapper.h"
#include <sys/random.h>
#include <errno.h>

SYMCRYPT_ENVIRONMENT_POSIX_USERMODE
// add SymCryptINit() for static link

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

// from linux docs

// RETURN VALUE         top
//        On success, getrandom() returns the number of bytes that were
//        copied to the buffer buf.  This may be less than the number of
//        bytes requested via buflen if either GRND_RANDOM was specified in
//        flags and insufficient entropy was present in the random source or
//        the system call was interrupted by a signal.

//        On error, -1 is returned, and errno is set to indicate the error.
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
                // Interrupted by a signal, retry the call
                continue;
            }
            //return SYMCRYPT_INTERNAL_ERROR; // Other errors, fail
            SymCryptFatal( 'vers' );

        }

        total_received += (size_t)result;
    }

    return SYMCRYPT_NO_ERROR;
}



VOID 
SYMCRYPT_CALL
SymCryptRandom( PBYTE pbRandom, SIZE_T cbRandom) {
    SIZE_T result;
    result = getrandom( pbRandom, cbRandom, 0 );
    if (result != cbRandom )
    {
        // If the entropy pool has been initialized and the request size is small
        // (buflen <= 256), then getrandom() will not fail with EINTR,
        // but we check anyway as it's not safe to continue if we don't
        // receive the right amount of entropy.
        SymCryptFatal( 'rngs' );
    }
}
