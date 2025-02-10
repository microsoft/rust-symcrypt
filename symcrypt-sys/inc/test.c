#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wrapper.h"
#include <sys/random.h>


VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    if( api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom( PBYTE pbBuffer, SIZE_T cbBuffer )
{
    customRand( pbBuffer, cbBuffer );
    return SYMCRYPT_NO_ERROR;
}




VOID 
SYMCRYPT_CALL
customRand( PBYTE pbRandom, SIZE_T cbRandom) {
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

// //
// // rngsecureurandom.c
// // Defines secure entropy functions using urandom as the source
// //
// // Copyright (c) Microsoft Corporation. Licensed under the MIT license.
// //

// #include "precomp.h"
// #include <sys/random.h>

// // Nothing to init
// VOID
// SYMCRYPT_CALL
// SymCryptEntropySecureInit(void){}

// // Nothing to uninit
// VOID
// SYMCRYPT_CALL
// SymCryptEntropySecureUninit(void){}

// // urandom is our secure entropy source.
// VOID
// SYMCRYPT_CALL
// SymCryptEntropySecureGet( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
// {
//     SIZE_T result;
//     result = getrandom( pbResult, cbResult, 0 );
//     if (result != cbResult )
//     {
//         // If the entropy pool has been initialized and the request size is small
//         // (buflen <= 256), then getrandom() will not fail with EINTR,
//         // but we check anyway as it's not safe to continue if we don't
//         // receive the right amount of entropy.
//         SymCryptFatal( 'rngs' );
//     }
// }