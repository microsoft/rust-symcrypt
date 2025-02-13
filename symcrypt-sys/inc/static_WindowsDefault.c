//
// static_WindowsDefault.c
// Default implementation for Windows static shared object.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

// Ensure that windows.h doesn't re-define the status_* symbols
#define WIN32_NO_STATUS
#include <windows.h>
#include <windef.h>
#include <bcrypt.h>
#include <symcrypt.h>
#include <symcrypt_low_level.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    return _aligned_malloc( nBytes, SYMCRYPT_ASYM_ALIGN_VALUE );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    _aligned_free( ptr );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG) cbBuffer, 0 );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}
