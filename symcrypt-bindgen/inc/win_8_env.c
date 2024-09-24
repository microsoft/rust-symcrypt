#include "../../../SymCrypt/inc/symcrypt.h"
#include "../../../SymCrypt/inc/symcrypt_low_level.h"

//SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN8_1_N_LATER;



VOID SYMCRYPT_CALL SymCryptInitEnvWindowsUsermodeWin8_1nLater( UINT32 version );
VOID SYMCRYPT_CALL SymCryptInit(void)
{

    SymCryptInitEnvWindowsUsermodeWin8_1nLater( SYMCRYPT_API_VERSION );
}

// Fatal error handling functions
_Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatalEnvWindowsUsermodeWin8_1nLater( UINT32 fatalCode );
_Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatal( UINT32 fatalCode )
{
    SymCryptFatalEnvWindowsUsermodeWin8_1nLater( fatalCode );
}

// CPU feature reporting functions
SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater(void);
SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresent(void)
{
    return SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater();
}

// Register handling functions (SIMD/AVX context saving)
SYMCRYPT_ENVIRONMENT_DEFS_SAVEXMM( WindowsUsermodeWin8_1nLater )
SYMCRYPT_ENVIRONMENT_DEFS_SAVEYMM( WindowsUsermodeWin8_1nLater )

// Error injection functions
VOID SYMCRYPT_CALL SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater( PBYTE pbBuf, SIZE_T cbBuf );
VOID SYMCRYPT_CALL SymCryptInjectError( PBYTE pbBuf, SIZE_T cbBuf )
{
    SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater( pbBuf, cbBuf );
}

VOID SYMCRYPT_CALL SymCryptCpuidExFunc ( int cpuInfo[4], int function_id, int subfunction_id ) {
    SymCryptCpuidExFuncEnvWindowsUsermodeWin8_1nLater(cpuInfo, function_id, subfunction_id);
}


// this code is from C:\Code\SymCrypt\modules\windows\user
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

// Ensure that windows.h doesn't re-define the status_* symbols
#define WIN32_NO_STATUS
#include <windows.h>
#include <windef.h>
#include <bcrypt.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;

// #define SYMCRYPT_FIPS_STATUS_INDICATOR
// #include "../modules/statusindicator_common.h"
// #include "../lib/status_indicator.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;


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

VOID
SYMCRYPT_CALL
SymCryptProvideEntropy(
    _In_reads_(cbEntropy)   PCBYTE  pbEntropy,
                            SIZE_T  cbEntropy )
{
    UNREFERENCED_PARAMETER(pbEntropy);
    UNREFERENCED_PARAMETER(cbEntropy);
}

VOID
SYMCRYPT_CALL
SymCryptRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG) cbBuffer, 0 );
    if (!NT_SUCCESS(status))
    {
        SymCryptFatal(status);
    }
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

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    LPCRITICAL_SECTION lpCriticalSection = malloc( sizeof(CRITICAL_SECTION) );
    InitializeCriticalSection(lpCriticalSection);
    return (PVOID)lpCriticalSection;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    LPCRITICAL_SECTION lpCriticalSection = (LPCRITICAL_SECTION)pMutex;
    DeleteCriticalSection(lpCriticalSection);
    free(lpCriticalSection);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    EnterCriticalSection( (LPCRITICAL_SECTION) pMutex );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    LeaveCriticalSection( (LPCRITICAL_SECTION) pMutex );
}

VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    if (api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }
}
