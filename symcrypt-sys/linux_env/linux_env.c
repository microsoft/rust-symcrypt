# include "linux_env.h"

/*
This file is for intilizting the required enviroment variables and functions required for building a 
static library on linux. 

The files that we are pulling from are the following:
- SymCrypt/lib/env_posixUserMode.c
- SymCrypt/modules/linux/common/callbacks_pthreads.c
- SymCrypt/modules/linux/common/rng
- SymCrypt/modules/linux/common/optional/rngfipsjitter.c
- SymCrypt/modules/linux/common/optional/rngforkdetection.c
*/

// This section from SymCrypt/lib/env_posixUserMode.c
VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    if( api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }
}

VOID
SYMCRYPT_CALL
SymCryptInitEnvPosixUsermode( UINT32 version )
{
    SymCryptRngInit(); // Rng must be initilized 
    if( g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED )
    {
        return;
    }

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    SymCryptDetectCpuFeaturesByCpuid( SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM );

    //
    // Our SaveXmm function never fails because it doesn't have to do anything in User mode.
    //
    g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;

#elif SYMCRYPT_CPU_ARM

    g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~SYMCRYPT_CPU_FEATURE_NEON;

#elif SYMCRYPT_CPU_ARM64

    SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();

#endif

    SymCryptInitEnvCommon( version );
}

VOID SYMCRYPT_CALL SymCryptInit(void)
{
    SymCryptInitEnvPosixUsermode( SYMCRYPT_API_VERSION );
}

// UGLY HACK: Forward declare __stack_chk_fail introduced by -fstack-protector-strong
// For OpenEnclave binaries we cannot have any PLT entries, but clang ignores -fno-plt for
// __stack_chk_fail.
// Opened issue against clang here: https://github.com/llvm/llvm-project/issues/54816
// If we introduce a direct reference to it in our code then clang does figure out it must be linked
// without PLT
void __stack_chk_fail(void);

// On X86, __stack_chk_fail_local is used as a wrapper for __stack_chk_fail. The compiler should
// generate it for us, but for some reason it is not doing so on gcc 9.4.0.
void __stack_chk_fail_local(void)
{
    __stack_chk_fail();
}

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatalEnvPosixUsermode( ULONG fatalCode )
{
    UINT32 fatalCodeVar;

    SymCryptFatalIntercept( fatalCode );

    //
    // Put the fatal code in a location where it shows up in the dump
    //
    SYMCRYPT_FORCE_WRITE32( &fatalCodeVar, fatalCode );

    //
    // Create an AV, which can trigger a core dump so that we get to
    // see what is going wrong.
    //
    SYMCRYPT_FORCE_WRITE32( (volatile UINT32 *)NULL, fatalCode );

    SymCryptFatalHang( fatalCode );

    // Never reached - call is to force clang not to use PLT entry for this function
    // See forward declaration above
    __stack_chk_fail();
}

// Fatal error handling functions
//_Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatalEnvPosixUsermode( UINT32 fatalCode );
_Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatal( UINT32 fatalCode )
{
    SymCryptFatalEnvPosixUsermode( fatalCode );
}
#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

SYMCRYPT_ENVIRONMENT_DEFS_SAVEXMM( PosixUsermode )
SYMCRYPT_ENVIRONMENT_DEFS_SAVEYMM( PosixUsermode )

VOID
SYMCRYPT_CALL
SymCryptRestoreYmmEnvPosixUsermode( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );
}
VOID
SYMCRYPT_CALL
SymCryptRestoreXmmEnvPosixUsermode( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveYmmEnvPosixUsermode( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );

    return SYMCRYPT_NO_ERROR;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveXmmEnvPosixUsermode( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );

    return SYMCRYPT_NO_ERROR;
}

VOID
SYMCRYPT_CALL
SymCryptCpuidExFuncEnvPosixUsermode( int cpuInfo[4], int function_id, int subfunction_id )
{
    __cpuidex( cpuInfo, function_id, subfunction_id );
}

VOID SYMCRYPT_CALL SymCryptCpuidExFunc ( int cpuInfo[4], int function_id, int subfunction_id ) {
    SymCryptCpuidExFuncEnvPosixUsermode(cpuInfo, function_id, subfunction_id);
}



#endif
SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvPosixUsermode(void)
{
    return 0;
}

SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresent(void)
{
    return SymCryptCpuFeaturesNeverPresentEnvPosixUsermode();
}

VOID
SYMCRYPT_CALL
SymCryptTestInjectErrorEnvPosixUsermode( PBYTE pbBuf, SIZE_T cbBuf )
{
    //
    // This feature is only used during testing. In production it is always
    // an empty function that the compiler can optimize away.
    //
    UNREFERENCED_PARAMETER( pbBuf );
    UNREFERENCED_PARAMETER( cbBuf );
}

VOID SYMCRYPT_CALL SymCryptInjectError( PBYTE pbBuf, SIZE_T cbBuf )
{
    SymCryptTestInjectErrorEnvPosixUsermode( pbBuf, cbBuf );
}


// This section from SymCrypt/modules/linux/common/callbacks_pthreads.c
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
SymCryptCallbackRandom( PBYTE pbBuffer, SIZE_T cbBuffer )
{
    SymCryptRandom( pbBuffer, cbBuffer );
    return SYMCRYPT_NO_ERROR;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc(void)
{
    PVOID ptr = malloc(sizeof(pthread_mutex_t));

    if( ptr )
    {
        if( pthread_mutex_init( (pthread_mutex_t *)ptr, NULL ) != 0 )
        {
            free(ptr);
            ptr = NULL;
        }
    }
    
    return ptr;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_destroy( (pthread_mutex_t *)pMutex );

    free(pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_lock( (pthread_mutex_t *)pMutex );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_unlock( (pthread_mutex_t *)pMutex );
}

// This section from SymCrypt/modules/linux/common/rng

// Size of small entropy request cache, same as Windows
#define  RANDOM_NUM_CACHE_SIZE         128
#define  MAX_GENERATE_BEFORE_RESEED    8192

PVOID g_rngLock; // lock around access to following global variable

BOOLEAN g_RngStateInstantiated = FALSE;
SYMCRYPT_RNG_AES_STATE g_AesRngState;

BYTE g_randomBytesCache[RANDOM_NUM_CACHE_SIZE];
SIZE_T g_cbRandomBytesCache = 0;

UINT32 g_rngCounter = 0; // reseed when counter exceeds MAX_GENERATE_BEFORE_RESEED, increments 1 per generate

// This function reseeds the RNG state using the Fips entropy source and the secure entropy source.
// Seed is constructed as per SP800-90A for CTR_DRBG with a derivation function, that is
// entropy_input || additional_input, where entropy input is from the SP800-90B compliant (if applicable)
// Fips entropy source and the additional input is from the secure entropy source.
VOID
SymCryptRngReseed(void)
{
    BYTE seed[64]; // 256 bits of entropy input and 256 bits of additional input

    // Second half of seed is 'additional input' of SP800-90A for DRBG.
    // Additional input is simply data from secure entropy source. Place directly in second half of seed buffer
    SymCryptEntropySecureGet( seed + 32, 32 );

    // Fill first half of seed with SP800-90B compliant (if applicable) Fips entropy source
    SymCryptEntropyFipsGet( seed, 32 );

    // Perform the reseed
    SymCryptRngAesReseed( &g_AesRngState, seed, sizeof(seed) );

    // Don't use any existing cached random data
    g_cbRandomBytesCache = 0;

    SymCryptWipeKnownSize( seed, sizeof(seed) );
}

// This function must be called during module initialization. It sets up
// the mutex used in following calls to Rng infrastructure.
VOID
SYMCRYPT_CALL
SymCryptRngInit(void)
{
    g_rngLock = SymCryptCallbackAllocateMutexFastInproc();

    if (g_rngLock == NULL)
    {
        SymCryptFatal( 'rngi' );
    }
}

// This sets up the internal SymCrypt RNG state by initializing the entropy sources,
// then instantiating the RNG state by seeding from Fips and secure entropy sources.
// First 32 bytes are from Fips source and last 32 are from the secure source, as per
// SP800-90A section 10.2.1.3.2.
// The FIPS input constitutes the entropy_input while secure input is the nonce.
VOID
SYMCRYPT_CALL
SymCryptRngInstantiate(void)
{
    SYMCRYPT_ERROR error = SYMCRYPT_NO_ERROR;
    BYTE seed[64];

    // Initialize both entropy sources
    SymCryptEntropyFipsInit();
    SymCryptEntropySecureInit();

    // Get entropy from Fips entropy source
    SymCryptEntropyFipsGet( seed, 32 );

    // Get nonce and personalization string from secure entropy source
    SymCryptEntropySecureGet( seed + 32, 32 );

    // Instantiate internal RNG state
    error = SymCryptRngAesInstantiate(
        &g_AesRngState,
        seed,
        sizeof(seed) );

    if( error != SYMCRYPT_NO_ERROR )
    {
        // Instantiate only fails if cbSeedMaterial is a bad size, and if it does,
        // SymCrypt cannot continue safely
        SymCryptFatal( 'rngi' );
    }

    SymCryptWipeKnownSize( seed, sizeof(seed) );

    SymCryptRngForkDetectionInit();

    g_RngStateInstantiated = TRUE;
}

// This function must be called during module uninitialization. Cleans
// up the RNG state and lock.
// Note: bytes in g_randomBytesCache are not wiped, as they have never been
// output and so are not secret
VOID
SYMCRYPT_CALL
SymCryptRngUninit(void)
{
    SymCryptEntropyFipsUninit();
    SymCryptEntropySecureUninit();
    SymCryptRngAesUninstantiate( &g_AesRngState );
    SymCryptCallbackFreeMutexFastInproc( g_rngLock );
}

// Nothing to uninit
VOID
SYMCRYPT_CALL
SymCryptEntropySecureUninit(void){}

// Nothing to init
VOID
SYMCRYPT_CALL
SymCryptEntropySecureInit(void){}

// This function fills pbRandom with cbRandom bytes. For small requests,
// we use a cache of pre-generated random bits. For large requests, we call
// the AesRngState's generate function directly
VOID
SYMCRYPT_CALL
SymCryptRandom( PBYTE pbRandom, SIZE_T cbRandom )
{
    SIZE_T cbRandomTmp = cbRandom;
    SIZE_T mask;
    SIZE_T cbFill;

    if( cbRandom == 0 )
    {
        return;
    }
    
    SymCryptCallbackAcquireMutexFastInproc( g_rngLock );

    if( !g_RngStateInstantiated )
    {
        SymCryptRngInstantiate();
    }
    else
    {
        // If a fork is detected, or counter is high enough, we reseed the RNG state
        ++g_rngCounter;
        if( SymCryptRngForkDetect() || (g_rngCounter > MAX_GENERATE_BEFORE_RESEED) )
        {
            // Call the Module reseed function
            // This will reseed for us with Fips and secure entropy sources
            SymCryptRngReseed();

            g_rngCounter = 0;
        }
    }

    // Big or small request?
    if( cbRandom < RANDOM_NUM_CACHE_SIZE )
    {
        // small request, use cache
        if( g_cbRandomBytesCache > 0 )
        {
            // bytes already in cache, use them
            cbFill = SYMCRYPT_MIN( cbRandomTmp, g_cbRandomBytesCache );
            memcpy(
                pbRandom,
                &g_randomBytesCache[g_cbRandomBytesCache - cbFill],
                cbFill
            );
            SymCryptWipe(
                &g_randomBytesCache[g_cbRandomBytesCache - cbFill],
                cbFill
            );
            g_cbRandomBytesCache -= cbFill;

            pbRandom += cbFill;
            cbRandomTmp -= cbFill;
        }

        if( cbRandomTmp > 0 )
        {
            // cache empty, repopulate it and continue to fill
            SymCryptRngAesGenerate(
                &g_AesRngState,
                g_randomBytesCache,
                RANDOM_NUM_CACHE_SIZE
            );

            g_cbRandomBytesCache = RANDOM_NUM_CACHE_SIZE;

            memcpy(
                pbRandom,
                &g_randomBytesCache[g_cbRandomBytesCache - cbRandomTmp],
                cbRandomTmp
            );
            SymCryptWipe(
                &g_randomBytesCache[g_cbRandomBytesCache - cbRandomTmp],
                cbRandomTmp
            );
            g_cbRandomBytesCache -= cbRandomTmp;

            // If we never throw away some bytes, then we could have long-lasting alignment
            // problems which slow everything down.
            // If an application ever asks for a single random byte,
            // and then only for 16 bytes at a time, then every memcpy from the cache
            // would incur alignment penalties.
            // We throw away some bytes to get aligned with the current request size,
            // up to 16-alignment. This tends to align our cache with the alignment of the common
            // request sizes.
            // We throw away at most 15 bytes out of 128.

            mask = cbRandom;            //                              xxxx100...0
            mask = mask ^ (mask - 1);   // set lsbset + all lower bits  0000111...1
            mask = (mask >> 1) & 15;    // bits to mask out             0000011...1 limited to 4 bits
            g_cbRandomBytesCache &= ~mask;
        }

    }
    else
    {
        // Large request, call generate directly
        SymCryptRngAesGenerate(
            &g_AesRngState,
            pbRandom,
            cbRandom
        );
    }

    SymCryptCallbackReleaseMutexFastInproc( g_rngLock );
}

// This function mixes the provided entropy into the RNG state using a call to SymCryptRngAesGenerateSmall
// We mix the caller provided entropy with secure entropy using SHA256 to form the 32-bytes of additional input
VOID
SYMCRYPT_CALL
SymCryptProvideEntropy( PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    BYTE additionalInput[32];
    SYMCRYPT_ERROR scError;
    SYMCRYPT_SHA256_STATE hashState;

    SymCryptSha256Init( &hashState );
    SymCryptSha256Append( &hashState, pbEntropy, cbEntropy );

    // Mix in data from secure entropy source.
    // Place in additionalInput buffer to store until we hash it.
    SymCryptEntropySecureGet( additionalInput, 32 );
    SymCryptSha256Append( &hashState, additionalInput, 32 );

    // Get hash result in additionalInput buffer.
    SymCryptSha256Result( &hashState, additionalInput );

    SymCryptCallbackAcquireMutexFastInproc( g_rngLock );

    scError = SymCryptRngAesGenerateSmall(
        &g_AesRngState,
        NULL,
        0,
        additionalInput,
        sizeof(additionalInput) );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SymCryptFatal( 'acdx' );
    }

    SymCryptCallbackReleaseMutexFastInproc( g_rngLock );

    SymCryptWipeKnownSize( additionalInput, sizeof(additionalInput) );
}

/// from SymCrypt/modules/linux/common/optional
VOID
SYMCRYPT_CALL
SymCryptEntropySecureGet( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    SIZE_T result;
    result = getrandom( pbResult, cbResult, 0 );
    if (result != cbResult )
    {
        // If the entropy pool has been initialized and the request size is small
        // (buflen <= 256), then getrandom() will not fail with EINTR,
        // but we check anyway as it's not safe to continue if we don't
        // receive the right amount of entropy.
        SymCryptFatal( 'rngs' );
    }
}

// This section from SymCrypt/modules/linux/common/optional/rngfipsjitter.c
static struct rand_data* g_jitter_entropy_collector = NULL;

// Initialize Jitter source and allocate entropy collector
VOID
SYMCRYPT_CALL
SymCryptEntropyFipsInit(void)
{
    if (jent_entropy_init() != 0)
    {
        // Documentation suggests that the statistical tests the init
        // function runs will succeed if the underlying system is appropriate
        // to run jitter on, so it should never fail on systems where we
        // need it to run.
        SymCryptFatal( 'jiti' );
    }
    
    g_jitter_entropy_collector = jent_entropy_collector_alloc( 1, JENT_FORCE_FIPS );
    if (g_jitter_entropy_collector == NULL)
    {
        // Entropy collector allocation only fails if the tests mention above fail,
        // invalid flags are passed in, or memory allocation fails. In a properly
        // running environment, we should not encounter any of those.
        SymCryptFatal( 'jita' );
    }
}

// Free entropy collector
VOID
SYMCRYPT_CALL
SymCryptEntropyFipsUninit(void)
{
    if (g_jitter_entropy_collector != NULL)
    {
        jent_entropy_collector_free( g_jitter_entropy_collector );
        g_jitter_entropy_collector = NULL;
    }
}

// Jitter is our SP 800-90B compliant entropy source.
VOID
SYMCRYPT_CALL
SymCryptEntropyFipsGet( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    SIZE_T result;
    result = jent_read_entropy( g_jitter_entropy_collector, (char *)pbResult, cbResult );
    if (result != cbResult)
    {
        // FIPS_jitter_entropy should always return the amount of bytes requested.
        // If not, SymCrypt can't safely continue.
        SymCryptFatal( 'jite' );
    }
}

// This section from SymCrypt/modules/linux/common/optional/rngforkdetection.c
pid_t g_pid = 0;

// Sets the initial pid
VOID
SYMCRYPT_CALL
SymCryptRngForkDetectionInit(void)
{
    g_pid = getpid();
}

// Returns true if pid has changed since init or last call
BOOLEAN
SYMCRYPT_CALL
SymCryptRngForkDetect(void)
{
    BOOLEAN forkDetected = FALSE;
    pid_t currPid = getpid();

    if( currPid != g_pid )
    {
        forkDetected = TRUE;
        g_pid = currPid;
    }

    return forkDetected;
}
