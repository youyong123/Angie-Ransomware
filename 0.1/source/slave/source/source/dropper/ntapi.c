#include <config.h>
#include <ntapi.h>

enum {
    HASH_NTDLL_KEY = RTLP_LCG_DWORD,
};

static CONST VOLATILE DWORD NtdllStrxsum    = 0xA62A3B3B ^ HASH_NTDLL_KEY; // ntdll.dll
static CONST VOLATILE DWORD NtdllStrxsumAlt = 0x145370BB ^ HASH_NTDLL_KEY; // NTDLL.DLL

static HMODULE hNtdllBase;

ULONG
DECLSPEC_DEPRECATED
NtapiImportAddressMethod(
    IN  ULONG  cbFucntionCount,
    OUT PVOID  pAddressExport,
    IN  PDWORD dwProcNamesHash
    )
{
    return RtlpLdrGetProcAddressEx(
        hNtdllBase,
        cbFucntionCount,
        dwProcNamesHash,
        pAddressExport
        );
}

BOOL
DECLSPEC_DEPRECATED
NtapiFindInMemory(VOID) // TODO: check again
{
    if (IS_NULL(hNtdllBase = RtlpLdrFindModule(NtdllStrxsum ^ HASH_NTDLL_KEY))) {
        if (IS_NULL(hNtdllBase = RtlpLdrFindModule(NtdllStrxsumAlt ^ HASH_NTDLL_KEY))) {
            $DLOG0(DLG_FLT_CRITICAL, "Failed to find ntdll.dll in memory!");

            return FALSE;
        }
    }

    $DLOG2(DLG_FLT_INFO, "Ntdll.dll = 0x%p", hNtdllBase);

    return TRUE;
}
