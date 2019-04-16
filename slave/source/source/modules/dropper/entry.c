#include <config.h>
#include <ldr.h>

VOID
DECLSPEC_DLLEXPORT
DropperEntry(VOID)
{
    #ifdef DEBUG
        #ifdef _AMD64_
            UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_X64_THREAD0);

            $DLogInitialize(&DebugName, TRUE);
        #else
            /* initialize just the functions */
            $DLogInitialize(NULL, TRUE);
        #endif
    #endif

    #ifdef _AMD64_
        $DLOG1(DLG_FLT_HIGHLIGHT, "TEST DROPPER X64 STARTED");
    #else
        $DLOG1(DLG_FLT_HIGHLIGHT, "TEST DROPPER X32 STARTED");
    #endif

    if (!LdrLoadNtapi()) {
        return;
    }

    #ifdef _AMD64_
        $DLOG1(DLG_FLT_HIGHLIGHT, "TEST DROPPER X64 STOPPED");
    #else
        $DLOG1(DLG_FLT_HIGHLIGHT, "TEST DROPPER X32 STOPPED");
    #endif
}