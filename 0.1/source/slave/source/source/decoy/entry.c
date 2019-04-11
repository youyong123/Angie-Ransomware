#include <entry.h>

ULONG
DecoyEntry(VOID)
{
    $DLOG1(DLG_FLT_INFO, "Executing decoy");

    LoadLibraryW(L"ws2_32.dll");

    #ifdef DEBUG
        $DLogDestroy(TRUE);
    #endif

    return 0;
}
