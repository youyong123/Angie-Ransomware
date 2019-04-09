#include <config.h>
#include <ntapi.h>
#include <module.h>
#include <identity.h>
#include <crypto/fnv1a.h>
#include <crypto/crc32.h>

#include <ntapi\basic.h>
#include "ntapi\basic.h"

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

    //InitCrc32();
    //CreateHostIdentity();

    return 0;
}
 