#include <ldr.h>
#include <ntapi.h>
#include <fnv1a.h>


static
VOID
DECLSPEC_NOINLINE
EnumProcessTest(VOID)
{
    NTSTATUS Status;
    SIZE_T cbProcessInformation = 0;
    PSYSTEM_PROCESS_INFORMATION ProcessInformation = NULL;
 
    if (RtlpGetPeb()->BeingDebugged) { __debugbreak(); }

    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, (PVOID)&cbProcessInformation);

    if (!cbProcessInformation) {
        $DLOG1(DLG_FLT_CRITICAL, "cbProcessInformation = 0");

        return;
    }
 
    if (!NT_SUCCESS(Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&ProcessInformation, 0, &cbProcessInformation, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        $DLOG1(DLG_FLT_CRITICAL, "NtAllocateVirtualMemory %08lX", Status);

        return;
    }

    $DLOG1(DLG_FLT_HIGHLIGHT, "%p", ProcessInformation);

    if (RtlpGetPeb()->BeingDebugged) { __debugbreak(); }

    if (!NT_SUCCESS(Status = NtQuerySystemInformation(SystemProcessInformation, (PVOID)ProcessInformation, cbProcessInformation, (PVOID)&cbProcessInformation))) {
        $DLOG1(DLG_FLT_CRITICAL, "NtQuerySystemInformation %08lX", Status);

        return;
    }

    for (; ProcessInformation->NextEntryOffset; ProcessInformation = (PVOID)((ULONG_PTR)ProcessInformation + ProcessInformation->NextEntryOffset)) {
        DWORD dwSumName = 0;

        if (ProcessInformation->ImageName.Length) {
            dwSumName = Fnv1AHashStringW(ProcessInformation->ImageName.Buffer);
        }

        #ifdef _AMD64_
            $DLOG1(DLG_FLT_HIGHLIGHT, "% 5I64u %08lX %ls", ProcessInformation->UniqueProcessId, dwSumName, ProcessInformation->ImageName.Buffer);
        #else
            $DLOG1(DLG_FLT_HIGHLIGHT, "% 5lu %08lX %ls", ProcessInformation->UniqueProcessId, dwSumName, ProcessInformation->ImageName.Buffer);
        #endif
    }
}

VOID
DECLSPEC_DLLEXPORT
DropperEntry(VOID)
{
    #ifdef DEBUG
        #ifdef _AMD64_
            UNICODE_STRING DebugName = CONST_UNICODE_STRING(SCFG_DLOG_DROPPER_X64_THREAD0);

            $DLogInitialize(&DebugName, TRUE);
        #else
            $DLogInitialize(NULL, TRUE);
        #endif
    #endif

    if (!LdrLoadNtapi()) {
        return;
    }

    EnumProcessTest();
}
