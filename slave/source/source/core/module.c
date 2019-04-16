#include <module.h>
#include <ntapi.h>
#include <crypto\lzo1.h>

PVOID
ModuleInject(
    IN     HANDLE       hProcess,
    IO     PMODULEDATA  ModuleData,
    IN OPT PMODULERELOC ModuleReloc,
    IN     BOOL         bIs64Module
    )
{
    $DLOG1(DLG_FLT_INFO, "Injecting module 0x%p %lu/%lu pages to %p", ModuleData->Content, 1 + (ModuleData->cbCompressed / 0x1000), 1 + (ModuleData->cbDecompressed / 0x1000), hProcess);

    PVOID Buffer = NULL;
    SIZE_T cbBuffer = ModuleData->cbDecompressed;

    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &Buffer, 0, &cbBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        $DLOG1(DLG_FLT_ERROR, "NtAllocateVirtualMemory failed miserably");

        return NULL;
    }

    $DLOG3(DLG_FLT_DEFAULT, "Address: 0x%p Compressed: %lu Decompressed: %lu", Buffer, ModuleData->cbCompressed, ModuleData->cbDecompressed);

    Lzo1Decompress(ModuleData->Content, ModuleData->cbCompressed, Buffer);

    if (NOT_NULL(ModuleReloc)) {
        PIMAGE_BASE_RELOCATION BaseReloc = ModuleReloc->Content;

        while (BaseReloc->SizeOfBlock) {
            $DLOG2(DLG_FLT_DEFAULT,  "% 8lX RVA % 8lX SizeOfBlock", BaseReloc->VirtualAddress, BaseReloc->SizeOfBlock);

            PWORD dwRelocArray = (PVOID)((ULONG_PTR)BaseReloc + sizeof(IMAGE_BASE_RELOCATION));
            ULONG NumberOfWords = (BaseReloc->SizeOfBlock  - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (ULONG i = 0; i != NumberOfWords; i++) {
                DWORD dwRelocRva  = dwRelocArray[i] & 0xFFF;
                DWORD dwRelocType = dwRelocArray[i] >> 12;

                if (bIs64Module) {
                    PULONG64_PTR dwPointer = (PVOID)((ULONG_PTR)Buffer + BaseReloc->VirtualAddress + dwRelocRva);

                    $DLOG3(DLG_FLT_DEFAULT,  "    % 8X %X %016I64X -> %016I64X", dwRelocRva, dwRelocType, *dwPointer, *dwPointer + (ULONG64_PTR)Buffer);

                    *dwPointer += (ULONG64_PTR)Buffer;
                } else {
                    PULONG32_PTR dwPointer = (PVOID)((ULONG_PTR)Buffer + BaseReloc->VirtualAddress + dwRelocRva);

                    $DLOG3(DLG_FLT_DEFAULT,  "    % 8X %X %08lX -> %08lX", dwRelocRva, dwRelocType, *dwPointer, *dwPointer + (ULONG32_PTR)Buffer);

                    *dwPointer += (ULONG32_PTR)Buffer;
                }
            }

            ((ULONG_PTR)BaseReloc) += (NumberOfWords * 2) + sizeof(IMAGE_BASE_RELOCATION);
        }
    }

    $DLOG1(DLG_FLT_INFO, "Done");

    return Buffer;
}
