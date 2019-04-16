#ifndef __INCLUDE_CORE_MODULE_H
#define __INCLUDE_CORE_MODULE_H

typedef struct _MODULEDATA {
    PVOID Content;
    ULONG cbCompressed;
    ULONG cbDecompressed;
} MODULEDATA, *PMODULEDATA;

typedef struct _MODULERELOC {
    PVOID Content;
    ULONG cbContent;
} MODULERELOC, *PMODULERELOC;

PVOID
ModuleInject(
    IN     HANDLE       hProcess,
    IO     PMODULEDATA  ModuleData,
    IN OPT PMODULERELOC ModuleReloc,
    IN     BOOL         bIs64Module
    );

#endif
