#ifndef __INCLUDE_CORE_LDR_H
#define __INCLUDE_CORE_LDR_H

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

BOOL
LdrLoadNtapi(VOID);

BOOL
LdrLoadWsapi(VOID);

#endif
