#ifndef __INCLUDE_CORE_NTAPI_H
#define __INCLUDE_CORE_NTAPI_H

extern
ULONG
(CDECL * fnVsnprintf)(
    OUT PVOID  Buffer,
    IN  SIZE_T BufferMaxSize,
    IN  PCSTR  szFormat,
    IN  PVOID  Arguments
);

BOOL
InitNtapi(VOID);

#endif
