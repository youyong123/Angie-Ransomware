#ifndef __RTLP_MEMORY_H
#define __RTLP_MEMORY_H

static
VOID
FORCEINLINE
RtlpFillMemoryInstr(
    OUT PVOID  pBuffer,
    IN  ULONG  dwFillChar,
    IN  SIZE_T stFillCount
    )
{
    __stosb((PBYTE)pBuffer, dwFillChar, stFillCount);
}

static
VOID
FORCEINLINE
RtlpZeroMemoryInstr(
    OUT PVOID  pBuffer,
    IN  SIZE_T stFillCount
    )
{
    __stosb((PBYTE)pBuffer, 0, stFillCount);
}

#endif
