#ifndef __RTLP_MEMORY_H
#define __RTLP_MEMORY_H

static
VOID
FORCEINLINE
RtlpFillMemoryInstr(
    OUT PVOID  Destination,
    IN  ULONG  dwFillChar,
    IN  SIZE_T FillCount
    )
{
    __stosb((PBYTE)Destination, dwFillChar, FillCount);
}

#define RtlpZeroMemoryInstr(BUFFER, SIZE) RtlpFillMemoryInstr(BUFFER, 0, SIZE)
#define RtlpZeroObjectInstr(OBJECT)       RtlpFillMemoryInstr(&(OBJECT), 0, sizeof(OBJECT))

static
VOID
FORCEINLINE
RtlpFillMemoryInline(
    OUT PVOID  Destination,
    IN  ULONG  FillChar,
    IN  SIZE_T FillCount
    )
{
    if (FillCount > sizeof(M128I)) {
        FillChar |= FillChar <<  8;
        FillChar |= FillChar << 16;

        M128I xwFillChar = _mm_set_epi32(FillChar, FillChar, FillChar, FillChar);

        while (FillCount >= sizeof(M128I)) {
            *((PM128I)Destination)++ = xwFillChar;
            FillCount -= sizeof(M128I);
        }
    }

    while (FillCount) {
        *((PBYTE)Destination)++ = FillChar;
        FillCount--;
    }
}

#define RtlpZeroMemoryInline(BUFFER, SIZE) RtlpFillMemoryInline(BUFFER, 0, SIZE)
#define RtlpZeroObjectInline(OBJECT)       RtlpFillMemoryInline(&(OBJECT), 0, sizeof(OBJECT))

#if 0
    VOID
    RtlpFillMemory(
        OUT PVOID  Destination,
        IN  ULONG  FillChar,
        IN  SIZE_T FillCount
        );

    #define RtlpZeroMemory(BLOCK, SIZE) RtlpFillMemory(BLOCK, 0, SIZE)
    #define RtlpZeroObject(OBJECT)      RtlpFillMemory(&(OBJECT), 0, sizeof(OBJECT))
#endif

static
VOID
FORCEINLINE
RtlpCopyMemoryInstr(
    OUT PVOID  Destination,
    IN  PVOID  Source,
    IN  SIZE_T CopyCount
    )
{
    __movsb((PBYTE)Destination, (PBYTE)Source, CopyCount);
}

static
VOID
FORCEINLINE
RtlpCopyMemoryInline(
    OUT PVOID  Destination,
    IN  PVOID  Source,
    IN  SIZE_T FillCount
    )
{
    while (FillCount >= sizeof(M128I)) {
        *((PM128I)Destination)++ = *((PM128I)Source)++;
        FillCount -= sizeof(M128I);
    }

    while (FillCount) {
        *((PBYTE)Destination)++ = *((PBYTE)Source)++;
        FillCount--;
    }
}

#if 0
    VOID
    RtlpCopyMemory(
        OUT PVOID  Destination,
        IN  PVOID  Source,
        IN  SIZE_T CopyCount
        );
#endif

#endif
