#ifndef __RTLP_FNV1A_H
#define __RTLP_FNV1A_H

#define RTLP_FNV1A_X32_PRIME 0x001000193
#define RTLP_FNV1A_X32_BASIS 0x0811C9DC5

static
DWORD
FORCEINLINE
RtlpFnv1AHashStringA(
    IN PSTR szBuffer
    )
{
    DWORD dwHash = RTLP_FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    while (*szBuffer) {
        dwHash ^= *szBuffer++;
        dwHash *= RTLP_FNV1A_X32_PRIME;
    }

    return dwHash;
}

static
DWORD
FORCEINLINE
RtlpFnv1AHashStringW(
    IN PWSTR szBuffer
    )
{
    DWORD dwHash = RTLP_FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    while (*szBuffer) {
        dwHash ^= (BYTE)*szBuffer++;
        dwHash *= RTLP_FNV1A_X32_PRIME;
    }

    return dwHash;
}

static
DWORD
FORCEINLINE
RtlpFnv1AHashBuffer(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    )
{
    DWORD dwHash = RTLP_FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    for (ULONG_PTR i = 0; i != cbBuffer; i++) {
        dwHash ^= ((PBYTE)pBuffer)[i];
        dwHash *= RTLP_FNV1A_X32_PRIME;
    }

    return dwHash;
}

#endif
