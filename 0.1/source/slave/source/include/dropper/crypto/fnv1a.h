#ifndef __CRYPTO_FNV1A_H
#define __CRYPTO_FNV1A_H

#define FNV1A_X32_PRIME 0x001000193
#define FNV1A_X32_BASIS 0x0811C9DC5

DWORD
Fnv1AHashStringA(
    IN PSTR szBuffer
    );

DWORD
Fnv1AHashStringW(
    IN PWSTR szBuffer
    );

DWORD
Fnv1AHashBuffer(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    );

static
DWORD
FORCEINLINE
Fnv1AHashStringInlineA(
    IN PSTR szBuffer
    )
{
    DWORD dwHash = FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    while (*szBuffer) {
        dwHash ^= *szBuffer;
        dwHash *= FNV1A_X32_PRIME;
    }

    return dwHash;
}

static
DWORD
FORCEINLINE
Fnv1AHashStringInlineW(
    IN PWSTR szBuffer
    )
{
    DWORD dwHash = FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    while (*szBuffer) {
        dwHash ^= (BYTE)*szBuffer;
        dwHash *= FNV1A_X32_PRIME;
    }

    return dwHash;
}

static
DWORD
FORCEINLINE
Fnv1AHashBufferInline(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    )
{
    DWORD dwHash = FNV1A_X32_BASIS;

    PRAGMA_LOOP_UNROLL_N(16)
    for (ULONG_PTR i = 0; i != cbBuffer; i++) {
        dwHash ^= ((PBYTE)pBuffer)[i];
        dwHash *= FNV1A_X32_PRIME;
    }

    return dwHash;
}

#endif
