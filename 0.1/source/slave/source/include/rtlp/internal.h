#ifndef _RTLP_INTERNAL_H
#define _RTLP_INTERNAL_H

static
PKUSER_SHARED_DATA
FORCEINLINE
RtlpUserShared(VOID)
{
    return ((PKUSER_SHARED_DATA)USER_SHARED_DATA);
}

static
PTEB32
FORCEINLINE
RtlpGetTeb32(VOID)
{
    return (PTEB32)((ULONG_PTR)__readfsdword(FIELD_OFFSET(NT_TIB32, Self)));
}

static
PTEB64
FORCEINLINE
RtlpGetTeb64(VOID)
{
    #ifdef _AMD64_
        return (PTEB64)((ULONG_PTR)__readgsdword(FIELD_OFFSET(NT_TIB64, Self)));
    #else
        enum {
            TEB_OFFSET = FIELD_OFFSET(NT_TIB64, Self)
        };

        __asm {
            mov eax, gs:[TEB_OFFSET]
        };
    #endif
}

static
PTEB
FORCEINLINE
RtlpGetTeb(VOID)
{
    #ifdef _AMD64_
        return (PTEB)RtlpGetTeb64();
    #else
        return (PTEB)RtlpGetTeb32();
    #endif
}

static
PPEB32
FORCEINLINE
RtlpGetPeb32(VOID)
{
    PRAGMA_WARNING_DISABLE(810) // conversion from "PVOID64" to "$PPEB64" may lose significant bits)
    return (PPEB32)RtlpGetTeb32()->ProcessEnvironmentBlock;
}

static
PPEB64
FORCEINLINE
RtlpGetPeb64(VOID)
{
    PRAGMA_WARNING_DISABLE(810) // conversion from "PVOID64" to "$PPEB64" may lose significant bits)
    return (PPEB64)RtlpGetTeb64()->ProcessEnvironmentBlock;
}

static
PPEB
FORCEINLINE
RtlpGetPeb(VOID)
{
    #ifdef _AMD64_
        return (PPEB)RtlpGetPeb64();
    #else
        return (PPEB)RtlpGetPeb32();
    #endif
}

#endif
