#ifndef __RTLP_BUFFER_H
#define __RTLP_BUFFER_H

static
PVOID
FORCEINLINE
RtlpBufferGetDosBuffer32(VOID)
{
    return &RtlpGetTeb32()->StaticUnicodeBuffer;
}

static
PVOID
FORCEINLINE
RtlpBufferGetDosBuffer64(VOID)
{
    return &RtlpGetTeb64()->StaticUnicodeBuffer;
}

static
PVOID
FORCEINLINE
RtlpBufferGetDosBuffer(VOID)
{
    #ifdef _AMD64_
        return &(RtlpGetTeb64()->StaticUnicodeBuffer);
    #else
        return &(RtlpGetTeb32()->StaticUnicodeBuffer);
    #endif
}

static
PVOID
FORCEINLINE
RtlpBufferGetFiberDat(VOID)
{
    #ifdef _AMD64_
        return &RtlpGetTeb64()->NtTib.FiberData;
    #else
        return &RtlpGetTeb32()->NtTib.FiberData;
    #endif
}

#endif
