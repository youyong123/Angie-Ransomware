#include <config.h>
#include <fastcall.h>
#include <ntapi.h>
#include "basic.h"

PVOID BasicSyscallsProcess[] = {
    (PVOID)RTLP_LCG_NATIVE,
    (PVOID)RTLP_LCG_NATIVE,
    (PVOID)RTLP_LCG_NATIVE,
    (PVOID)RTLP_LCG_NATIVE,
    (PVOID)RTLP_LCG_NATIVE
};

#define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow)

enum {
    XOR_KEY = RTLP_LCG_DWORD,
};

CONST VOLATILE DWORD BasicSyscallsNamesHashXorKey = XOR_KEY;

DWORD BasicSyscallsNamesHash[] = {
    0xCA67B978 ^ XOR_KEY, // NtAllocateVirtualMemory
    0xB51CC567 ^ XOR_KEY, // NtFreeVirtualMemory
    0xED0594DA ^ XOR_KEY, // NtCreateThreadEx
    0xA9C5B599 ^ XOR_KEY, // NtCreateFile
    0x6B372C05 ^ XOR_KEY  // NtClose
};

CONST ULONG BasicSyscallsOffsetX86[] = {
    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w7x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w8x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w81x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w10x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w11x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w12x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w13x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w14x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w15x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86

    #define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86) w16x86,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_X86
};

#undef  NTDLL_SYSCALL_WOW64
#define NTDLL_SYSCALL_X86(n, w2K, xpx86, w2k3, vx86, w7x86, w8x86, w81x86, w10x86, w11x86, w12x86, w13x86, w14x86, w15x86, w16x86)

CONST ULONG BasicSyscallsOffsetWow64[] = {
    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w7wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w8wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w81wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w10wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w11wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w12wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w13wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w14wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w15wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64

    #define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow) w16wow,
    #include "basicoffset.h"
    #undef NTDLL_SYSCALL_WOW64
};

PRAGMA_WARNING_DISABLE_PUSH(869) // parameter "X" was never referenced

NTSTATUS
NTAPISTUB
NtAllocateVirtualMemory(
    IN HPROCESS  ProcessHandle,
    IO PVOID    *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IO PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    )
{
    NTAPI_STUB_SOURCE(BasicSyscallsProcess[0], 0x18);
}

NTSTATUS
NTAPISTUB
NtFreeVirtualMemory(
    IN HPROCESS ProcessHandle,
    IN PVOID   *BaseAddress,
    IO PSIZE_T  RegionSize,
    IN ULONG    FreeType
    )
{
    NTAPI_STUB_SOURCE(BasicSyscallsProcess[1], 0x10);
}

NTSTATUS
NTAPISTUB
NtCreateThreadEx(
    OUT PHTRHEAD    hThread,
    IN  ACCESS_MASK DesiredAccess,
    IN  PVOID       ObjectAttributes,
    IN  HPROCESS    ProcessHandle,
    IN  PTHREAD_START_ROUTINE pStartAddress,
    IN  PVOID       pParameter,
    IN  BOOL        CreateSuspended,
    IN  ULONG       StackZeroBits,
    IN  ULONG       SizeOfStackCommit,
    IN  ULONG       SizeOfStackReserve,
    OUT PVOID       pBytesBuffer
    )
{
    NTAPI_STUB_SOURCE(BasicSyscallsProcess[2], 0x2C);
}

NTSTATUS
NTAPISTUB
NtCreateFile(
    OUT PHANDLE            FileHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK   IoStatusBlock,
    IN  PLARGE_INTEGER     AllocationSize,
    IN  ULONG              FileAttributes,
    IN  ULONG              ShareAccess,
    IN  ULONG              CreateDisposition,
    IN  ULONG              CreateOptions,
    IN  PVOID              EaBuffer,
    IN  ULONG              EaLength
    )
{
    NTAPI_STUB_SOURCE(BasicSyscallsProcess[3], 0x2C);
}

NTSTATUS
NTAPISTUB
NtClose(
    IN HANDLE Handle
    )
{
    NTAPI_STUB_SOURCE(BasicSyscallsProcess[4], 0x4);
}

PRAGMA_WARNING_DISABLE_POP(869)

