
#define NTDLL_SYSCALL_WOW64(n, xpwow, vwow, w7wow, w8wow, w81wow, w10wow, w11wow, w12wow, w13wow, w14wow, w15wow, w16wow)

enum {
    XOR_KEY = RTLP_LCG_DWORD,
};

CONST VOLATILE DWORD NtapiSyscallsNamesHashXorKey = XOR_KEY;

DWORD NtapiSyscallsNamesHash[] = {
    0x6B372C05 ^ XOR_KEY, // NtClose
    0xCA67B978 ^ XOR_KEY, // NtAllocateVirtualMemory
    0x43E32F32 ^ XOR_KEY, // NtWriteVirtualMemory
    0xED0594DA ^ XOR_KEY, // NtCreateThreadEx
    0x5EA49A38 ^ XOR_KEY, // NtOpenProcess
    0x7A43974A ^ XOR_KEY, // NtQuerySystemInformation
    0x08AC8BAC ^ XOR_KEY, // NtDeviceIoControlFile
    0xF67464E4 ^ XOR_KEY, // NtWriteFile
    0xA9E25A1D ^ XOR_KEY, // NtReadFile
    0xA9C5B599 ^ XOR_KEY, // NtCreateFile
    0x117BE69E ^ XOR_KEY  // NtQueryDirectoryFile
};

FARPROC NtapiSyscallsAddressStorage[] = {
    (PVOID)RTLP_LCG_NATIVE, // NtClose
    (PVOID)RTLP_LCG_NATIVE, // NtAllocateVirtualMemory
    (PVOID)RTLP_LCG_NATIVE, // NtWriteVirtualMemory
    (PVOID)RTLP_LCG_NATIVE, // NtCreateThreadEx
    (PVOID)RTLP_LCG_NATIVE, // NtOpenProcess
    (PVOID)RTLP_LCG_NATIVE, // NtQuerySystemInformation
    (PVOID)RTLP_LCG_NATIVE, // NtDeviceIoControlFile
    (PVOID)RTLP_LCG_NATIVE, // NtWriteFile
    (PVOID)RTLP_LCG_NATIVE, // NtReadFile
    (PVOID)RTLP_LCG_NATIVE, // NtCreateFile
    (PVOID)RTLP_LCG_NATIVE  // NtQueryDirectoryFile
};

CONST ULONG NtapiSyscallsOffset[] = {
    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w7,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w8,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w81,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w10,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w11,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w12,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w13,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w14,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w15,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL

    #define NTDLL_SYSCALL(n, xp, v, w7, w8, w81, w10, w11, w12, w13, w14, w15, w16) w16,
    #include "rawsyscalls.h"
    #undef NTDLL_SYSCALL
};
