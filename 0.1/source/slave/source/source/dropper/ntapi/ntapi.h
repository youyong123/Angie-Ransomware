#ifndef __PRIVATE_DROPPER_NTAPISYSCALLS_BASIC_H
#define __PRIVATE_DROPPER_NTAPISYSCALLS_BASIC_H

#define NtapiSyscallsFunctionsCount 9

extern CONST VOLATILE DWORD NtapiSyscallsNamesHashXorKey;
extern DWORD NtapiSyscallsNamesHash[];
extern PVOID NtapiSyscallsAddressStorage[];
extern CONST ULONG NtapiSyscallsOffsetX86[];
extern CONST ULONG NtapiSyscallsOffsetWow64[];

#endif
