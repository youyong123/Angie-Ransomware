#ifndef __NTAPI_NTAPI__
#define __NTAPI_NTAPI__

#define NtapiSyscallsFunctionsCount 10

extern CONST VOLATILE DWORD NtapiSyscallsNamesHashXorKey;
extern DWORD NtapiSyscallsNamesHash[];
extern FARPROC NtapiSyscallsAddressStorage[];
extern CONST ULONG NtapiSyscallsOffset[];

#endif
