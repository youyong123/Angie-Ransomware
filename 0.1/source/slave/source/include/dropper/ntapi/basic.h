#ifndef __DROPPER_NTAPI_BASIC_H
#define __DROPPER_NTAPI_BASIC_H

NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    IN HPROCESS  ProcessHandle,
    IO PVOID    *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IO PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    );

NTSTATUS
NTAPI
NtFreeVirtualMemory(
    IN HPROCESS ProcessHandle,
    IN PVOID   *BaseAddress,
    IO PSIZE_T  RegionSize,
    IN ULONG    FreeType
    );

NTSTATUS
NTAPI
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
    );

NTSTATUS
NTAPI
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
    );

NTSTATUS
NTAPI
NtClose(
    IN HANDLE Handle
    );

#endif
