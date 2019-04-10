#ifndef __DROPPER_NTAPI_H
#define __DROPPER_NTAPI_H

#define NTAPISTUB     \
    DECLSPEC_NAKED    \
    DECLSPEC_NOINLINE \
    NTAPI

NTSTATUS
NTAPISTUB
NtAllocateVirtualMemory(
    IN HPROCESS  ProcessHandle,
    IO PVOID    *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IO PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    );

NTSTATUS
NTAPISTUB
NtFreeVirtualMemory(
    IN HPROCESS ProcessHandle,
    IN PVOID   *BaseAddress,
    IO PSIZE_T  RegionSize,
    IN ULONG    FreeType
    );

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
    );

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
    );

NTSTATUS
NTAPISTUB
NtClose(
    IN HANDLE Handle
    );

NTSTATUS
NTAPISTUB
NtCreateMutant(
    OUT     PHANDLE             MutantHandle,
    IN      ACCESS_MASK         DesiredAccess,
    IN  OPT POBJECT_ATTRIBUTES  ObjectAttributes,
    IN      BOOLEAN             InitialOwner
    );

NTSTATUS
NTAPISTUB
NtOpenMutant(
    OUT PHANDLE            MutantHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSTATUS
NTAPISTUB
NtTerminateProcess(
    IN OPT HANDLE   ProcessHandle,
    IN     NTSTATUS ExitStatus
    );

#endif
