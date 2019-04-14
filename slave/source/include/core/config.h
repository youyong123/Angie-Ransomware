#ifndef __INCLUDE_CORE_CONFIG_H
#define __INCLUDE_CORE_CONFIG_H

typedef union _CONFIG {
    DWORD dwParts[10];

    struct {
        struct {
            BOOLEAN bHV;
            BOOLEAN bSSE5; // SSE4.2
            BOOLEAN bSSE4; // SSE4.1
            BOOLEAN bSSE3;
        } Features;

        struct {
            BOOLEAN bIntel;
            BOOLEAN bAmd;
            BOOLEAN bUnderWow64;
            BOOLEAN bLongMode; // CPU mode state
        } Cpu;

        struct {
            union {
                union {
                    BOOLEAN     bMicrosoft;
                    BOOLEAN     bVmware;
                    BOOLEAN NON bPadding;
                    BOOLEAN     bParallels;
                };

                BOOL bEnabled;
            };
        } HyperVisor;

        struct {
            NTVERSION Major;
            NTVERSION Minor;
            NTVERSION Build;
            BOOL      bIsDeprecated;
            ULONG     dwCommonIndex;
        } NtVersion;

        struct {
            WORD  wLongModeSelector;
            WORD  wLegacyModeSelector;
        } Os;
    };
} CONFIG, *PCONFIG;

extern CONFIG Config;

BOOL
DECLSPEC_NOINLINE
InitConfig(VOID);

#endif
