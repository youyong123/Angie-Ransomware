#ifndef _INCLUDE_SDK_INTERNAL_
#define _INCLUDE_SDK_INTERNAL_

#define PF_FLOATING_POINT_PRECISION_ERRATA       0
#define PF_FLOATING_POINT_EMULATED               1
#define PF_COMPARE_EXCHANGE_DOUBLE               2
#define PF_MMX_INSTRUCTIONS_AVAILABLE            3
#define PF_PPC_MOVEMEM_64BIT_OK                  4
#define PF_ALPHA_BYTE_INSTRUCTIONS               5
#define PF_XMMI_INSTRUCTIONS_AVAILABLE           6
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE          7
#define PF_RDTSC_INSTRUCTION_AVAILABLE           8
#define PF_PAE_ENABLED                           9
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE        10
#define PF_SSE_DAZ_MODE_AVAILABLE               11
#define PF_NX_ENABLED                           12
#define PF_SSE3_INSTRUCTIONS_AVAILABLE          13
#define PF_COMPARE_EXCHANGE128                  14
#define PF_COMPARE64_EXCHANGE128                15
#define PF_CHANNELS_ENABLED                     16
#define PF_XSAVE_ENABLED                        17
#define PF_ARM_VFP_32_REGISTERS_AVAILABLE       18
#define PF_ARM_NEON_INSTRUCTIONS_AVAILABLE      19
#define PF_SECOND_LEVEL_ADDRESS_TRANSLATION     20
#define PF_VIRT_FIRMWARE_ENABLED                21
#define PF_RDWRFSGSBASE_AVAILABLE               22
#define PF_FASTFAIL_AVAILABLE                   23
#define PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE     24
#define PF_ARM_64BIT_LOADSTORE_ATOMIC           25
#define PF_ARM_EXTERNAL_CACHE_AVAILABLE         26
#define PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE      27
#define PF_RDRAND_INSTRUCTION_AVAILABLE         28
#define PF_ARM_V8_INSTRUCTIONS_AVAILABLE        29
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30
#define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE  31
#define PF_RDTSCP_INSTRUCTION_AVAILABLE         32
#define PF_RDPID_INSTRUCTION_AVAILABLE          33

#define PROCESSOR_FEATURE_MAX 64

#define PROCESSOR_ARCHITECTURE_INTEL    0
#define PROCESSOR_ARCHITECTURE_MIPS     1
#define PROCESSOR_ARCHITECTURE_ALPHA    2
#define PROCESSOR_ARCHITECTURE_PPC      3
#define PROCESSOR_ARCHITECTURE_SHX      4
#define PROCESSOR_ARCHITECTURE_ARM      5
#define PROCESSOR_ARCHITECTURE_IA64     6
#define PROCESSOR_ARCHITECTURE_ALPHA64  7
#define PROCESSOR_ARCHITECTURE_MSIL     8
#define PROCESSOR_ARCHITECTURE_AMD64    9
#define PROCESSOR_ARCHITECTURE_UNKNOWN  0xFFFF

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT         Flags;
    USHORT         Length;
    ULONG          TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG          MaximumLength;
    ULONG          Length;
    ULONG          Flags;
    ULONG          DebugFlags;
    PVOID          ConsoleHandle;
    ULONG          ConsoleFlags;
    HANDLE         StdInputHandle;
    HANDLE         StdOutputHandle;
    HANDLE         StdErrorHandle;
    UNICODE_STRING CurrentDirectoryPath;
    HANDLE         CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID          Environment;
    ULONG          StartingPositionLeft;
    ULONG          StartingPositionTop;
    ULONG          Width;
    ULONG          Height;
    ULONG          CharWidth;
    ULONG          CharHeight;
    ULONG          ConsoleTextAttributes;
    ULONG          WindowFlags;
    ULONG          ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopName;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef enum _PROCESS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PROCESS_CREATE_STATE;

typedef struct _PROCESS_CREATE_INFO {
    SIZE_T Size;
    PROCESS_CREATE_STATE State;

    union {
        // PsCreateInitialState
        struct {
            union {
                ULONG InitFlags;

                struct {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };

            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct {
            union {
                ULONG OutputFlags;

                struct {
                    UCHAR  ProtectedProcess      :  1;
                    UCHAR  AddressSpaceOverride  :  1;
                    UCHAR  DevOverrideEnabled    :  1; // from Image File Execution Options
                    UCHAR  ManifestDetected      :  1;
                    UCHAR  ProtectedProcessLight :  1;
                    UCHAR  SpareBits1            :  3;
                    UCHAR  SpareBits2            :  8;
                    USHORT SpareBits3            : 16;
                };
            };

            HANDLE  FileHandle;
            HANDLE  SectionHandle;
            ULONG64 UserProcessParametersNative;
            ULONG   UserProcessParametersWow64;
            ULONG   CurrentParameterFlags;
            ULONG64 PebAddressNative;
            ULONG   PebAddressWow64;
            ULONG64 ManifestAddress;
            ULONG   ManifestSize;
        } SuccessState;
    };
} PROCESS_CREATE_INFO, *PPROCESS_CREATE_INFO;

typedef struct _IO_STATUS_BLOCK {
    union {
      NTSTATUS Status;
      PVOID    Pointer;
    };

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* undocumented */
typedef VOID IO_APC_ROUTINE, *PIO_APC_ROUTINE;

typedef struct _KSYSTEM_TIMER {
    ULONG32 LowPart;
    LONG32  High1Part;
    LONG32  High2Part;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _LIST_ENTRY32 {
    PVOID32 Flink;
    PVOID32 Blink;
} LIST_ENTRY32, *PLIST_ENTRY32;

typedef struct _LIST_ENTRY64 {
    PVOID64 Flink;
    PVOID64 Blink;
} LIST_ENTRY64, *PLIST_ENTRY64;

#define USER_SHARED_DATA 0x7FFE0000

typedef struct _KUSER_SHARED_DATA {
    ULONG32 TickCountLowDeprecated;
    ULONG32 TickCountMultiplier;
    VOLATILE KSYSTEM_TIME InterruptTime;
    VOLATILE KSYSTEM_TIME SystemTime;
    VOLATILE KSYSTEM_TIME TimeZoneBias;
    UCHAR   Reserved1[0x04];
    WCHAR   NtSystemRoot[MAX_PATH];
    UCHAR   Reserved2[0x2C];
    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    UCHAR   Reserved3[0x01];
    USHORT  NativeProcessorArchitecture; /* Windows 8 and above */
    UCHAR   Reserved4[0x08];
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    UCHAR   Reserved5[0x20];
    BOOLEAN KdDebuggerEnabled;
    UCHAR   Reserved6[0x17];
    BOOLEAN SafeBootMode;
    UCHAR   Reserved7[0x1B];
    ULONG   SystemCall;
    UCHAR   Reserved8[0x14];

    union {
        KSYSTEM_TIME TickCount;
        ULONG64 TickCountQuad;
    };
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct _CLIENT_ID32 {
    ULONG32 UniqueProcess;
    ULONG32 UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _CLIENT_ID64 {
    ULONG64 UniqueProcess;
    ULONG64 UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

typedef struct _NT_TIB32 {
    PVOID32 ExceptionList;
    PVOID32 StackBase;
    PVOID32 StackLimit;
    PVOID32 SubSystemTib;

    union {
        PVOID32 FiberData;
        ULONG32 Version;
    };

    PVOID32 ArbitraryUserPointer;
    PVOID32 Self;
} NT_TIB32, *PNT_TIB32;

typedef struct _NT_TIB64 {
    PVOID64 ExceptionList;
    PVOID64 StackBase;
    PVOID64 StackLimit;
    PVOID64 SubSystemTib;

    union {
        PVOID64 FiberData;
        ULONG64 Version;
    };

    PVOID64 ArbitraryUserPointer;
    PVOID64 Self;
} NT_TIB64, *PNT_TIB64;

#define TLS_MAX_SLOTS 64

typedef struct _TEB32 {
    NT_TIB32 NtTib;
    PVOID32 EnvironmentPointer;
    CLIENT_ID32 ClientId;
    UCHAR   Reserved1[0x004];
    PVOID32 ThreadLocalStoragePointer;
    PVOID32 ProcessEnvironmentBlock;
    ULONG32 LastErrorValue;
    UCHAR Reserved2[0x0088];
    PVOID WOW32Reserved;
    UCHAR Reserved3[0x0B30];
    ULONG32 LastStatusValue;
    UNICODE_STRING32 StaticUnicodeString;
    WCHAR   StaticUnicodeBuffer[MAX_PATH + 1];
    UCHAR   Reserved4[0x004];
    ULONG32 TlsSlots[TLS_MAX_SLOTS];
    LIST_ENTRY32 TlsLinks;
    UCHAR   Reserved5[0x010];
    ULONG32 HardErrorMode;
} TEB32, *PTEB32;

typedef struct _TEB64 {
    NT_TIB64 NtTib;
    PVOID64 EnvironmentPointer;
    CLIENT_ID64 ClientId;
    UCHAR   Reserved1[0x0008];
    PVOID64 ThreadLocalStoragePointer;
    PVOID64 ProcessEnvironmentBlock;
    ULONG32 LastErrorValue;
    UCHAR   Reserved2[0x0094];
    PVOID64 WOW32Reserved;
    UCHAR   Reserved3[0x1148];
    ULONG32 LastStatusValue;
    UNICODE_STRING64 StaticUnicodeString;
    WCHAR   StaticUnicodeBuffer[MAX_PATH + 1];
    UCHAR   Reserved4[0x000E];
    ULONG64 TlsSlots[TLS_MAX_SLOTS];
    LIST_ENTRY64 TlsLinks;
    UCHAR   Reserved5[0x0020];
    ULONG32 HardErrorMode;
} TEB64, *PTEB64;

#define FLG_STOP_ON_EXCEPTION           0x00000001
#define FLG_SHOW_LDR_SNAPS              0x00000002
#define FLG_DEBUG_INITIAL_COMMAND       0x00000004
#define FLG_STOP_ON_HUNG_GUI            0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK      0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK      0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS    0x00000040
#define FLG_HEAP_VALIDATE_ALL           0x00000080
#define FLG_APPLICATION_VERIFIER        0x00000100
#define FLG_POOL_ENABLE_TAGGING         0x00000400
#define FLG_HEAP_ENABLE_TAGGING         0x00000800
#define FLG_USER_STACK_TRACE_DB         0x00001000
#define FLG_KERNEL_STACK_TRACE_DB       0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST    0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL      0x00008000
#define FLG_DISABLE_STACK_EXTENSION     0x00010000
#define FLG_ENABLE_CSRDEBUG             0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD   0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS  0x00080000
#define FLG_ENABLE_SYSTEM_CRIT_BREAKS   0x00100000
#define FLG_HEAP_DISABLE_COALESCING     0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS     0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING    0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING  0x01000000
#define FLG_HEAP_PAGE_ALLOCS            0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX    0x04000000
#define FLG_DISABLE_DBGPRINT            0x08000000
#define FLG_CRITSEC_EVENT_CREATION      0x10000000
#define FLG_LDR_TOP_DOWN                0x20000000
#define FLG_ENABLE_HANDLE_EXCEPTIONS    0x40000000
#define FLG_DISABLE_PROTDLLS            0x80000000
#define FLG_VALID_BITS                  0x7FFFFFFF

typedef struct _PEB32 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    UCHAR   Reserved1[0x005];
    PVOID32 ImageBaseAddress;
    PVOID32 Ldr;
    PVOID32 ProcessParameters;
    UCHAR   Reserved2[0x004];
    PVOID32 ProcessHeap;
    UCHAR   Reserved3[0x03C];
    PVOID32 AnsiCodePageData;
    PVOID32 OemCodePageData;
    PVOID32 UnicodeCaseTableData;
    ULONG32 NumberOfProcessors;
    ULONG32 NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG32 HeapSegmentReserve;
    ULONG32 HeapSegmentCommit;
    ULONG32 HeapDeCommitTotalFreeThreshold;
    ULONG32 HeapDeCommitFreeBlockThreshold;
    ULONG32 NumberOfHeaps;
    ULONG32 MaximumNumberOfHeaps;
    PVOID32 ProcessHeaps;
    UCHAR   Reserved4[0x010];
    ULONG32 OSMajorVersion;
    ULONG32 OSMinorVersion;
    USHORT  OSBuildNumber;
    USHORT  OSCSDVersion;
    ULONG32 OSPlatformId;
    ULONG32 ImageSubsystem;
    ULONG32 ImageSubsystemMajorVersion;
    ULONG32 ImageSubsystemMinorVersion;
    ULONG32 ActiveProcessAffinityMask;
    UCHAR   Reserved5[0x3B4];
    ULONG32 NtGlobalFlag2; /* Don't use under Windows 7 */
} PEB32, *PPEB32;

typedef struct _PEB64 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    UCHAR   Reserved1[0x009];
    PVOID64 ImageBaseAddress;
    PVOID64 Ldr;
    PVOID64 ProcessParameters;
    UCHAR   Reserved2[0x008];
    PVOID64 ProcessHeap;
    UCHAR   Reserved3[0x068];
    PVOID64 AnsiCodePageData;
    PVOID64 OemCodePageData;
    PVOID64 UnicodeCaseTableData;
    ULONG32 NumberOfProcessors;
    ULONG32 NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG64 HeapSegmentReserve;
    ULONG64 HeapSegmentCommit;
    ULONG64 HeapDeCommitTotalFreeThreshold;
    ULONG64 HeapDeCommitFreeBlockThreshold;
    ULONG32 NumberOfHeaps;
    ULONG32 MaximumNumberOfHeaps;
    PVOID64 ProcessHeaps;
    UCHAR   Reserved4[0x020];
    ULONG32 OSMajorVersion;
    ULONG32 OSMinorVersion;
    USHORT  OSBuildNumber;
    USHORT  OSCSDVersion;
    ULONG32 OSPlatformId;
    ULONG32 ImageSubsystem;
    ULONG32 ImageSubsystemMajorVersion;
    ULONG32 ImageSubsystemMinorVersion;
    ULONG32 ActiveProcessAffinityMask;
    UCHAR   Reserved5[0x68C];
    ULONG32 NtGlobalFlag2; /* Don't use under Windows 7 */
} PEB64, *PPEB64;

typedef struct _PEB_LDR_DATA32 {
    ULONG32 Lenght;
    BOOLEAN Initialized;
    PVOID32 SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    PVOID32 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    PVOID32 ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA64 {
    ULONG32 Lenght;
    BOOLEAN Initialized;
    PVOID64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    PVOID64 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    PVOID64 ShutdownThreadId;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef enum _LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency           =  0,
    LoadReasonStaticForwarderDependency  =  1,
    LoadReasonDynamicForwarderDependency =  2,
    LoadReasonDelayloadDependency        =  3,
    LoadReasonDynamicLoad                =  4,
    LoadReasonAsImageLoad                =  5,
    LoadReasonAsDataLoad                 =  6,
    LoadReasonEnclavePrimary             =  7,
    LoadReasonEnclaveDependency          =  8,
    LoadReasonUnknown                    = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    PVOID32 DllBase;
    PVOID32 EntryPoint;
    ULONG32 SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;

    union {
        ULONG32 Flags;

        struct {
            ULONG32 PackagedBinary          : 1;
            ULONG32 MarkedForRemoval        : 1;
            ULONG32 ImageDll                : 1;
            ULONG32 LoadNotificationsSent   : 1;
            ULONG32 TelemetryEntryProcessed : 1;
            ULONG32 ProcessStaticImport     : 1;
            ULONG32 InLegacyLists           : 1;
            ULONG32 InIndexes               : 1;
            ULONG32 ShimDll                 : 1;
            ULONG32 InExceptionTable        : 1;
            ULONG32 ReservedFlags1          : 2;
            ULONG32 LoadInProgress          : 1;
            ULONG32 LoadConfigProcessed     : 1;
            ULONG32 EntryProcessed          : 1;
            ULONG32 ProtectDelayLoad        : 1;
            ULONG32 ReservedFlags3          : 2;
            ULONG32 DontCallForThreads      : 1;
            ULONG32 ProcessAttachCalled     : 1;
            ULONG32 ProcessAttachFailed     : 1;
            ULONG32 CorDeferredValidate     : 1;
            ULONG32 CorImage                : 1;
            ULONG32 DontRelocate            : 1;
            ULONG32 CorILOnly               : 1;
            ULONG32 ChpeImage               : 1;
            ULONG32 ReservedFlags5          : 2;
            ULONG32 Redirected              : 1;
            ULONG32 ReservedFlags6          : 2;
            ULONG32 CompatDatabaseProcessed : 1;
        };
    };

    UCHAR Reserve1[0x58];

    /* Windows 8 and above */
    ULONG32 BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    PVOID64 DllBase;
    PVOID64 EntryPoint;
    ULONG32 SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;

    union {
        ULONG32 Flags;
    
        struct {
            ULONG32 PackagedBinary          : 1;
            ULONG32 MarkedForRemoval        : 1;
            ULONG32 ImageDll                : 1;
            ULONG32 LoadNotificationsSent   : 1;
            ULONG32 TelemetryEntryProcessed : 1;
            ULONG32 ProcessStaticImport     : 1;
            ULONG32 InLegacyLists           : 1;
            ULONG32 InIndexes               : 1;
            ULONG32 ShimDll                 : 1;
            ULONG32 InExceptionTable        : 1;
            ULONG32 ReservedFlags1          : 2;
            ULONG32 LoadInProgress          : 1;
            ULONG32 LoadConfigProcessed     : 1;
            ULONG32 EntryProcessed          : 1;
            ULONG32 ProtectDelayLoad        : 1;
            ULONG32 ReservedFlags3          : 2;
            ULONG32 DontCallForThreads      : 1;
            ULONG32 ProcessAttachCalled     : 1;
            ULONG32 ProcessAttachFailed     : 1;
            ULONG32 CorDeferredValidate     : 1;
            ULONG32 CorImage                : 1;
            ULONG32 DontRelocate            : 1;
            ULONG32 CorILOnly               : 1;
            ULONG32 ChpeImage               : 1;
            ULONG32 ReservedFlags5          : 2;
            ULONG32 Redirected              : 1;
            ULONG32 ReservedFlags6          : 2;
            ULONG32 CompatDatabaseProcessed : 1;
        };
    };

    UCHAR Reserve1[0x9C];

    /* Windows 8 and above */
    ULONG32 BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

#ifdef _M_AMD64
    typedef CLIENT_ID64 CLIENT_ID;
    typedef LIST_ENTRY64 LIST_ENTRY;
    typedef NT_TIB64 NT_TIB;
    typedef TEB64 TEB;
    typedef PEB64 PEB;
    typedef PEB_LDR_DATA64 PEB_LDR_DATA;
    typedef LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRY;

    typedef PCLIENT_ID64 PCLIENT_ID;
    typedef PLIST_ENTRY64 PLIST_ENTRY;
    typedef PNT_TIB64 PNT_TIB;
    typedef PTEB64 PTEB;
    typedef PPEB64 PPEB;
    typedef PPEB_LDR_DATA64 PPEB_LDR_DATA;
    typedef PLDR_DATA_TABLE_ENTRY64 PLDR_DATA_TABLE_ENTRY;
#else
    typedef CLIENT_ID32  CLIENT_ID;
    typedef LIST_ENTRY32  LIST_ENTRY;
    typedef NT_TIB32  NT_TIB;
    typedef TEB32 TEB;
    typedef PEB32 PEB;
    typedef PEB_LDR_DATA32 PEB_LDR_DATA;
    typedef LDR_DATA_TABLE_ENTRY32 LDR_DATA_TABLE_ENTRY;

    typedef PCLIENT_ID32 PCLIENT_ID;
    typedef PLIST_ENTRY32 PLIST_ENTRY;
    typedef PNT_TIB32 PNT_TIB;
    typedef PTEB32 PTEB;
    typedef PPEB32 PPEB;
    typedef PPEB_LDR_DATA32 PPEB_LDR_DATA;
    typedef PLDR_DATA_TABLE_ENTRY32 PLDR_DATA_TABLE_ENTRY;
#endif

#endif
