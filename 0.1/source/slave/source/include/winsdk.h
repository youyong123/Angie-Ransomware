#ifndef __INCLUDE_WINSDK_H
#define __INCLUDE_WINSDK_H

/*
    "patched" windows.h wannabe header that removes all beta features and gives steroids on weak types and defines
*/

#define _WIN32_WINNT  0x0601
#define _WIN32_IE     0x0800
#define NTDDI_VERSION 0x06010000
#define WINVER        0x0601

#define PRAGMA_PACK_PUSH(X)            __pragma(pack(push, X))
#define PRAGMA_PACK_POP(X)             __pragma(pack(pop))
#define PRAGMA_WARNING_SUPPRESS(X)     __pragma(warning(suppress:X))
#define PRAGMA_WARNING_DISABLE(X)      __pragma(warning(disable:X))
#define PRAGMA_WARNING_PUSH            __pragma(warning(push))
#define PRAGMA_WARNING_POP             __pragma(warning(pop))
#define PRAGMA_WARNING_DISABLE_PUSH(X) __pragma(warning(push, disable:X))
#define PRAGMA_WARNING_DISABLE_POP(X)  __pragma(warning(pop))
#define PRAGMA_LOOP_NOUNROLL           __pragma(nounroll)
#define PRAGMA_LOOP_UNROLL             __pragma(unroll)
#define PRAGMA_LOOP_UNROLL_N(X)        __pragma(unroll(X))
#define PRAGMA_OPTIMIZATION_LEVEL(X)   __pragma(intel optimization_level X)
#define PRAGMA_MESSAGE(X)              __pragma(message(X))

#define DECLSPEC_NAKED                 __declspec(naked)
#define DECLSPEC_NOINLINE              __declspec(noinline)
#define DECLSPEC_NORETURN              __declspec(noreturn)
#define DECLSPEC_DEPRECATED            __declspec(deprecated)
#define DECLSPEC_ALIGN_8               __declspec(align(8))
#define DECLSPEC_ALIGN_16              __declspec(align(16))
#define DECLSPEC_ALIGN(X)              __declspec(align(X))
#define DECLSPEC_INTRIN_TYPE           __declspec(intrin_type)
#define DECLSPEC_SELECTANY             __declspec(selectany)
#define DECLSPEC_DLLIMPORT             __declspec(dllimport)
#define DECLSPEC_DLLEXPORT             __declspec(dllexport)

#define CDECL      __cdecl
#define STDCALL    __stdcall
#define FASTCALL   __fastcall
#define VECTORCALL __vectorcall

#define INLINE      __inline
#define FORCEINLINE __forceinline

#include <windef.h>
#include <winbase.h>
#include <no_sal2.h>

#define IO  // in/out
#define NON // not used
#define OPT // optional

#undef VOID
#undef NULL
#undef INVALID_HANDLE_VALUE
#undef DECLARE_HANDLE

typedef void VOID;
typedef const void CVOID;

#ifndef DEBUG
    #undef DBG_UNREFERENCED_PARAMETER(P)
    #undef DBG_UNREFERENCED_LOCAL_VARIABLE(V)

    #define DBG_UNREFERENCED_PARAMETER(P)
    #define DBG_UNREFERENCED_LOCAL_VARIABLE(V)
#endif

#define __TOTEXT(X) #X
#define TOTEXT(X)   __TOTEXT(X)

#define SIGNED    signed
#define UNSIGNED  unsigned
#define VOLATILE  volatile

#define PTR64 __ptr64
#define PTR32 __ptr32

#define MAKELONG64(L, H) ((ULONG64)(((ULONG32)(L)) | ((ULONG64)H) << 32))

typedef ULONG64 QWORD, *PQWORD;

PRAGMA_WARNING_DISABLE_PUSH(344) // invalid redeclaration of type name X

typedef double      DOUBLE,   *PDOUBLE;
typedef long double DOUBLE64, *PDOUBLE64;

typedef SHORT  SHORT_PTR,  *PSHORT_PTR;
typedef LONG64 LONG64_PTR, *PLONG64_PTR;
typedef LONG32 LONG32_PTR, *PLONG32_PTR;

typedef USHORT  USHORT_PTR,  *PUSHORT_PTR;
typedef ULONG64 ULONG64_PTR, *PULONG64_PTR;
typedef ULONG32 ULONG32_PTR, *PULONG32_PTR;
typedef QWORD   QWORD_PTR,   *PQWORD_PTR;

typedef ULONG_PTR   DWORD_PTR,   *PDWORD_PTR;
typedef ULONG64_PTR DWORD64_PTR, *PDWORD64_PTR;
typedef ULONG32_PTR DWORD32_PTR, *PDWORD32_PTR;

typedef void        VOID;
typedef const void  CVOID;

typedef VOID *      PVOID;
typedef VOID *PTR64 PVOID64;
typedef VOID *PTR32 PVOID32;

typedef CVOID *      PCVOID;
typedef CVOID *PTR64 PCVOID64;
typedef CVOID *PTR32 PCVOID32;

#define NULL   ((PVOID  )((ULONG_PTR )0))
#define NULL64 ((PVOID64)(ULONG64_PTR)0))
#define NULL32 ((PVOID32)(ULONG32_PTR)0))

#define IS_NULL(X)  (!(X))
#define NOT_NULL(X) (X)

typedef PVOID   HANDLE,   *PHANDLE;
typedef PVOID64 HANDLE64, *PHANDLE64;
typedef PVOID32 HANDLE32, *PHANDLE32;

#define INVALID_HANDLE_VALUE   ((HANDLE  )(ULONG_PTR  )-1)
#define INVALID_HANDLE_VALUE64 ((HANDLE64)(ULONG64_PTR)-1)
#define INVALID_HANDLE_VALUE32 ((HANDLE32)(ULONG32_PTR)-1)

#define IS_INVALID_HANDLE(X)  ((X) == -1)
#define NOT_INVALID_HANDLE(X) ((X) != -1)

#define DECLARE_HANDLE(X) \
    typedef HANDLE  X;    \
    typedef PHANDLE P##X

#define DECLARE_HANDLE64(X) \
    typedef HANDLE64  X;    \
    typedef PHANDLE64 P##X

#define DECLARE_HANDLE32(X) \
    typedef HANDLE32  X;    \
    typedef PHANDLE32 P##X

#define DECLARE_HANDLEWOW64(X) \
    DECLARE_HANDLE(X);         \
    DECLARE_HANDLE64(X##64);   \
    DECLARE_HANDLE32(X##32)

DECLARE_HANDLE(HPROCESS);
DECLARE_HANDLE(HTRHEAD);

#define PAGE_SIZE 0x1000

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)

typedef LONG NTSTATUS, *PNTSTATUS;

#define NT_SUCCESS(Status)     (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)     ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)       ((((ULONG)(Status)) >> 30) == 3)

typedef struct _UNICODE_STRING {
    USHORT       Length;
    USHORT       MaximumLength;
    WCHAR *PTR32 Buffer;
} UNICODE_STRING, *PTR32 PUNICODE_STRING, *PTR64 LPUNICODE_STRING;

typedef struct _UNICODE_STRING32 {
    USHORT       Length;
    USHORT       MaximumLength;
    WCHAR *PTR32 Buffer;
} UNICODE_STRING32, *PTR32 PUNICODE_STRING32, *PTR64 LPUNICODE_STRING32;

typedef struct _UNICODE_STRING64 {
    USHORT       Length;
    USHORT       MaximumLength;
    WCHAR *PTR64 Buffer;
} UNICODE_STRING64, *PTR32 PUNICODE_STRING64, *PTR64 LPUNICODE_STRING64;

#define CONST_STRING(X)             \
    {                               \
        sizeof(X) - sizeof((X)[0]), \
        sizeof(X),                  \
        X                           \
    }

#define CONST_UNICODE_STRING CONST_STRING
#define CONST_ANSII_STRING   CONST_STRING

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt    = 1,
    NtProductLanManNt = 2,
    NtProductServer   = 3
} NT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIMER {
    ULONG32 LowPart;
    LONG32  High1Part;
    LONG32  High2Part;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

/* All "PF_*" are defined but not PROCESSOR_FEATURE_MAX :? */
#define PROCESSOR_FEATURE_MAX 64

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
    UCHAR   Reserved5[0x0C];
    ULONG   AlternativeArchitecture;
    ULONG   BootId;
    BOOLEAN KdDebuggerEnabled;
    UCHAR   Reserved6[0x1C];
    ULONG   NumberOfPhysicalPages;
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

typedef struct _TEB32 {
    NT_TIB32 NtTib;
    PVOID32  EnvironmentPointer;
    CLIENT_ID32 ClientId;
    UCHAR    Reserved1[0x004];
    PVOID32  ThreadLocalStoragePointer;
    PVOID32  ProcessEnvironmentBlock;
    ULONG32  LastErrorValue;
    UCHAR    Reserved2[0x0088];
    PVOID    WOW32Reserved;
    UCHAR    Reserved3[0x0B30];
    ULONG32  LastStatusValue;
    UNICODE_STRING32 StaticUnicodeString;
    WCHAR    StaticUnicodeBuffer[MAX_PATH + 1];
    UCHAR    Reserved4[0x004];
    ULONG32  TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY32 TlsLinks;
    UCHAR    Reserved5[0x010];
    ULONG32  HardErrorMode;
} TEB32, *PTEB32;

typedef struct _TEB64 {
    NT_TIB64 NtTib;
    PVOID64  EnvironmentPointer;
    CLIENT_ID64 ClientId;
    UCHAR    Reserved1[0x0008];
    PVOID64  ThreadLocalStoragePointer;
    PVOID64  ProcessEnvironmentBlock;
    ULONG32  LastErrorValue;
    UCHAR    Reserved2[0x0094];
    PVOID64  WOW32Reserved;
    UCHAR    Reserved3[0x1148];
    ULONG32  LastStatusValue;
    UNICODE_STRING64 StaticUnicodeString;
    WCHAR    StaticUnicodeBuffer[MAX_PATH + 1];
    UCHAR    Reserved4[0x000E];
    ULONG64  TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY64 TlsLinks;
    UCHAR    Reserved5[0x0020];
    ULONG32  HardErrorMode;
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
    typedef CLIENT_ID64             CLIENT_ID;
    typedef TEB64                   TEB;
    typedef PEB64                   PEB;
    typedef PEB_LDR_DATA64          PEB_LDR_DATA;
    typedef LDR_DATA_TABLE_ENTRY64  LDR_DATA_TABLE_ENTRY;

    typedef PCLIENT_ID64            PCLIENT_ID;
    typedef PTEB64                  PTEB;
    typedef PPEB64                  PPEB;
    typedef PPEB_LDR_DATA64         PPEB_LDR_DATA;
    typedef PLDR_DATA_TABLE_ENTRY64 PLDR_DATA_TABLE_ENTRY;
#else
    typedef CLIENT_ID32             CLIENT_ID;
    typedef TEB32                   TEB;
    typedef PEB32                   PEB;
    typedef PEB_LDR_DATA32          PEB_LDR_DATA;
    typedef LDR_DATA_TABLE_ENTRY32  LDR_DATA_TABLE_ENTRY;

    typedef PCLIENT_ID32            PCLIENT_ID;
    typedef PTEB32                  PTEB;
    typedef PPEB32                  PPEB;
    typedef PPEB_LDR_DATA32         PPEB_LDR_DATA;
    typedef PLDR_DATA_TABLE_ENTRY32 PLDR_DATA_TABLE_ENTRY;
#endif

PRAGMA_WARNING_DISABLE_POP(344)

#endif
