#include <identity.h>
#include <crypto\crc32.h>

IDENTITY ComputerIndentity;

BOOL
CreateHostIdentity(VOID)
{
    $DLOG0(DLG_FLT_INFO, "Creating host identity");

    DWORD dwBuffer[4];

    /* CPU */
    {
        PRAGMA_LOOP_UNROLL
        for (ULONG i = 0x80000002; i != 0x80000004; i++) {
            __cpuid((PVOID)&dwBuffer, i);
            ComputerIndentity.Cpu ^= Crc32SumBuffer((PVOID)&dwBuffer, sizeof(dwBuffer));
        }
    };

    /* UserName */
    {
        // TODO:
    };

    /* ComputerName */
    {
        // TODO:
    };

    /* Random stuff */
    {
        PPEB Peb = RtlpGetPeb();

        dwBuffer[0] = RtlpUserShared()->NumberOfPhysicalPages;
        dwBuffer[1] = RtlpUserShared()->AlternativeArchitecture | (RtlpUserShared()->BootId << 16);
        dwBuffer[2] = RtlpUserShared()->NtProductType           | (Peb->OSBuildNumber       << 16);
        dwBuffer[3] =                   Peb->OSMajorVersion     | (Peb->OSMinorVersion      << 16);

        ComputerIndentity.Etc = Crc32SumBuffer((PVOID)&dwBuffer, sizeof(dwBuffer));
    };

    $DLOG0(DLG_FLT_HIGHLIGHT, "%08lX%08lX%08lX%08lX", ComputerIndentity.Cpu, ComputerIndentity.UserName, ComputerIndentity.ComputerName, ComputerIndentity.Etc);
    $DLOG1(DLG_FLT_INFO, "Done!");

    return TRUE;
}

