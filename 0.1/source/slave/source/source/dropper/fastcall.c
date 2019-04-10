#include <config.h>
#include <fastcall.h>

VOID
FASTCALLSTUB
KiFastSystemCall(VOID)
{
    __asm {
        mov edx, esp
        sysenter
        ret
    };
}

// TODO: Test
//ULONG64
//KiJumpLongMode(
//    IN PVOID64 pAddress,
//    IN PVOID64 pArgs
//    )
//{
//    /*
//        Slow, but still faster than microsoft wow64cpu!ExitFromSimulatedCode... or some shit like that
//    */
//
//    __asm {
//        /*
//            assembler doesn't understand "jmp selector:address"
//            need to use the slow method or use external assembler
//        */
//        mov byte ptr [Config.Cpu.bLongMode], 1
//        push word ptr [Config.Cpu.wSelectorX86]
//        push offset L2
//        push word ptr [Config.Cpu.wSelectorAmd64]
//        push offset L1
//        retf
//
//    L1:
//        mov edi, dword ptr [offset pArgs]
//        call [offset pAddress]
//        retf
//
//    L2:
//        mov byte ptr [Config.Cpu.bLongMode], 0
//    }
//}

//
//#if 0
//    VOID
//    FASTCALLSTUB
//    KiFastSystemCall64(void)
//    {
//        enum {
//            SystemCallOffset = FIELD_OFFSET(USER_SHARED_DATA, Syscall)
//        }
//
//        __asm {
//            _emit 0x4C
//            _emit 0x8B
//            _emit 0xD1
//            test byte ptr [USER_SHARED_DATA + SystemCallOffset], TRUE
//            jne L1
//            syscall
//            ret
//        L1:
//            int 0x2E
//            ret
//        };
//    }
//#endif
