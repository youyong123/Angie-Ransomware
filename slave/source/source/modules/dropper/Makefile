
c: cx86 cx64

l: lx86 lx64

cx86:
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c *.c /Fo:$(PROJECT_OBJECT_PATH)/modules/dropper/x86/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c ntapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/modules/dropper/x86/ntapi/

cx64:
	$(ICPP_COMPILER_X64) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c *.c /Fo:$(PROJECT_OBJECT_PATH)/modules/dropper/x64/
	$(ICPP_COMPILER_X64) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c ntapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/modules/dropper/x64/ntapi/

lx86:
	@"$(ICPP_LINKER_X86)" /NOLOGO /TIME /MACHINE:X86 $(LDFL_ADDON) $(LDFL) /LIBPATH:"$(LIB_ICPP_X86)" /LIBPATH:"$(LIB_VCTOOLS_X86)" /LIBPATH:"$(LIB_UNMANAGED_X86)" /LIBPATH:"$(PROJECT_LIB_PATH)/x86" /NOENTRY /DLL /DRIVER /KERNEL /ALIGN:32 /BASE:0 /OUT:$(PROJECT_OBJECT_PATH)/modules/dropper/bin/dropper32.dll \
	$(PROJECT_OBJECT_PATH)/modules/dropper/x86/*.obj \
	$(PROJECT_OBJECT_PATH)/modules/dropper/x86/ntapi/*.obj
	@Module.exe "$(PROJECT_OBJECT_PATH)/modules/dropper/bin/dropper32.dll" "$(PROJECT_PATH)/source/source/core/bin/dropper32.h"

lx64:
	@"$(ICPP_LINKER_X64)" /NOLOGO /TIME /MACHINE:X64 $(LDFL_ADDON) $(LDFL) /LIBPATH:"$(LIB_ICPP_X64)" /LIBPATH:"$(LIB_VCTOOLS_X64)" /LIBPATH:"$(LIB_UNMANAGED_X64)" /LIBPATH:"$(PROJECT_LIB_PATH)/x64" /NOENTRY /DLL /DRIVER /KERNEL /ALIGN:32 /BASE:0 /OUT:$(PROJECT_OBJECT_PATH)/modules/dropper/bin/dropper64.dll \
	$(PROJECT_OBJECT_PATH)/modules/dropper/x64/*.obj \
	$(PROJECT_OBJECT_PATH)/modules/dropper/x64/ntapi/*.obj
	@Module.exe "$(PROJECT_OBJECT_PATH)/modules/dropper/bin/dropper64.dll" "$(PROJECT_PATH)/source/source/core/bin/dropper64.h"
