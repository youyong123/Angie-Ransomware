
c:
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/*.c         /Fo:$(PROJECT_OBJECT_PATH)/core/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/ntapi/*.c   /Fo:$(PROJECT_OBJECT_PATH)/core/ntapi/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/wsapi/*.c   /Fo:$(PROJECT_OBJECT_PATH)/core/wsapi/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c source/dropper/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/dropper/
	nasm -f win32 source/fastcall.asm -o $(PROJECT_OBJECT_PATH)/core/fastcall.obj
