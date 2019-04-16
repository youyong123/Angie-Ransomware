
c:
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c *.c       /Fo:$(PROJECT_OBJECT_PATH)/core/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c ntapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/ntapi/
	$(ICPP_COMPILER_X86) $(CLFL_BASE) $(CLFL_CPU) $(CLFL_OX) $(CLFL_ADDON) /c wsapi/*.c /Fo:$(PROJECT_OBJECT_PATH)/core/wsapi/
	nasm -f win32 fastcall.asm -o $(PROJECT_OBJECT_PATH)/core/fastcall.obj
