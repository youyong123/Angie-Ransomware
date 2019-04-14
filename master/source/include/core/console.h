#ifndef __INCLUDE_CORE_CONSOLE_H
#define __INCLUDE_CORE_CONSOLE_H

VOID
DECLSPEC_NOINLINE
CDECL
ConsolePrint(
    IN PCSTR szFormat,
    IN ...
    );

VOID
InitConsole(VOID);

#endif
