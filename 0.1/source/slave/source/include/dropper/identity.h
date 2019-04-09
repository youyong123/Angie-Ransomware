#ifndef __DROPPER_IDENTITY_H
#define __DROPPER_IDENTITY_H

typedef struct _IDENTITY {
    DWORD Cpu;
    DWORD UserName;
    DWORD ComputerName;
    DWORD Etc;
} IDENTITY, *PIDENTITY;

extern IDENTITY ComputerIndentity;

BOOL
CreateHostIdentity(VOID);

#endif
