#ifndef __DROPPER_INSTANCE_H
#define __DROPPER_INSTANCE_H

extern WCHAR InstanceMutantPath[48];
extern HANDLE InstanceMutantObject;

BOOL
DECLSPEC_NOINLINE
CreateInstance(VOID);

#endif
