#ifndef __HWEIGHT_H__
#define __HWEIGHT_H__
#include "../../../bsr-headers/windows/types.h"
#include "../bsr_wrappers.h"

extern unsigned int hweight32(unsigned int w);
extern unsigned int hweight16(unsigned int w);
extern unsigned int hweight8(unsigned int w);
extern ULONG_PTR hweight64(__u64 w);
#endif
