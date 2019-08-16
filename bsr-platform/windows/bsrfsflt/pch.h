
#ifndef __DRBDLOCK_PCH_H_
#define __DRBDLOCK_PCH_H_

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
#pragma warning(disable: 4127)

#include <FltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>
#include "bsrfsflt.h"
#include "bsrfsflt_struct.h"
#include "bsrfsflt_comm.h"
#include "bsrfsflt_proc.h"
#include "volBlock.h"

#endif