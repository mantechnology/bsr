#ifndef __BSR_IOCTL_H__
#define __BSR_IOCTL_H__


#include <linux/ioctl.h>
#include "../bsr_log.h"

#define BSR_CONTROL_DEV     "/dev/bsr-control"
#define BSR_IOCTL_MAGIC     147

#define IOCTL_MVOL_SET_LOGLV_MIN			_IOWR(BSR_IOCTL_MAGIC, 1, LOGGING_MIN_LV)
#define IOCTL_MVOL_GET_BSR_LOG				_IOWR(BSR_IOCTL_MAGIC, 2, BSR_LOG)

#endif