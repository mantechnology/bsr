#ifndef __BSR_IOCTL_H__
#define __BSR_IOCTL_H__


#include <linux/ioctl.h>
#include "../bsr_log.h"

#define BSR_CONTROL_DEV     "/dev/bsr-control"
#define BSR_IOCTL_MAGIC     147
#define BSR_HANDLER_USE_REG	"/etc/bsr.d/.handler_use"

typedef struct _HANDLER_INFO {
	bool				use;
} HANDLER_INFO, *PHANDLER_INFO;


#define IOCTL_MVOL_SET_LOGLV_MIN			_IOWR(BSR_IOCTL_MAGIC, 1, LOGGING_MIN_LV)
#define IOCTL_MVOL_GET_BSR_LOG				_IOWR(BSR_IOCTL_MAGIC, 2, BSR_LOG)
#define IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT	_IOWR(BSR_IOCTL_MAGIC, 3, unsigned int)
#define IOCTL_MVOL_SET_HANDLER_USE			_IOWR(BSR_IOCTL_MAGIC, 4, HANDLER_INFO)
#endif