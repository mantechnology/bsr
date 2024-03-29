#ifndef __BSR_LINUX_IOCTL_H__
#define __BSR_LINUX_IOCTL_H__


#include <linux/ioctl.h>

#define BSR_CONTROL_DEV     "/dev/bsr-control"
#define BSR_IOCTL_MAGIC     147
#define BSR_HANDLER_USE_REG	"/etc/bsr.d/.handler_use"
#define BSR_MON_RUN_REG		"/etc/bsr.d/.bsrmon_run"



#define IOCTL_MVOL_SET_LOGLV_MIN			_IOWR(BSR_IOCTL_MAGIC, 1, LOGGING_MIN_LV)
#define IOCTL_MVOL_GET_BSR_LOG				_IOWR(BSR_IOCTL_MAGIC, 2, BSR_LOG)

#define IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT	_IOWR(BSR_IOCTL_MAGIC, 3, unsigned int)
#define IOCTL_MVOL_SET_HANDLER_USE			_IOWR(BSR_IOCTL_MAGIC, 4, HANDLER_INFO)
// BSR-654
#define IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY	_IOWR(BSR_IOCTL_MAGIC, 5, DEBUG_LOG_CATEGORY)
// BSR-740
#define IOCTL_MVOL_SET_BSRMON_RUN			_IOWR(BSR_IOCTL_MAGIC, 6, unsigned int)
// BSR-741
#define IOCTL_MVOL_GET_BSRMON_RUN			_IOWR(BSR_IOCTL_MAGIC, 7, unsigned int)
// BSR-764
#define IOCTL_MVOL_SET_SIMUL_PERF_DEGR		_IOWR(BSR_IOCTL_MAGIC, 8, SIMULATION_PERF_DEGR)
// BSR-1048
#define IOCTL_MVOL_WRITE_LOG				_IOWR(BSR_IOCTL_MAGIC, 9, WRITE_KERNEL_LOG)
// BSR-1072
#define IOCTL_MVOL_BSR_PANIC				_IOWR(BSR_IOCTL_MAGIC, 10, KERNEL_PANIC_INFO)
// BSR-1039
#define IOCTL_MVOL_HOLD_STATE			_IOWR(BSR_IOCTL_MAGIC, 11, HOLD_STATE)
// BSR-1039
#define IOCTL_MVOL_FAKE_AL_USED			_IOWR(BSR_IOCTL_MAGIC, 12, int)

#endif

