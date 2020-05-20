#include <bsr_int.h>
#include <bsr_log.h>

// minimum levels of logging, below indicates default values. it can be changed when BSR receives IOCTL_MVOL_SET_LOGLV_MIN.
atomic_t g_eventlog_lv_min = ATOMIC_INIT(LOG_LV_DEFAULT_EVENTLOG);
atomic_t g_dbglog_lv_min = ATOMIC_INIT(LOG_LV_DEFAULT_DBG);

#ifdef _LIN
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3

#ifndef COMPAT_HAVE_TIME64_TO_TM
#ifndef time64_to_tm
#define time64_to_tm time_to_tm
#endif
#endif
#ifndef COMPAT_HAVE_KTIME_TO_TIMESPEC64
#ifndef ktime_to_timespec64
#define ktime_to_timespec64 ktime_to_timespec
#endif
#endif

#endif



#ifdef _WIN

DWORD msgids[] = {
	PRINTK_EMERG,
	PRINTK_ALERT,
	PRINTK_CRIT,
	PRINTK_ERR,
	PRINTK_WARN,
	PRINTK_NOTICE,
	PRINTK_INFO,
	PRINTK_DBG
};

// _WIN32_MULTILINE_LOG
void save_to_system_event(char * buf, int length, int level_index)
{
	int offset = 3;
	char *p = buf + offset;
	DWORD msgid = msgids[level_index];

	while (offset < length) {
		if (offset != 3)
			msgid = PRINTK_NON;

		int line_sz = WriteEventLogEntryData(msgid, 0, 0, 1, L"%S", p);
		if (line_sz > 0) {
			offset = offset + (line_sz / 2);
			p = buf + offset;
		}
		else {
			WriteEventLogEntryData(PRINTK_ERR, 0, 0, 1, L"%S", KERN_ERR "LogLink: save_to_system_event: unexpected ret\n");
			break;
		}
	}
}
#endif


void _printk(const char * func, const char * level, const char * format, ...)
{
	int ret = 0;
	va_list args;
	char* buf = NULL;
	int length = 0;
	char *ebuf = NULL;
	int elength = 0;
	LONGLONG logcnt = 0;
#ifdef _WIN
	int level_index = format[1] - '0';
#else
	int level_index = printk_get_level(level)  - '0';
#endif
	int printLevel = 0;
	bool bEventLog = false;
	bool bDbgLog = false;
	bool bOosLog = false;
	bool bLatency = false;
#ifdef _WIN
	LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS timeFields = {0,};
#else // _LIN
	struct timespec ts;
	struct tm tm;
#endif
	LONGLONG	totallogcnt = 0;
	long 		offset = 0;
	struct acquire_data ad = { {0}, };

	D_ASSERT(NO_OBJECT, (level_index >= 0) && (level_index < KERN_NUM_END));

	// to write system event log.
	if (level_index <= atomic_read(&g_eventlog_lv_min))
		bEventLog = true;
	// to print through debugger.
	if (level_index <= atomic_read(&g_dbglog_lv_min))
		bDbgLog = true;

	// DW-1961
	if ((atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_OOS) && (level_index == KERN_OOS_NUM))
		bOosLog = true;
	if ((atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) && (level_index == KERN_LATENCY_NUM))
		bLatency = true;
	// DW-2034 if only eventlogs are to be recorded, they are not recorded in the log buffer.
	if (bDbgLog || bOosLog || bLatency) {
		// BSR-578 it should not be produced when it is not consumed thread.
		if (g_consumer_state == RUNNING) {
			logcnt = idx_ring_acquire(&gLogBuf.h, &ad);
			if (gLogBuf.h.r_idx.has_consumer) {
				atomic_set64(&gLogCnt, logcnt);
			}
			else {
				// BSR-578 consumer thread started but actual consumption did not start
				logcnt = atomic_inc_return64(&gLogCnt);
				if (logcnt >= LOGBUF_MAXCNT) {
					atomic_set64(&gLogCnt, 0);
					logcnt = 0;
				}
			}
		}
		else {
			// BSR-578
			logcnt = atomic_inc_return64(&gLogCnt);
			if (logcnt >= LOGBUF_MAXCNT) {
				atomic_set64(&gLogCnt, 0);
				logcnt = 0;
			}
		}
#ifdef _WIN
		totallogcnt = atomic_inc_return64(&gLogBuf.h.total_count);
#else // BSR-577 TODO remove
		totallogcnt = atomic_inc_return64(&gTotalLogCnt);
#endif


#ifdef _WIN
		buf = ((char*)gLogBuf.b + (logcnt * MAX_BSRLOG_BUF));
#else // BSR-577 TODO remove
		buf = gLogBuf_old[logcnt];
#endif

#ifdef _WIN
		RtlZeroMemory(buf, MAX_BSRLOG_BUF);
#else
		memset(buf, 0, MAX_BSRLOG_BUF);
#endif
		//#define TOTALCNT_OFFSET	(9)
		//#define TIME_OFFSET		(TOTALCNT_OFFSET+24)	//"00001234 08/02/2016 13:24:13.123 "
#ifdef _WIN
		KeQuerySystemTime(&systemTime);
	    ExSystemTimeToLocalTime(&systemTime, &localTime);
	    RtlTimeToTimeFields(&localTime, &timeFields);

		offset = _snprintf(buf, MAX_BSRLOG_BUF - 1, "%08lld %02d/%02d/%04d %02d:%02d:%02d.%03d [%s] ",
											totallogcnt,
											timeFields.Month,
											timeFields.Day,
											timeFields.Year,
											timeFields.Hour,
											timeFields.Minute,
											timeFields.Second,
											timeFields.Milliseconds,
											func);
#else // _LIN
		ts = ktime_to_timespec64(ktime_get_real());
		time64_to_tm(ts.tv_sec, (9*60*60), &tm); // TODO timezone

		offset = snprintf(buf, MAX_BSRLOG_BUF - 1, "%08lld %02d/%02d/%04d %02d:%02d:%02d.%03d [%s]",
										totallogcnt,
										tm.tm_mon+1,
										tm.tm_mday,
										(int)tm.tm_year+1900,
										tm.tm_hour,
										tm.tm_min,
										tm.tm_sec,
										(int)(ts.tv_nsec / NSEC_PER_MSEC),
										func);


#endif

#define LEVEL_OFFSET	8
		switch (level_index) {
		case KERN_EMERG_NUM: case KERN_ALERT_NUM: case KERN_CRIT_NUM:
			printLevel = DPFLTR_ERROR_LEVEL; memcpy(buf + offset, "bsr_crit", LEVEL_OFFSET); break;
		case KERN_ERR_NUM:
			printLevel = DPFLTR_ERROR_LEVEL; memcpy(buf + offset, "bsr_erro", LEVEL_OFFSET); break;
		case KERN_WARNING_NUM:
			printLevel = DPFLTR_WARNING_LEVEL; memcpy(buf + offset, "bsr_warn", LEVEL_OFFSET); break;
		case KERN_NOTICE_NUM: case KERN_INFO_NUM:
			printLevel = DPFLTR_INFO_LEVEL; memcpy(buf + offset, "bsr_info", LEVEL_OFFSET); break;
		case KERN_DEBUG_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf + offset, "bsr_trac", LEVEL_OFFSET); break;
		case KERN_OOS_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf + offset, "bsr_oos ", LEVEL_OFFSET); break;
		case KERN_LATENCY_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf + offset, "bsr_late", LEVEL_OFFSET); break;
		default:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf + offset, "bsr_unkn", LEVEL_OFFSET); break;
		}

		va_start(args, format);
#ifdef _WIN
		ret = _vsnprintf(buf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET - 1, format, args); // BSR_DOC: improve vsnprintf 
#else // _LIN
		ret = vsnprintf(buf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET, format, args);
#endif
		va_end(args);
		length = (int)strlen(buf);
		if (length > MAX_BSRLOG_BUF) {
			length = MAX_BSRLOG_BUF - 1;
			buf[MAX_BSRLOG_BUF - 1] = 0;
		}
#ifdef _WIN
		DbgPrintEx(FLTR_COMPONENT, printLevel, buf);
#endif
		// BSE-112 it should not be produced when it is not consumed.
		if (!bEventLog && g_consumer_state == RUNNING)
			idx_ring_commit(&gLogBuf.h, ad);
	}
	
#if defined(_WIN) && defined(_WIN_WPP)
	DoTraceMessage(TRCINFO, "%s", buf);
	WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", buf);
	DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "bsr_info: [%s] %s", func, buf);
#else
	
	if (bEventLog) {
		if (buf) {
			ebuf = buf + offset + LEVEL_OFFSET;
			elength = length - (offset + LEVEL_OFFSET);
			// BSE-578 it should not be produced when it is not consumed.
			if (g_consumer_state == RUNNING)
				idx_ring_commit(&gLogBuf.h, ad);
		}
		else {
			char tbuf[MAX_BSRLOG_BUF] = {0,};

			// DW-2034 log event logs only
			va_start(args, format);
#ifdef _WIN
			ret = _vsnprintf(tbuf, MAX_BSRLOG_BUF - 1, format, args); 
#else
			ret = vsnprintf(tbuf, MAX_BSRLOG_BUF, format, args); 
#endif
			va_end(args);

			length = (int)strlen(tbuf);
			if (length > MAX_BSRLOG_BUF) {
				length = MAX_BSRLOG_BUF - 1;
				tbuf[MAX_BSRLOG_BUF - 1] = 0;
			}

			ebuf = tbuf;
			elength = length;
		}

		// DW-2066 outputs shall be for object information and message only
#ifdef _WIN
		save_to_system_event(ebuf, elength, level_index);
#else
		printk("%s%s", level, ebuf);
#endif
	}
	

#endif
}

