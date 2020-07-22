#include <bsr_int.h>
#include <bsr_log.h>

#ifdef _LIN
#include <linux/stacktrace.h>

#endif

// minimum levels of logging, below indicates default values. it can be changed when BSR receives IOCTL_MVOL_SET_LOGLV_MIN.
atomic_t g_eventlog_lv_min = ATOMIC_INIT(LOG_LV_DEFAULT_EVENTLOG);
atomic_t g_dbglog_lv_min = ATOMIC_INIT(LOG_LV_DEFAULT_DBG);

// BSR-579
atomic_t g_log_file_max_count = ATOMIC_INIT(LOG_FILE_COUNT_DEFAULT);

#ifdef _LIN
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3

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
	// BSR-583
	char* logbuf = NULL;
	int length = 0;
	char *ebuf = NULL;
	int elength = 0;
	LONGLONG logcnt = 0;
#ifdef _WIN
	int level_index = format[1] - '0';
#else
	int level_index = level[1]  - '0';
#endif
	int printLevel = 0;
	bool bEventLog = false;
	bool bDbgLog = false;
	bool bOosLog = false;
	bool bLatency = false;
	// BSR-583
	bool bMissing = false;
	char missingLog[MAX_BSRLOG_BUF];
#ifdef _WIN
	LARGE_INTEGER systemTime, localTime;
	TIME_FIELDS timeFields = {0,};
#else // _LIN
	struct timespec64 ts;
	struct tm tm;
#endif
	LONGLONG	totallogcnt = 0;
	long 		offset = 0;

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
			bool is_acquire = idx_ring_acquire(&gLogBuf.h, &logcnt);
			if (gLogBuf.h.r_idx.has_consumer) {
				if (is_acquire) {
					atomic_set64(&gLogCnt, logcnt);
					// BSR-583 
					if (atomic_read64(&gLogBuf.missing_count)) {
#ifdef _WIN
						RtlZeroMemory(missingLog, MAX_BSRLOG_BUF);
						_snprintf(missingLog, MAX_BSRLOG_BUF - 1, "missing log counter : %llu\n", (unsigned long long)atomic_read64(&gLogBuf.missing_count));
#else
						memset(missingLog, 0, MAX_BSRLOG_BUF);
						snprintf(missingLog, MAX_BSRLOG_BUF - 1, "missing log counter : %llu\n", (unsigned long long)atomic_read64(&gLogBuf.missing_count));
#endif
						level_index = KERN_WARNING_NUM;
						atomic_set64(&gLogBuf.missing_count, 0);
						bMissing = true;
					}
				}
				else {
					// BSR-583 
					atomic_inc_return64(&gLogBuf.missing_count);
					// BSR-583 
					if (bEventLog)
						goto eventlog;
					else
						return;
				}
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

		// BSR-583
		buf = ((char*)gLogBuf.b + (logcnt * (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)));
		totallogcnt = atomic_inc_return64(&gLogBuf.h.total_count);

#ifdef _WIN
		// BSR-583
		RtlZeroMemory(buf, MAX_BSRLOG_BUF + IDX_OPTION_LENGTH);
#else
		memset(buf, 0, MAX_BSRLOG_BUF + IDX_OPTION_LENGTH);
#endif
		// BSR-583
		logbuf = buf + IDX_OPTION_LENGTH;
		//#define TOTALCNT_OFFSET	(9)
		//#define TIME_OFFSET		(TOTALCNT_OFFSET+24)	//"00001234 08/02/2016 13:24:13.123 "
#ifdef _WIN
#if (NTDDI_VERSION < NTDDI_WIN8)
		KeQuerySystemTime(&systemTime);
#else
		// BSR-38 if the current version is equal to or higher than NTDDI_WIN8, call KeQuerySystemTimePrecise().
		KeQuerySystemTimePrecise(&systemTime);
#endif
	    ExSystemTimeToLocalTime(&systemTime, &localTime);
	    RtlTimeToTimeFields(&localTime, &timeFields);

		// BSR-583
		offset = _snprintf(logbuf, MAX_BSRLOG_BUF - 1, "%08lld %02d/%02d/%04d %02d:%02d:%02d.%07d [%s] ",
											totallogcnt,
											timeFields.Month,
											timeFields.Day,
											timeFields.Year,
											timeFields.Hour,
											timeFields.Minute,
											timeFields.Second,
											// BSR-38 mark up to 100 nanoseconds.
											(systemTime.QuadPart % 10000000),
											func);
#else // _LIN
		ts = ktime_to_timespec64(ktime_get_real());
		time64_to_tm(ts.tv_sec, (9*60*60), &tm); // TODO timezone

		offset = snprintf(logbuf, MAX_BSRLOG_BUF - 1, "%08lld %02d/%02d/%04d %02d:%02d:%02d.%07d [%s] ",
										totallogcnt,
										tm.tm_mon+1,
										tm.tm_mday,
										(int)tm.tm_year+1900,
										tm.tm_hour,
										tm.tm_min,
										tm.tm_sec,
										// BSR-38 mark up to 100 nanoseconds.
										(int)(ts.tv_nsec / 100),
										func);


#endif

#define LEVEL_OFFSET	8
		switch (level_index) {
		case KERN_EMERG_NUM: case KERN_ALERT_NUM: case KERN_CRIT_NUM:
			printLevel = DPFLTR_ERROR_LEVEL; memcpy(logbuf + offset, "bsr_crit", LEVEL_OFFSET); break;
		case KERN_ERR_NUM:
			printLevel = DPFLTR_ERROR_LEVEL; memcpy(logbuf + offset, "bsr_erro", LEVEL_OFFSET); break;
		case KERN_WARNING_NUM:
			printLevel = DPFLTR_WARNING_LEVEL; memcpy(logbuf + offset, "bsr_warn", LEVEL_OFFSET); break;
		case KERN_NOTICE_NUM: case KERN_INFO_NUM:
			printLevel = DPFLTR_INFO_LEVEL; memcpy(logbuf + offset, "bsr_info", LEVEL_OFFSET); break;
		case KERN_DEBUG_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(logbuf + offset, "bsr_trac", LEVEL_OFFSET); break;
		case KERN_OOS_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(logbuf + offset, "bsr_oos ", LEVEL_OFFSET); break;
		case KERN_LATENCY_NUM:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(logbuf + offset, "bsr_late", LEVEL_OFFSET); break;
		default:
			printLevel = DPFLTR_TRACE_LEVEL; memcpy(logbuf + offset, "bsr_unkn", LEVEL_OFFSET); break;
		}

		// BSR-583
		if (!bMissing) {
			va_start(args, format);
#ifdef _WIN
			// BSR-583
			ret = _vsnprintf(logbuf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET - 1, format, args); // BSR_DOC: improve vsnprintf 
#else // _LIN
			ret = vsnprintf(logbuf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET, format, args);
#endif
			va_end(args);
		}
		else {
			// BSR-583 missing log count output
#ifdef _WIN
			_snprintf(logbuf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET - 1, "%s", missingLog);
#else // _LIN
			snprintf(logbuf + offset + LEVEL_OFFSET, MAX_BSRLOG_BUF - offset - LEVEL_OFFSET - 1, "%s", missingLog);
#endif
		}

		length = (int)strlen(logbuf);
		if (length > MAX_BSRLOG_BUF) {
			length = MAX_BSRLOG_BUF - 1;
			logbuf[MAX_BSRLOG_BUF - 1] = 0;
		}
#ifdef _WIN
		DbgPrintEx(FLTR_COMPONENT, printLevel, logbuf);
#endif
		// BSE-112 it should not be produced when it is not consumed.
		if (!bEventLog && g_consumer_state == RUNNING)  {
			// BSR-583
			idx_ring_commit(&gLogBuf.h, buf);
		}
	}
	
#if defined(_WIN) && defined(_WIN_WPP)
	DoTraceMessage(TRCINFO, "%s", logbuf);
	WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", logbuf);
	DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "bsr_info: [%s] %s", func, logbuf);
#else

eventlog:
	if (bEventLog) {
		// BSR-583
		if (logbuf) {
			ebuf = logbuf + offset + LEVEL_OFFSET;
			elength = length - (offset + LEVEL_OFFSET);
			// BSE-578 it should not be produced when it is not consumed.
			if (g_consumer_state == RUNNING) {
				// BSR-583
				idx_ring_commit(&gLogBuf.h, buf);
			}
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


#ifdef _DEBUG_OOS
static USHORT getStackFrames(PVOID *frames, USHORT usFrameCount)
{
	USHORT usCaptured = 0;
#ifdef _LIN
	unsigned long entries[usFrameCount];
	struct stack_trace trace = {
		.entries = entries,
		.max_entries = ARRAY_SIZE(entries),
	};
#endif

	if (NULL == frames ||
		0 == usFrameCount)
	{
		bsr_err(NO_OBJECT,"Invalid Parameter, frames(%p), usFrameCount(%d)\n", frames, usFrameCount);
		return 0;
	}
#ifdef _WIN
	usCaptured = RtlCaptureStackBackTrace(2, usFrameCount, frames, NULL);	
	if (0 == usCaptured) {
		bsr_err(NO_OBJECT,"Captured frame count is 0\n");
		return 0;
	}
#else // _LIN
	// BSR-219 oos log linux porting
	trace.nr_entries = 0;
	trace.skip = 1; /* skip the last entries */
	save_stack_trace(&trace);

	for (usCaptured = 0; usCaptured < trace.nr_entries; usCaptured++)
		frames[usCaptured] = (void *)trace.entries[usCaptured];
#endif 
	return usCaptured;	
}

// DW-1153 Write Out-of-sync trace specific log. it includes stack frame.
void WriteOOSTraceLog(int bitmap_index, ULONG_PTR startBit, ULONG_PTR endBit, ULONG_PTR bitsCount, unsigned int mode)
{
	PVOID* stackFrames = NULL;
	USHORT frameCount = STACK_FRAME_CAPTURE_COUNT;
	CHAR buf[MAX_BSRLOG_BUF] = { 0, };
	int i;
	// getting stack frames may overload with frequent bitmap operation, just return if oos trace is disabled.
	if (!(atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_OOS)) {
		return;
	}
#ifdef _WIN
	_snprintf(buf, sizeof(buf) - 1, "%s["OOS_TRACE_STRING"] %s %Iu bits for bitmap_index(%d), pos(%Iu ~ %Iu), sector(%Iu ~ %Iu)", KERN_OOS, mode == SET_IN_SYNC ? "Clear" : "Set", bitsCount, bitmap_index, startBit, endBit, BM_BIT_TO_SECT(startBit), (BM_BIT_TO_SECT(endBit) | 0x7));
	stackFrames = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID) * frameCount, '22DW');

#else // _LIN
	snprintf(buf, sizeof(buf), "%s["OOS_TRACE_STRING"] %s %lu bits for bitmap_index(%d), pos(%lu ~ %lu), sector(%lu ~ %lu)", 
			KERN_OOS, mode == SET_IN_SYNC ? "Clear" : "Set", bitsCount, bitmap_index, startBit, endBit, (size_t)BM_BIT_TO_SECT(startBit), (size_t)(BM_BIT_TO_SECT(endBit) | 0x7));
	stackFrames = (PVOID*)kmalloc(sizeof(PVOID) * frameCount, GFP_ATOMIC|__GFP_NOWARN, '');
#endif

	if (NULL == stackFrames) {
		bsr_err(NO_OBJECT,"Failed to allcate pool for stackFrames\n");
		return;
	}

	frameCount = getStackFrames(stackFrames, frameCount);

	for (i = 0; i < frameCount; i++) {
		CHAR temp[60] = { 0, };
#ifdef _WIN
		_snprintf(temp, sizeof(temp) - 1, FRAME_DELIMITER"%p", stackFrames[i]);
#else
		if (stackFrames[i] == NULL)
			break;
		snprintf(temp, sizeof(temp), FRAME_DELIMITER"%pS", stackFrames[i]);
#endif
		strncat(buf, temp, sizeof(buf) - strlen(buf) - 1);
	}
	
	strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
	
	_printk(__FUNCTION__, KERN_OOS, buf);

	if (NULL != stackFrames) {
#ifdef _WIN
		ExFreePool(stackFrames);
#else // _LIN
		kfree(stackFrames);
#endif
		stackFrames = NULL;
	}
}
#endif