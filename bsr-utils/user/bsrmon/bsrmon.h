#ifdef _WIN
#include <windows.h>
#include "bsr_ioctl.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_BUF_SIZE 4096

#ifdef _WIN
#define _SEPARATOR_ "\\"
#else // _LIN
#define _SEPARATOR_ "/"
#endif


#ifdef _LIN
#define PERIOD_OPTION_PATH "/etc/bsr.d/.bsrmon_period"
#define FILE_SIZE_OPTION_PATH "/etc/bsr.d/.bsrmon_file_size"
#define FILE_CNT_OPTION_PATH "/etc/bsr.d/.bsrmon_file_cnt"
#endif

#ifdef _WIN
#define popen _popen
#define pclose _pclose
#define fscanf_str fscanf_s
#define fscanf_ex fscanf_s
#define sprintf_ex sprintf_s
#define strtok_r strtok_s
#else // _LIN
#ifndef ULONG_PTR
#define ULONG_PTR unsigned long
#endif
#define fopen_s(pFile, filename, mode) ((*pFile=fopen(filename, mode)) == NULL)
#define sprintf_ex sprintf
#define fscanf_str(fp, format, buf, size) fscanf(fp, format, buf)
#define fscanf_ex fscanf
#endif

static inline void clear_screen()
{
#ifdef _WIN
	system("cls");
#else // _LIN
	system("clear");
#endif
}