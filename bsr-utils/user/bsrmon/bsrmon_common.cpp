#include "bsrmon.h"


static int decode_timestamp(char timestamp[], struct time_stamp *ts)
{
	timestamp[2] = timestamp[5] = '\0';
	ts->t_sec  = atoi(&timestamp[6]);
	ts->t_min  = atoi(&timestamp[3]);
	ts->t_hour = atoi(timestamp);

	if ((ts->t_sec < 0) || (ts->t_sec > 59) ||
	    (ts->t_min < 0) || (ts->t_min > 59) ||
	    (ts->t_hour < 0) || (ts->t_hour > 23))
		return 1;

	ts->use = true;

	return 0;
}

int parse_timestamp(char *str, struct time_stamp *ts, const char * def_timestamp)
{
	char timestamp[9];
	if (str) {
		switch (strlen(str)) {
			case 5:
				// ex) 00:00
#ifdef _WIN
				strncpy_s(timestamp, str, 5);
#else // _LIN
				strncpy(timestamp, str, 5);
#endif
				timestamp[5] = '\0';
#ifdef _WIN
				strcat_s(timestamp, ":00");
#else // _LIN
				strcat(timestamp, ":00");
#endif
				break;

			case 8:
				// ex) 00:00:00
#ifdef _WIN
				strncpy_s(timestamp, str, 8);
#else // _LIN
				strncpy(timestamp, str, 8);
#endif
				break;

			default:
#ifdef _WIN
				strncpy_s(timestamp, def_timestamp, 8);
#else // _LIN
				strncpy(timestamp, def_timestamp, 8);
#endif
				break;
		}
	} else {
#ifdef _WIN
		strncpy_s(timestamp, def_timestamp, 8);
#else // _LIN
		strncpy(timestamp, def_timestamp, 8);
#endif
	}
	timestamp[8] = '\0';

	return decode_timestamp(timestamp, ts);
}

/*
 * Compare two timestamps.
 *
 * RETURNS:
 * A positive value if @curr is greater than @ts,
 * a negative one otherwise.
 */
int datecmp(char *curr, struct time_stamp *ts)
{
    struct time_stamp curr_ts;
	char timestamp[9];

#ifdef _WIN
	strncpy_s(timestamp, curr, 8);
#else // _LIN
	strncpy(timestamp, curr, 8);
#endif
    decode_timestamp(timestamp, &curr_ts);

	if (curr_ts.t_hour == ts->t_hour) {
		if (curr_ts.t_min == ts->t_min)
			return (curr_ts.t_sec - ts->t_sec);
		else
			return (curr_ts.t_min - ts->t_min);
	}
	else
		return (curr_ts.t_hour - ts->t_hour);
}