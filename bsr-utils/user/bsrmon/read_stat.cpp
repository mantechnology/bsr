#include "bsrmon.h"
#include "read_stat.h"
#include "module_debug.h"
#ifdef _WIN
#include <share.h>
#else //_LIN
#include <unistd.h>
#endif


// BSR-948
char g_timestamp[64];
int indent = 0;
bool json = false;
#define INDENT_WIDTH	4
#ifdef _WIN
#define printI(fmt, ...) printf("%*s" fmt,INDENT_WIDTH * indent,"", __VA_ARGS__)
#else
#define printI(fmt, args...) printf("%*s" fmt,INDENT_WIDTH * indent,"", ## args )
#endif


#define BYTE_TO_KBYTE(x) x >> 10
#define STRING_TO_KBYTE(x) BYTE_TO_KBYTE(atoll(x))

static int collection_time(FILE *fp, char *d)
{
	char format[10] = { 0, };

#ifdef _WIN
	sprintf_s(format, sizeof(format), "%%%ds", COLLECTION_TIME_LENGTH);
#else
	sprintf(format, "%%%ds", COLLECTION_TIME_LENGTH);
#endif
	return fscanf_str(fp, format, d);
}

// BSR-1047 fix bsrmon /show parsing error when using ipv6 address
char * get_ipv6_name(char **save_ptr) 
{
	char * ptr = NULL;
	char ipv6_name[CONNECTION_NAME_MAX] = {0,};
	ptr = strtok_r(NULL, " ", save_ptr);
	if (ptr == NULL)
		return NULL;
	sprintf_ex(ipv6_name, "ipv6 %s", ptr);
#ifdef _WIN
	return _strdup(ipv6_name);
#else
	return strdup(ipv6_name);
#endif
}

// BSR-1032 check ipv6 floating peer
bool is_ipv6(char * token)
{
	return strcmp(token, "ipv6") == 0;
}

// BSR-1032 get peer name (exclude ipv6)
char * get_peer_name(char * name)
{
	char *p_name = strrchr(name, ' ');
	if (!p_name)
		p_name = name;
	else
		p_name++; // skip ipv6
	return p_name;
}

// BSR-772
static FILE* open_shared(char *filename)
{
	FILE * fp;

#ifdef _WIN
	// Opens a stream with file sharing
	fp = _fsopen(filename, "r", _SH_DENYNO);
#else // _LIN
	fp = fopen(filename, "r");
#endif

	return fp;
}

unsigned long long stat_avg(unsigned long long sum, unsigned long cnt)
{
	if (cnt) {
		// div round
		return 1 + ((sum -1) / cnt);
	}
	return sum;
}


void set_min_max_val(perf_stat *stat, unsigned long long val)
{
	/* Excluded from statistics if:
		1. Current value is 0
		2. Consecutive duplicate values
	*/
	if (val == 0 || (stat->priv == val && stat->duplicate))
		return;

	if (!stat->max){
		stat->max = stat->min = val;
	} else if (stat->max < val) 
		stat->max = val;
	else if (stat->min > val)
		stat->min = val;

	if (stat->priv == val)
		stat->duplicate = true;
	else 
		stat->duplicate = false;

	stat->priv = val;
	// prevent overflow
	if (stat->sum + val < stat->sum) {
		stat->sum = stat->sum / stat->cnt;
		stat->cnt = 0;
	}
	stat->sum += val;
	stat->cnt++;
	stat->samples++;
}

// TODO
void set_min_max_avg(unsigned long t_min, unsigned long t_max, unsigned long t_avg, perf_stat *stat)
{
	/* Excluded from statistics if:
		1. Current value is 0
		2. Consecutive duplicate values
	*/
	if (t_avg == 0 || (stat->priv == t_avg && stat->duplicate))
		return;
	if (t_max > 0) {
		if (!stat->max)
			stat->max = t_max;
		else if (stat->max < t_max) 
			stat->max = t_max;
		
		if (!stat->min)
			stat->min = t_min;
		else if (stat->min > t_min)
			stat->min = t_min;
	}
	
	if (stat->priv == t_avg)
		stat->duplicate = true;
	else 
		stat->duplicate = false;

	stat->priv = t_avg;
	// prevent overflow
	if (stat->sum + t_avg < stat->sum) {
		stat->sum = stat->sum / stat->cnt;
		stat->cnt = 0;
	}
	stat->sum += t_avg;
	stat->cnt++;
	stat->samples++;
}

void set_min_max_fp(FILE *fp, perf_stat *stat)
{
	unsigned long t_min = 0, t_max = 0, t_avg = 0;
	fscanf_ex(fp, "%lu %lu %lu", &t_min, &t_max, &t_avg);

	set_min_max_avg(t_min, t_max, t_avg, stat);	
}

bool set_min_max_ptr(char ** save_ptr, perf_stat *stat)
{
	char *min_ptr, *max_ptr, *avg_ptr;

	min_ptr = strtok_r(NULL, " ", save_ptr);
	if (!min_ptr)
		return false;
	max_ptr = strtok_r(NULL, " ", save_ptr);
	if (!max_ptr)
		return false;
	avg_ptr = strtok_r(NULL, " ", save_ptr);
	if (!avg_ptr)
		return false;

	set_min_max_avg(atol(min_ptr), atol(max_ptr), atol(avg_ptr), stat);
	return true;
}

unsigned int read_val_fp(FILE *fp)
{
	unsigned int val = 0, r = 0;
	r = fscanf_ex(fp, "%u", &val);
	if (r != 1)
		return 0;
	else
		return val;
}

void print_stat(const char * name, perf_stat *s)
{
	printf("%s: min=%llu, max=%llu, avg=%llu, samples=%lu\n", 
			name, s->min, s->max, stat_avg(s->sum, s->cnt), s->samples);
}

void print_range(const char * name, struct perf_stat *s, const char * ws)
{
	if ((s->min == s->max) || s->max == 0)
		printf("%s%-23llu%s", name, s->min, ws);
	else {
		char temp[32] = {0,};

		sprintf_ex(temp, "%llu - %llu", s->min, s->max);
		printf("%s%-23s%s", name, temp, ws);
	}
}

void print_umem(const char * name, struct umem_perf_stat *s)
{
	printf("  %-13s ", name);
#ifdef _WIN
	print_range("", &s->wss, " ");
	print_range("", &s->qpp, " ");
	print_range("", &s->qnpp, " ");
	print_range("", &s->pfu, " ");
	printf("\n");
#else // _LIN
	print_range("", &s->rsz, " ");
	print_range("", &s->vsz, " ");
	printf("\n");
#endif

}


/*
 * BSR-771
 *
 * Compare the save timestamp with the filter timestamp.
 * Returns 0 if the save time is earlier or later than the filter time.
 */
static int check_record_time(char * save_t, struct time_filter *tf)
{
	/* compare yyyy-mm-dd*/
	if (tf->start_date && (strncmp(save_t, tf->start_date, strlen(tf->start_date)) < 0))
		return 0;

	if (tf->end_date && (strncmp(save_t, tf->end_date, strlen(tf->end_date)) > 0))
		return 0;

	/* compare hh:mm:ss (escape yyyy-mm-dd_) */
	if (!tf->start_date && !tf->end_date) {
		if ((tf->start_time.use && (datecmp(&save_t[11], &tf->start_time) < 0)) ||
			(tf->end_time.use && (datecmp(&save_t[11], &tf->end_time) > 0))) {
			return 0;
		}
	} 
	else {
		// BSR-940
		/* compare hh:mm:ss (include yyyy-mm-dd) */
		if (tf->start_time.use) {
			if (!tf->start_date || (strncmp(save_t, tf->start_date, strlen(tf->start_date)) == 0))
				if (datecmp(&save_t[11], &tf->start_time) < 0)
					return 0;
		}

		if (tf->end_time.use) {
			if (!tf->end_date || (strncmp(save_t, tf->end_date, strlen(tf->end_date)) == 0))
				if (datecmp(&save_t[11], &tf->end_time) > 0)
					return 0;
		}	
	}
	
	return 1;

}


/**
 * Reports statistics of io performance.
 */
void read_io_stat_work(std::set<std::string> filelist, struct time_filter *tf)
{
	FILE *fp;
	char line[256] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,};
	struct {
		unsigned long iops;
		unsigned long ios;
		unsigned long kbs;
		unsigned long kb;
	} r, w;

	struct io_perf_stat read_io, write_io;
	unsigned int i = 0, iter_index = 0;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];

	std::set<std::string>::iterator iter;

	memset(&read_io, 0, sizeof(struct io_perf_stat));
	memset(&write_io, 0, sizeof(struct io_perf_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);


	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}

				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					if (!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

					if (fgets(line, sizeof(line), fp) != NULL) {
						memset(&r, 0, sizeof(r));
						memset(&w, 0, sizeof(w));
						/* riops rios rkbs rkb wiops wios rkbs rkb */
#ifdef _WIN
						i = sscanf_s(line, "%lu %lu %lu %lu %lu %lu %lu %lu",
							&r.iops, &r.ios, &r.kbs, &r.kb, &w.iops, &w.ios, &w.kbs, &w.kb);
#else // _LIN
						i = sscanf(line, "%lu %lu %lu %lu %lu %lu %lu %lu",
							&r.iops, &r.ios, &r.kbs, &r.kb, &w.iops, &w.ios, &w.kbs, &w.kb);
#endif
						if (i != 8) {
							printf(" i!=8\n");
							continue;
						}
						set_min_max_val(&read_io.iops, r.iops);
						read_io.ios += r.ios;
						set_min_max_val(&read_io.kbs, r.kbs);
						read_io.kb += r.kb;
						set_min_max_val(&write_io.iops, w.iops);
						write_io.ios += w.ios;
						set_min_max_val(&write_io.kbs, w.kbs);
						write_io.kb += w.kb;
						sprintf_ex(filter_e, "%s", save_t);

					}
					continue;
				}
				else {
					if (start_collect)
						end_collect = true;
					fscanf_ex(fp, "%*[^\n]");
				}
			}

		
			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}


		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			printf("  read : io count=%llu, bw=%llukbyte\n", read_io.ios, read_io.kb);
			//print_stat("    IOPS        ", &read_io.iops);
			print_stat("    BW (kbyte/s)", &read_io.kbs);
			printf("  write: io count=%llu, bw=%llukbyte\n", write_io.ios, write_io.kb);
			//print_stat("    IOPS        ", &write_io.iops);
			print_stat("    BW (kbyte/s)", &write_io.kbs);


			memset(&read_io, 0, sizeof(read_io));
			memset(&write_io, 0, sizeof(write_io));
			memset(&filter_s, 0, sizeof(filter_s));
			memset(&filter_e, 0, sizeof(filter_e));
			do_print = false;
			find_date = true;
			goto read_continue;
		}

		fclose(fp);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

/**
 * Reports statistics of io_complete_latency
 */
void read_io_complete_work(std::set<std::string> filelist, struct time_filter *tf)
{
	FILE *fp;
	char line[256] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,};
	int val[8] = {0};
	struct perf_stat local, master;
	unsigned long long total_l_cnt = 0, total_m_cnt= 0;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];
	unsigned int i = 0, iter_index = 0;
	std::set<std::string>::iterator iter;

	memset(&local, 0, sizeof(struct perf_stat));
	memset(&master, 0, sizeof(struct perf_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();


		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

					if (fgets(line, sizeof(line), fp) != NULL) {
						memset(val, 0, sizeof(int) * 8);

						/* local_cnt local_min local_max local_avg master_cnt master_min master_max master_avg*/
#ifdef _WIN
						i = sscanf_s(line, "%lu %lu %lu %lu %lu %lu %lu %lu",
							&val[0], &val[1], &val[2], &val[3], &val[4], &val[5], &val[6], &val[7]);
#else // _LIN
						i = sscanf(line, "%lu %lu %lu %lu %lu %lu %lu %lu",
						 	&val[0], &val[1], &val[2], &val[3], &val[4], &val[5], &val[6], &val[7]);
#endif
						

						if (i < 6)
							continue;

						if (i == 8) {
							// BSR-1072
							total_l_cnt += val[0];
							set_min_max_avg(val[1], val[2], val[3], &local);
							total_m_cnt += val[4];
							set_min_max_avg(val[5], val[6], val[7], &master);
						} else {
							set_min_max_avg(val[0], val[1], val[2], &local);
							set_min_max_avg(val[3], val[4], val[5], &master);
						}			
						sprintf_ex(filter_e, "%s", save_t);

					}
					continue;

				}
				else {
					if (start_collect)
						end_collect = true;
				}
				fscanf_ex(fp, "%*[^\n]");
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}		
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			print_stat("  local clat  (usec)", &local);
			print_stat("  master clat (usec)", &master);

			memset(&local, 0, sizeof(struct perf_stat));
			memset(&master, 0, sizeof(struct perf_stat));
			memset(&filter_s, 0, sizeof(filter_s));
			memset(&filter_e, 0, sizeof(filter_e));
			do_print = false;
			find_date = true;
			goto read_continue;
		}

		fclose(fp);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}


static void set_max_fp(FILE *fp, unsigned int *stat)
{
	unsigned int val = 0, r = 0;
	r = fscanf_ex(fp, "%u", &val);
	if (r == 1 && val > 0) {
		if (*stat < val)
			*stat = val;
	}
}

// BSR-1054 reports statistics of io_pending
void read_io_pending_work(std::set<std::string> filelist, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,};
	struct io_pending_stat io;
	unsigned long long pending_latency = 0;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];
	unsigned int iter_index;
	std::set<std::string>::iterator iter;

	memset(&io, 0, sizeof(struct io_pending_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();


		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}
					
					// upper_pending pending_latency lower_pending al_suspended al_pending_changes al_wait_req upper_blocked suspended suspend_cnt unstable pending_bitmap_work
					set_max_fp(fp, &io.upper_pending);
					fscanf_ex(fp, "%lld", &pending_latency);
					set_min_max_val(&io.pending_latency, pending_latency);
					set_max_fp(fp, &io.lower_pending);
					io.al_suspended += read_val_fp(fp);
					set_max_fp(fp, &io.al_pending_changes);
					set_max_fp(fp, &io.al_wait_req);
					io.upper_blocked += read_val_fp(fp);
					io.suspended += read_val_fp(fp);
					io.suspend_cnt += read_val_fp(fp);
					io.unstable += read_val_fp(fp);
					io.pending_bitmap_work += read_val_fp(fp);

					sprintf_ex(filter_e, "%s", save_t);

					fscanf_ex(fp, "%*[^\n]");
					continue;

				}
				else {
					if (start_collect)
						end_collect = true;
				}
				fscanf_ex(fp, "%*[^\n]");
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}		
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			// upper_pending pending_latency lower_pending al_suspended al_pending_changes al_wait_req upper_blocked suspended suspend_cnt unstable pending_bitmap_work
			printf("  upper_pending     : max=%u\n", io.upper_pending);
			printf("    pending_latency (usec): min=%llu, max=%llu, avg=%llu, samples=%lu\n", 
						io.pending_latency.min, io.pending_latency.max, 
						stat_avg(io.pending_latency.sum, io.pending_latency.cnt), io.pending_latency.samples);
			printf("  lower_pending     : max=%u\n", io.lower_pending);
			printf("  al_suspended      : total=%llu\n", io.al_suspended);
			printf("  al_pending_changes: max=%u\n", io.al_pending_changes);
			printf("  al_wait_req       : max=%u\n", io.al_wait_req);
			printf("  upper_blocked     : total=%llu\n", io.upper_blocked);
			printf("    suspended          : total=%llu\n", io.suspended);
			printf("    suspend_cnt        : total=%llu\n", io.suspend_cnt);
			printf("    unstable           : total=%llu\n", io.unstable);
			printf("    pending_bitmap_work: total=%llu\n", io.pending_bitmap_work);

			memset(&io, 0, sizeof(struct io_pending_stat));
			memset(&filter_s, 0, sizeof(filter_s));
			memset(&filter_e, 0, sizeof(filter_e));
			do_print = false;
			find_date = true;
			goto read_continue;
		}

		fclose(fp);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

static void read_peer_ack_stat(FILE *fp, struct peer_stat * peer_head)
{
	char buf[MAX_BUF_SIZE] = {0,};
	char * ptr = NULL, *save_ptr = NULL;

	/* peer_name */
	if (fgets(buf, MAX_BUF_SIZE, fp) != NULL) {
		struct peer_stat *peer;

		// remove EOL
		*(buf + (strlen(buf) - 1)) = 0;

		ptr = strtok_r(buf, " ", &save_ptr);

		while (ptr) {	
			bool is_peer = false;
			struct peer_ack_stat * peer_ack = NULL;
			peer = peer_head;

			// BSR-1032
			if (is_ipv6(ptr))
				ptr = strtok_r(NULL, " ", &save_ptr);

			while (peer) {
				// BSR-1032
				if (strcmp(ptr, get_peer_name(peer->name)) == 0) {
					peer->exist = 1;
					is_peer = true;
					break;
				}
				peer = peer->next;
			}

			if (!is_peer) {
				ptr = strtok_r(NULL, " ", &save_ptr);
				continue;
			}
			
			peer_ack = (struct peer_ack_stat *)peer->data;
		
			if (!set_min_max_ptr(&save_ptr, &peer_ack->pre_send))
				break;
			if (!set_min_max_ptr(&save_ptr, &peer_ack->acked))
				break;
			if (!set_min_max_ptr(&save_ptr, &peer_ack->net_done))
				break;

			ptr = strtok_r(NULL, " ", &save_ptr);
		}
	}
}

static struct peer_stat *get_peer_list(char * resname)
{
	FILE *pipe;
	struct peer_stat *peer_cur, *peer_head, *peer_end;
	char cmd[128] = {0,};	
	char peer_name[64] = {0,};

	peer_head = peer_end = NULL;

	sprintf_ex(cmd, "bsradm sh-peer-node-name %s", resname);
	if ((pipe = popen(cmd, "r")) != NULL) {
		while (fgets(peer_name, 64, pipe) != NULL) {
			*(peer_name + (strlen(peer_name) - 1)) = 0;

			peer_cur = (struct peer_stat *)malloc(sizeof(struct peer_stat));
			if (!peer_cur) {
				fprintf(stderr, "Failed to malloc peer_stat, size : %lu\n", sizeof(struct peer_stat));
				return NULL;
			}
			memset(peer_cur, 0, sizeof(struct peer_stat));
#ifdef _WIN
			strcpy_s(peer_cur->name, peer_name);
#else // _LIN
			strcpy(peer_cur->name, peer_name);
#endif		
			peer_cur->next = NULL;
			if (peer_head == NULL) {
				peer_head = peer_end = peer_cur;
			}
			else {
				peer_end->next = peer_cur;
				peer_end = peer_cur;
			}
		}
		pclose(pipe);
	}
	return peer_head;
}

/**
 * Reports statistics of request performance.
 */
void read_req_stat_work(std::set<std::string> filelist, char *resname, struct peer_stat *peer, struct time_filter *tf)
{
	FILE *fp;
	
	char tok[64] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	unsigned int t_cnt = 0;
	unsigned long long req_total = 0, al_total= 0;
	struct req_perf_stat req_stat;	
	// struct peer_ack_stat *peer_head;
	struct peer_stat *peer_head;
	
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 

	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	memset(&req_stat, 0, sizeof(struct req_perf_stat));

	/* peer list */
	if (!peer)
		peer = get_peer_list(resname);
	peer_head = peer;

	
	while (peer) {
		peer->data = (struct peer_ack_stat *)malloc(sizeof(struct peer_ack_stat));
		memset(peer->data, 0, sizeof(struct peer_ack_stat));
		peer->exist = 0;
		peer = peer->next;
	}

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:

		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);
				if (check_record_time(save_t, tf)) {
					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

					sprintf_ex(filter_e, "%s", save_t);

					/* req cnt */
					fscanf_str(fp, "%s", tok);
					fscanf_ex(fp, "%u", &t_cnt);

					if (tok != NULL && strlen(tok) !=0 && 
						strcmp(tok, "req")) {
						fscanf_ex(fp, "%*[^\n]");
						continue;
					}
									
					req_total += t_cnt;
					set_min_max_fp(fp, &req_stat.before_queue);
					set_min_max_fp(fp, &req_stat.before_al_begin);
					set_min_max_fp(fp, &req_stat.in_actlog);
					set_min_max_fp(fp, &req_stat.submit);
					set_min_max_fp(fp, &req_stat.bio_endio);
					set_min_max_fp(fp, &req_stat.destroy);
					

					/* al_update cnt*/
					fscanf_str(fp, "%s", tok);
					fscanf_ex(fp, "%u", &t_cnt);
					

					if (tok != NULL && strlen(tok) !=0 && strcmp(tok, "al")) {
						fscanf_ex(fp, "%*[^\n]");
						continue;
					}
					
					al_total += t_cnt;
					set_min_max_fp(fp, &req_stat.before_bm_write);
					set_min_max_fp(fp, &req_stat.after_bm_write);
					set_min_max_fp(fp, &req_stat.after_sync_page);

					read_peer_ack_stat(fp, peer_head);
					
					continue;
				}
				else {
					if (start_collect)
						end_collect = true;
				}

				fscanf_ex(fp, "%*[^\n]");	
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			printf("  requests  : total=%llu\n", req_total);
			print_stat("    before_queue    (usec)", &req_stat.before_queue);
			print_stat("    before_al_begin (usec)", &req_stat.before_al_begin);
			print_stat("    in_actlog       (usec)", &req_stat.in_actlog);
			print_stat("    submit          (usec)", &req_stat.submit);
			print_stat("    bio_endio       (usec)", &req_stat.bio_endio);
			print_stat("    destroy         (usec)", &req_stat.destroy);
			printf("  al_update : total=%llu\n", al_total);
			print_stat("    before_bm_write (usec)", &req_stat.before_bm_write);
			print_stat("    after_bm_write  (usec)", &req_stat.after_bm_write);
			print_stat("    after_sync_page (usec)", &req_stat.after_sync_page);
						
			peer = peer_head;
			while (peer) {
				struct peer_ack_stat * peer_ack = (struct peer_ack_stat *)peer->data;
				printf("  PEER %s:\n", peer->name);
				if (peer->exist) {
					print_stat("    pre_send (usec)", &peer_ack->pre_send);
					print_stat("    acked    (usec)", &peer_ack->acked);
					print_stat("    net_done (usec)", &peer_ack->net_done);
					memset(peer->data, 0, sizeof(struct peer_ack_stat));
					peer->exist = 0;
				} 
				else {
					printf("    not found\n");
				}
				
				peer = peer->next;
			}
			memset(&req_stat, 0, sizeof(struct req_perf_stat));
			peer = peer_head;

			do_print = false;
			find_date = true;

			goto read_continue;
		}
		
		fclose(fp);
	}

	while (peer) {
		peer_head = peer;
		peer = peer->next;
		free(peer_head->data);
		free(peer_head);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}


void read_peer_req_stat_work(std::set<std::string> filelist, char *resname, struct peer_stat *peer, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct peer_stat *peer_head;
	
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 

	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	if (!peer)
		peer = get_peer_list(resname);
	peer_head = peer;

	while (peer) {
		peer->data = (struct peer_req_stat *)malloc(sizeof(struct peer_req_stat));
		memset(peer->data, 0, sizeof(struct peer_req_stat));
		peer->exist = 0;
		peer = peer->next;
	}

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);
				if (check_record_time(save_t, tf)) {
					char buf[MAX_BUF_SIZE] = {0,};
					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

					sprintf_ex(filter_e, "%s", save_t);
					
					if(fgets(buf, MAX_BUF_SIZE, fp) != NULL) {
						char *ptr, *save_ptr;
						struct peer_req_stat * peer_req = NULL;

						// remove EOL
						*(buf + (strlen(buf) - 1)) = 0;

						/* peer_name */
						ptr = strtok_r(buf, " ", &save_ptr);
						while (ptr) {
							bool is_peer = false;
							peer = peer_head;
							// BSR-1032
							if (is_ipv6(ptr))
								ptr = strtok_r(NULL, " ", &save_ptr);

							while (peer) {
								// BSR-1032
								if (strcmp(ptr, get_peer_name(peer->name)) == 0) {
									is_peer = true;
									peer->exist = 1;
									break;
								}
								peer = peer->next;
							}

							if (!is_peer) {
								ptr = strtok_r(NULL, " ", &save_ptr);
								continue;
							}
							
							peer_req = (struct peer_req_stat *)peer->data;

							/* peer request cnt */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							peer_req->req_cnt += atoi(ptr);
							if (!set_min_max_ptr(&save_ptr, &peer_req->submit))
								break;
							if (!set_min_max_ptr(&save_ptr, &peer_req->bio_endio))
								break;
							if (!set_min_max_ptr(&save_ptr, &peer_req->destroy))
								break;

							ptr = strtok_r(NULL, " ", &save_ptr);
						}

					}
					continue;
				}
				else {
					if (start_collect)
						end_collect = true;
				}

				fscanf_ex(fp, "%*[^\n]");	
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			peer = peer_head;
			while (peer) {
				struct peer_req_stat * peer_req = (struct peer_req_stat *)peer->data;
				printf("  PEER %s:\n", peer->name);
				if (peer->exist) {
					printf("    peer requests : total=%llu\n", peer_req->req_cnt);
					print_stat("    submit    (usec)", &peer_req->submit);
					print_stat("    bio_endio (usec)", &peer_req->bio_endio);
					print_stat("    destroy   (usec)", &peer_req->destroy);
					memset(peer->data, 0, sizeof(struct peer_req_stat));
					peer->exist = 0;
				} 
				else {
					printf("    not found\n");
				}
				
				peer = peer->next;
			}

			do_print = false;
			find_date = true;

			goto read_continue;
		}
		
		fclose(fp);
	}

	while (peer) {
		peer_head = peer;
		peer = peer->next;
		free(peer_head->data);
		free(peer_head);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);	
}

// BSR-765 add al stat reporting
void read_al_stat_work(std::set<std::string> filelist, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = { 0, }, start_t[64] = { 0, }, end_t[64] = { 0, };
	unsigned int t_cnt = 0, t_max = 0, t_total = 0, nr_elements = 0;;
	unsigned int all_slot_used_cnt = 0;
	struct al_stat al;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];
	bool change_nr = false, print_new_nr = false;
	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	memset(&al, 0, sizeof(struct al_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (change_nr || (EOF != collection_time(fp, save_t))) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					if(!start_collect) {
						start_collect = true;
						if (!print_new_nr)
							sprintf_ex(filter_s, "%s", save_t);
					}
					sprintf_ex(filter_e, "%s", save_t);

					/* nr_elements */
					if (!change_nr)
						fscanf_ex(fp, "%u", &nr_elements);
					if (al.nr_elements && (nr_elements != al.nr_elements)) {
						// changed nr_elements, print stat and reset
						do_print = true;
						change_nr = true;
						break;
					} 
					else {
						al.nr_elements = nr_elements;
						/* used used_max */
						fscanf_ex(fp, "%u %u", &t_cnt, &t_max);
						if (t_cnt > 0) {
							al.used.sum += t_cnt;
							al.used.cnt++;
						} 
						
						if (al.used.max < t_max)
							al.used.max = t_max;

						if (al.nr_elements == t_max)
							all_slot_used_cnt++;

						/* hits_cnt hits misses_cnt misses starving_cnt starving locked_cnt locked changed_cnt changed */
						al.hits += read_val_fp(fp);
						read_val_fp(fp);
						al.misses += read_val_fp(fp);
						read_val_fp(fp);
						al.starving += read_val_fp(fp);
						read_val_fp(fp);
						al.locked += read_val_fp(fp);
						read_val_fp(fp);
						al.changed += read_val_fp(fp);
						read_val_fp(fp);

						/* al_wait_retry_cnt al_wait_retry_total al_wait_retry_max*/
						fscanf_ex(fp, "%u %u %u", &t_cnt, &t_total, &t_max);
						if (t_total > 0) {
							al.wait.sum += t_total;
							if (al.wait.max < t_max)
								al.wait.max = t_max;
						}

						/* pending_changes max_pending_changes */
						fscanf_ex(fp, "%u %u", &t_cnt, &t_max);
						if (t_cnt > 0) {
							al.pending.sum += t_cnt;
							al.pending.cnt++;
							if (al.pending.max < t_max)
								al.pending.max = t_max;
						} 

						/* e_al_starving e_al_pending e_al_used e_al_busy e_al_wouldblock */
						al.e_starving += read_val_fp(fp);
						al.e_pending += read_val_fp(fp);
						al.e_used += read_val_fp(fp);
						al.e_busy += read_val_fp(fp);
						al.e_wouldblock += read_val_fp(fp);

						fscanf_ex(fp, "%*[^\n]");
						continue;
					}
					
				}
				else {
					if (start_collect)
						end_collect = true;
				}
				fscanf_ex(fp, "%*[^\n]");
			} 

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}			
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			if (print_new_nr) {
				printf(" -> al_extents changed \n");
				print_new_nr = false;
			}
			printf(" Run: %s - %s\n", filter_s, filter_e);
			printf("  al_extents : %u\n", al.nr_elements);
			printf("    used     : max=%lu(all_slot_used=%u), avg=%llu\n", 
						al.used.max, all_slot_used_cnt, al.used.sum ? al.used.sum / al.used.cnt : 0);
			printf("    hits     : total=%llu\n", al.hits);
			printf("    misses   : total=%llu\n", al.misses);
			printf("    starving : total=%llu\n", al.starving);
			printf("    locked   : total=%llu\n", al.locked);
			printf("    changed  : total=%llu\n", al.changed);
			printf("    al_wait retry count : max=%lu, total=%llu\n", al.wait.max, al.wait.sum);
			printf("    pending_changes     : max=%lu, total=%llu\n", al.pending.max, al.pending.sum);
			printf("    error : total=%u\n", 
							al.e_starving + al.e_pending + al.e_used + al.e_busy + al.e_wouldblock);
			printf("      NOBUFS - starving     : total=%u\n", al.e_starving);
			printf("             - pending slot : total=%u\n", al.e_pending);
			printf("             - used    slot : total=%u\n", al.e_used);
			printf("      BUSY       : total=%u\n", al.e_busy);
			printf("      WOULDBLOCK : total=%u\n", al.e_wouldblock);

			
			
			memset(&al, 0, sizeof(struct al_stat));
			all_slot_used_cnt = 0;

			if (change_nr) {
				al.nr_elements = nr_elements;
				print_new_nr = true;
				change_nr = false;	
				sprintf_ex(filter_s, "%s", save_t);
			}	

			do_print = false;
			find_date = true;

			goto read_continue;
		}

		fclose(fp);
	}


	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);

}


// BSR-838
void read_resync_ratio_work(std::set<std::string> filelist, char *resname, struct peer_stat *peer, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct peer_stat *peer_head;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 

	struct resync_ratio_stat {
		struct perf_stat repl_sended;
		struct perf_stat resync_sended;
		struct perf_stat resync_ratio;
	};

	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	if (!peer)
		peer = get_peer_list(resname);
	peer_head = peer;

	while (peer) {
		peer->data = (struct resync_ratio_stat *)malloc(sizeof(struct resync_ratio_stat));
		memset(peer->data, 0, sizeof(struct resync_ratio_stat));
		peer->exist = 0;
		peer = peer->next;
	}

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}

				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					char buf[MAX_BUF_SIZE];

					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}
					
					sprintf_ex(filter_e, "%s", save_t);

					if (fgets(buf, sizeof(buf), fp) != NULL) {
						char *ptr, *save_ptr;
						struct resync_ratio_stat * resync_stat = NULL;
						
						// remove EOL
						*(buf + (strlen(buf) - 1)) = 0;

						/* peer name */
						ptr = strtok_r(buf, " ", &save_ptr);
						while (ptr) {					
							bool is_peer = false;
							peer = peer_head;
							// BSR-1032
							if (is_ipv6(ptr))
								ptr = strtok_r(NULL, " ", &save_ptr);

							while (peer) {
								// BSR-1032
								if (strcmp(ptr, get_peer_name(peer->name)) == 0) {
									is_peer = true;
									peer->exist = 1;
									break;
								}
								peer = peer->next;
							}

							

							if (!is_peer) {
								ptr = strtok_r(NULL, " ", &save_ptr);
								continue;
							}

							resync_stat = (struct resync_ratio_stat *)peer->data;
							
							/* replication sended, resync sended, ratio */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&resync_stat->repl_sended, atoll(ptr));
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&resync_stat->resync_sended, atoll(ptr));
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&resync_stat->resync_ratio, atoll(ptr));

							ptr = strtok_r(NULL, " ", &save_ptr);
						}
					}

					continue;
				}
				else {
					if (start_collect)
						end_collect = true;
				}

				fscanf_ex(fp, "%*[^\n]");
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			peer = peer_head;
			while (peer) {
				struct resync_ratio_stat * resync_stat = (struct resync_ratio_stat *)peer->data;
				if (peer->exist) {
					printf("  PEER %s: replication sended=%llubyte/s, resync sended=%llubyte/s, resync ratio=%llu\n", 
						peer->name, 
						stat_avg(resync_stat->repl_sended.sum, resync_stat->repl_sended.cnt), 
						stat_avg(resync_stat->resync_sended.sum, resync_stat->resync_sended.cnt), 
						stat_avg(resync_stat->resync_ratio.sum, resync_stat->resync_ratio.cnt));
					print_stat("    repl_sended   (byte/s)", &resync_stat->repl_sended);
					print_stat("    resync_sended (byte/s)", &resync_stat->resync_sended);
					print_stat("    resync_ratio  (byte/s)", &resync_stat->resync_ratio);
					memset(peer->data, 0, sizeof(struct resync_ratio_stat));
					peer->exist = 0;
				} 
				else {
					printf("  PEER %s: \n", peer->name);
					printf("    not found\n");
				}
				peer = peer->next;
			}
			do_print = false;
			find_date = true;

			goto read_continue;
		}

		fclose(fp);
	}

	while (peer) {
		peer_head = peer;
		peer = peer->next;
		free(peer_head->data);
		free(peer_head);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);	
}

/**
 * Reports statistics of network performance.
 */
void read_network_stat_work(std::set<std::string> filelist, char *resname, struct peer_stat *peer, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct peer_stat *peer_head;
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 
	struct network_stat {
		struct perf_stat send;
		struct perf_stat recv;
	};	
	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	if (!peer)
		peer = get_peer_list(resname);
	peer_head = peer;

	while (peer) {
		peer->data = (struct network_stat *)malloc(sizeof(struct network_stat));
		memset(peer->data, 0, sizeof(struct network_stat));
		peer->exist = 0;
		peer = peer->next;
	}
	
	// read current file at last 
	iter = filelist.begin();
	iter++;

	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				
				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					char buf[MAX_BUF_SIZE];

					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

					sprintf_ex(filter_e, "%s", save_t);

					if (fgets(buf, sizeof(buf), fp) != NULL) {
						char *ptr, *save_ptr;
						struct network_stat * net_stat = NULL;

						// remove EOL
						*(buf + (strlen(buf) - 1)) = 0;
						/* peer name*/
						ptr = strtok_r(buf, " ", &save_ptr);
						while (ptr) {						
							bool is_peer = false;
							peer = peer_head;
							// BSR-1032
							if (is_ipv6(ptr))
								ptr = strtok_r(NULL, " ", &save_ptr);

							while (peer) {
								// BSR-1032
								if (strcmp(ptr, get_peer_name(peer->name)) == 0) {
									is_peer = true;
									peer->exist = 1;
									break;
								}
								peer = peer->next;
							}

							
							if (!is_peer) {
								ptr = strtok_r(NULL, " ", &save_ptr);
								continue;
							}

							net_stat = (struct network_stat *)peer->data;

							/* send_byte/s recv_byte/s */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&net_stat->send, atoi(ptr));
							
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&net_stat->recv, atoi(ptr));
							
							ptr = strtok_r(NULL, " ", &save_ptr);
						}
					}

					continue;
				} 
				else {
					if (start_collect)
						end_collect = true;
				}
				fscanf_ex(fp, "%*[^\n]");	
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}
		
		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			peer = peer_head;
			while (peer) {
				struct network_stat * net_stat = (struct network_stat *)peer->data;
				if (peer->exist) {
					printf("  PEER %s: send=%llubyte/s, receive=%llubyte/s\n", 
						peer->name,  
						stat_avg(net_stat->send.sum, net_stat->send.cnt), 
						stat_avg(net_stat->recv.sum, net_stat->recv.cnt));
					print_stat("    send (byte/s)", &net_stat->send);
					print_stat("    recv (byte/s)", &net_stat->recv);
					memset(peer->data, 0, sizeof(struct network_stat));
					peer->exist = 0;
				}
				else {
					printf("  PEER %s: \n", peer->name);
					printf("    not found\n");
				}
				peer = peer->next;
			}
			do_print = false;
			find_date = true;

			goto read_continue;
		}

		fclose(fp);
	}

	while (peer) {
		peer_head = peer;
		peer = peer->next;
		free(peer_head->data);
		free(peer_head);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

/**
 * Reports statistics of sendbuf performance.
 */
void read_sendbuf_stat_work(std::set<std::string> filelist, char *resname, struct peer_stat *peer, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 

	struct sendbuf_stat {
		long long d_buf_size;
		long long c_buf_size;
		struct perf_stat data;
		struct perf_stat control;
		struct perf_stat total_in_flight;
		struct perf_stat highwater;
		struct perf_stat ap_size;
		struct perf_stat ap_cnt;
		struct perf_stat rs_size; 
		struct perf_stat rs_cnt;
	};
	struct peer_stat *peer_head;


	bool change_bufsize = false, init_buf = true;

	unsigned int iter_index = 0;
	std::set<std::string>::iterator iter;

	if (!peer)
		peer = get_peer_list(resname);
	peer_head = peer;

	while (peer) {
		peer->data = (struct sendbuf_stat *)malloc(sizeof(struct sendbuf_stat));
		memset(peer->data, 0, sizeof(struct sendbuf_stat));
		peer->exist = 0;
		peer = peer->next;
	}

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}
read_continue:
		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}

				if (strlen(start_t) == 0)
					sprintf_ex(start_t, "%s", save_t);

				if (check_record_time(save_t, tf)) {
					char buf[MAX_BUF_SIZE] = {0,};

					if(!start_collect) {
						start_collect = true;
						if (!change_bufsize)
							sprintf_ex(filter_s, "%s", save_t);
						else
							change_bufsize = false;
					}
					sprintf_ex(filter_e, "%s", save_t);

					if (fgets(buf, sizeof(buf), fp) != NULL) {
						char *ptr, *save_ptr;
						struct sendbuf_stat * sendbuf = NULL;
						// remove EOL
						*(buf + (strlen(buf) - 1)) = 0;

						/* peer */
						ptr = strtok_r(buf, " ", &save_ptr);
						while (ptr) {				
							bool is_peer = false;
							long long t_size = 0, t_used = 0;
							peer = peer_head;

							// BSR-1032
							if (is_ipv6(ptr))
								ptr = strtok_r(NULL, " ", &save_ptr);

							while (peer) {
								// BSR-1032
								if (strcmp(ptr, get_peer_name(peer->name)) == 0) {
									is_peer = true;
									peer->exist = 1;
									break;
								}
								peer = peer->next;
							}
							
							if (!is_peer) {
								ptr = strtok_r(NULL, " ", &save_ptr);
								continue;
							}
							 					
							sendbuf = (struct sendbuf_stat *)peer->data;

							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							// BSR-839 print highwater
							/* ap_in_flight size cnt */
							if (ptr && !strcmp(ptr, "ap")) {
								long long ap_s = 0, rs_s = 0;
								int ap_c = 0, rs_c = 0;

								ap_s = atoll(strtok_r(NULL, " ", &save_ptr));
								ap_c = atoi(strtok_r(NULL, " ", &save_ptr));
								
								/* rs_in_flight size cnt */
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (ptr && strcmp(ptr, "rs"))
									break;
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								rs_s = atoll(ptr);
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								rs_c = atoi(ptr);
								
								set_min_max_val(&sendbuf->ap_size, ap_s);
								set_min_max_val(&sendbuf->ap_cnt, ap_c);
								set_min_max_val(&sendbuf->rs_size, rs_s);
								set_min_max_val(&sendbuf->rs_cnt, rs_c);

								set_min_max_val(&sendbuf->total_in_flight, ap_s + rs_s);
								set_min_max_val(&sendbuf->highwater, ap_c + rs_c);
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
							}

							if (!strcmp(ptr, "no")) {
								// skip str
								strtok_r(NULL, " ", &save_ptr);
								strtok_r(NULL, " ", &save_ptr);

								if (sendbuf->d_buf_size != 0) {
									change_bufsize = true;
									break;
								}								
							}
							else if (!strcmp(ptr, "data")) {
								/* data sock size used */
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								t_size = atoll(ptr);
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								t_used = atoll(ptr);

								if (init_buf && (sendbuf->d_buf_size == 0)) {
									sendbuf->d_buf_size = t_size;
								} 
								else if (sendbuf->d_buf_size != t_size) {
									change_bufsize = true;
									break;
								}
								
								set_min_max_val(&sendbuf->data, t_used);

								ptr = strtok_r(NULL, " ", &save_ptr);

								while (ptr && strcmp(ptr, "control"))
									ptr = strtok_r(NULL, " ", &save_ptr);
								
								if (ptr == NULL)
									break;

								/* control sock size used */
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								t_size = atoll(ptr);
								ptr = strtok_r(NULL, " ", &save_ptr);
								if (!ptr)
									break;
								t_used = atoll(ptr);
								if (sendbuf->c_buf_size == 0 || sendbuf->c_buf_size != t_size) {
									sendbuf->c_buf_size = t_size;
									memset(&sendbuf->control, 0, sizeof(struct perf_stat));
								}
								
								set_min_max_val(&sendbuf->control, t_used);
							}
							else 
								break;

							ptr = strtok_r(NULL, " ", &save_ptr);
						}

						if (init_buf)
							init_buf = false;
						
					}

					if (change_bufsize) {
						start_collect = end_collect = false;
						do_print = true;
						break;
					}

					continue;
				} 
				else {
					if (start_collect)
						end_collect = true;
				}

				fscanf_ex(fp, "%*[^\n]");
			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}
		}

		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
				
			peer = peer_head;
			while (peer) {
				struct sendbuf_stat *sendbuf = (struct sendbuf_stat *)peer->data;
				if (peer->exist) {
					if (sendbuf->d_buf_size) {
						printf("  PEER %s: data stream size=%lldbyte, control stream size=%lldbyte\n", 
							peer->name, sendbuf->d_buf_size, sendbuf->c_buf_size);
						print_stat("    data-used (bytes)", &sendbuf->data);
						print_stat("    cntl-used (bytes)", &sendbuf->control);
					} else {
						printf("  PEER %s: no send buffer\n", peer->name);
					}
					
					// BSR-839 print highwater
					print_stat("    highwater", &sendbuf->highwater);
					print_stat("    fill (bytes)", &sendbuf->total_in_flight);
					print_stat("       ap_in_flight (bytes)", &sendbuf->ap_size);
					print_stat("                      (cnt)", &sendbuf->ap_cnt);
					print_stat("       rs_in_flight (bytes)", &sendbuf->rs_size);
					print_stat("                      (cnt)", &sendbuf->rs_cnt);

					memset(peer->data, 0, sizeof(struct sendbuf_stat));
					peer->exist = 0;
				}
				else {
					printf("  PEER %s: \n", peer->name);
					printf("    not found\n");
				}
				peer = peer->next;
			}
			do_print = false;
			find_date = true;
			init_buf = true;

			if (change_bufsize) {
				printf(" -> send buffer size changed\n");
				sprintf_ex(filter_s, "%s", save_t);
			}

			goto read_continue;
		}

		fclose(fp);
	}

	while (peer) {
		peer_head = peer;
		peer = peer->next;
		free(peer_head->data);
		free(peer_head);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

#define TOP_PROCESS_LIST_CNT 5
#ifdef _LIN
// BSR-875
void add_top_process_list(struct process_info *proc_info, struct process_info *proc)
{
	int i, insert_idx = 0;
	bool insert = false;

	for (i = 0; i < TOP_PROCESS_LIST_CNT; i++) {
		if (proc_info[i].rsz == 0) {
			memcpy(&proc_info[i], proc, sizeof(struct process_info));
			return;
		} else if (proc_info[i].rsz <= proc->rsz) {
			insert = true;
			insert_idx = i;
			break;
		}
	}

	if (!insert)
		return;
	
	for (i = TOP_PROCESS_LIST_CNT - 2; i >= insert_idx; i--)
		memcpy(&proc_info[i+1], &proc_info[i], sizeof(struct process_info));
	
	if (insert) 
		memcpy(&proc_info[insert_idx], proc, sizeof(struct process_info));

}	
#else
struct top_process_stat {
	char time[32];
	char name[256];
	LONGLONG usage;
};

void add_memory_intensive_processes(struct top_process_stat *top_stat, struct top_process_stat *n) {

	LONGLONG usage_min = 0;
	int index = 0;

	for (int i = 0; i < TOP_PROCESS_LIST_CNT; i++) {
		if (top_stat[i].usage == 0) {
			index = i;
			break;
		}

		if (usage_min == 0 ||
			usage_min > top_stat[i].usage) {
			usage_min = top_stat[i].usage;
			index = i;
		}
	}

	if (usage_min < n->usage) {
		memcpy(&top_stat[index], n, sizeof(*n));
	}
}

#endif
/**
 * Reports statistics of memory performance.
 */
void read_memory_work(std::set<std::string> filelist, struct time_filter *tf)
{
	FILE *fp;
	struct kmem_perf_stat kmem = {};
	struct umem_perf_stat bsrmon_stat = {};
	struct umem_perf_stat bsradm_stat = {};
	struct umem_perf_stat bsrsetup_stat = {};
	struct umem_perf_stat bsrmeta_stat = {};
#ifdef _WIN
	struct umem_perf_stat bsrservice_stat = {};
	struct perf_stat total_stat = {};
	struct perf_stat total_usage_stat = {};
	LONGLONG t_used = 0, np_used = 0, p_use = 0, unt_np_used = 0, t_mem = 0;

	struct top_process_stat top_stat[TOP_PROCESS_LIST_CNT] = {};
	struct top_process_stat top_n_stat = {};
	struct top_process_stat t = {};
#else // _LIN
	unsigned int t_req = 0, t_al = 0, t_bm = 0, t_ee = 0, t_bio_set = 0, t_kmalloc = 0, t_vmalloc = 0, t_pp = 0;
	struct sys_mem_perf_stat sys_mem_stat = {0,};
	unsigned int mem_total = 0, mem_used = 0, mem_free = 0, mem_buff_cache = 0;
	struct process_info proc_list[TOP_PROCESS_LIST_CNT] = {0,};
	struct process_info temp_proc = {0,};
#endif
	struct umem_perf_stat *temp = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	bool start_collect = false, end_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 
	unsigned int index = 0, iter_index = 0;

	std::set<std::string>::iterator iter;

	// read current file at last 
	iter = filelist.begin();
	iter++;
	for (iter_index = 0; iter_index < filelist.size(); iter_index++, iter++) {

		if (iter == filelist.end())
			iter = filelist.begin();

		if (fopen_s(&fp, iter->c_str(), "r") != 0) {
			fprintf(stderr, "Failed to open file(%s)\n", iter->c_str());
			return;
		}

read_continue:

		while (!feof(fp)) {
			if (EOF != collection_time(fp, save_t)) {
				if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
					fscanf_ex(fp, "%*[^\n]");
					continue;
				}
				if (check_record_time(save_t, tf)) {
					char *ptr, *save_ptr;
					char buf[MAX_BUF_SIZE];

			#ifdef _WIN
					memcpy(top_n_stat.time, save_t, strlen(save_t));
			#endif
					if(!start_collect) {
						start_collect = true;
						sprintf_ex(filter_s, "%s", save_t);
					}

			#ifdef _WIN
					/* total memory(bytes), total usage memory(bytes) */
					fscanf_ex(fp, "%lld %lld", &t_mem, &t_used);
					set_min_max_val(&total_stat, BYTE_TO_KBYTE(t_mem));
					set_min_max_val(&total_usage_stat, BYTE_TO_KBYTE(t_used));

					/* module TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) UntagNonPagedUsed(bytes)*/
					fscanf_ex(fp, "%lld %lld %lld %lld", &t_used, &np_used, &p_use, &unt_np_used);
					set_min_max_val(&kmem.total, BYTE_TO_KBYTE(t_used));
					set_min_max_val(&kmem.npused, BYTE_TO_KBYTE(np_used));
					set_min_max_val(&kmem.pused, BYTE_TO_KBYTE(p_use));
					set_min_max_val(&kmem.untnpused, BYTE_TO_KBYTE(unt_np_used));
			#else // _LIN
					/* MemTotal MemUsed MemFree buff/cache */
					fscanf_ex(fp, "%u %u %u %u", &mem_total, &mem_used, &mem_free, &mem_buff_cache);
					set_min_max_val(&sys_mem_stat.total, mem_total);
					set_min_max_val(&sys_mem_stat.used, mem_used);
					set_min_max_val(&sys_mem_stat.free, mem_free);
					set_min_max_val(&sys_mem_stat.buff_cache, mem_buff_cache);
					
					/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
					fscanf_ex(fp, "%u %u %u %u", &t_req, &t_al, &t_bm, &t_ee);
					set_min_max_val(&kmem.req, t_req);
					set_min_max_val(&kmem.al, t_al);
					set_min_max_val(&kmem.bm, t_bm);
					set_min_max_val(&kmem.ee, t_ee);

					/* total_bio_set kmalloc vmalloc total_page_pool */
					fscanf_ex(fp, "%u %u %u %u", &t_bio_set, &t_kmalloc, &t_vmalloc, &t_pp);
					set_min_max_val(&kmem.bio_set, t_bio_set);
					set_min_max_val(&kmem.kmalloc, t_kmalloc);
					set_min_max_val(&kmem.vmalloc, t_vmalloc);
					set_min_max_val(&kmem.page_pool, t_pp);

					/* top 5 process */
					fscanf_ex(fp, "%s %u %u %u", temp_proc.name, &temp_proc.pid, &temp_proc.rsz, &temp_proc.vsz);
					strcpy(temp_proc._time, save_t);
					add_top_process_list(proc_list, &temp_proc);
			#endif

					if (fgets(buf, sizeof(buf), fp) != NULL) {
						// remove EOL
						*(buf + (strlen(buf) - 1)) = 0;
						ptr = strtok_r(buf, " ", &save_ptr);

			#ifdef _WIN
						memset(top_n_stat.name, 0, sizeof(top_n_stat.name));
						memcpy(top_n_stat.name, ptr, strlen(ptr));
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						top_n_stat.usage = STRING_TO_KBYTE(ptr);
						add_memory_intensive_processes(top_stat, &top_n_stat);

						ptr = strtok_r(NULL, " ", &save_ptr);
			#endif

						while (ptr) {
							/* app name */
							if (!strcmp(ptr, "bsrmon"))
								temp = &bsrmon_stat;
							else if (!strcmp(ptr, "bsradm"))
								temp = &bsradm_stat;
							else if (!strcmp(ptr, "bsrsetup"))
								temp = &bsrsetup_stat;
							else if (!strcmp(ptr, "bsrmeta"))
								temp = &bsrmeta_stat;
			#ifdef _WIN
							else if (!strcmp(ptr, "bsr") || !strcmp(ptr, "bsrService") )
								temp = &bsrservice_stat;
			#endif
							else
								break;
							
							/* pid - skip */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
			#ifdef _WIN
							/* WorkingSetSize(bytes) */ 
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->wss, STRING_TO_KBYTE(ptr));
							/* QuotaPagedPoolUsage(bytes) */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->qpp, STRING_TO_KBYTE(ptr));
							/* QuotaNonPagedPoolUsage(bytes) */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->qnpp, STRING_TO_KBYTE(ptr));
							/* PagefileUsage(bytes) */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->pfu, STRING_TO_KBYTE(ptr));
			#else // _LIN	
							/* rsz(kbytes) */ 
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->rsz, atol(ptr));
							/* vsz(kbytes) */
							ptr = strtok_r(NULL, " ", &save_ptr);
							if (!ptr)
								break;
							set_min_max_val(&temp->vsz, atol(ptr));
			#endif
							// next app
							ptr = strtok_r(NULL, " ", &save_ptr);
						}
					}

					sprintf_ex(filter_e, "%s", save_t);
					continue;
				}
				else {
					if (start_collect)
						end_collect = true;
				}
				fscanf_ex(fp, "%*[^\n]");

			}

			if (start_collect && end_collect) {
				start_collect = end_collect = false;
				do_print = true;
				break;
			}	
		}


		if (start_collect && !end_collect && (iter == filelist.begin())) {
			start_collect = end_collect = false;
			do_print = true;
		}


		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
#ifdef _WIN
			print_range("Total Memory (kbytes) : ", &total_stat, "\n");
			print_range("  TotalUsed : ", &total_usage_stat, "\n");

			printf(" module (kbytes)\n");
			/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
			print_range("  TotalUsed         : ", &kmem.total, "\n");
			print_range("  NonPagedUsed      : ", &kmem.npused, "\n");
			print_range("  PagedUsed         : ", &kmem.pused, "\n");
			print_range("  UntagNonPagedUsed : ", &kmem.untnpused, "\n");
#else
			/* MemTotal MemUsed MemFree buff/cache */
			print_range("Total Memory (kbytes) : ", &sys_mem_stat.total, "\n");
			print_range("  used : ", &sys_mem_stat.used, "\n");
			print_range("  free : ", &sys_mem_stat.free, "\n");
			print_range("  buff/cache : ", &sys_mem_stat.buff_cache, "\n");

			printf(" module (kytes)\n");
			printf("  BSR Slab memory \n");
			/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
			print_range("   bsr_req: ", &kmem.req, "\n");
			print_range("   bsr_al : ", &kmem.al, "\n");
			print_range("   bsr_bm : ", &kmem.bm, "\n");
			print_range("   bsr_ee : ", &kmem.ee, "\n");
			/* total_bio_set kmalloc vmalloc total_page_pool */
			print_range("   bsr_bio_set : ", &kmem.bio_set, "\n");
			print_range("   kmalloc  : ", &kmem.kmalloc, "\n");
			print_range("  BSR Virtual memory : ", &kmem.vmalloc, "\n");
			print_range("  BSR Pages memory : ", &kmem.page_pool, "\n");
#endif

#ifdef _WIN
			printf(" user (kbytes)\n");
			printf("  Top Memory\n");
			printf("   %-23s %-13s %-23s\n", "time", "name", "WorkingSetSize");

			for (int i = 0; i < TOP_PROCESS_LIST_CNT; i++) {
				for (int j = i + 1; j < TOP_PROCESS_LIST_CNT; j++) {
					if (top_stat[i].usage > top_stat[j].usage) {
						memcpy(&t, &top_stat[i], sizeof(t));
						top_stat[i] = top_stat[j];
						memcpy(&top_stat[j], &t, sizeof(t));
					}
				}
			}

			for (int i = (TOP_PROCESS_LIST_CNT - 1); i >= 0; i--) {
				if (top_stat[i].usage > 0)
					printf("   %-23s %-13s %lld\n", top_stat[i].time, top_stat[i].name, top_stat[i].usage);
			}
			printf("  %-13s %-23s %-23s %-23s %s\n", "name", "WorkingSetSize", "QuotaPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage");
			print_umem("bsrService", &bsrservice_stat);
#else // _LIN
			printf(" user (kbytes)\n");
			printf("  Top process\n");
			printf("   %-23s %-13s %-23s\n", "time", "name", "rsz");
			for (index = 0; index < TOP_PROCESS_LIST_CNT; index++)
				printf("   %-23s %-13s %-23u\n", proc_list[index]._time, proc_list[index].name, proc_list[index].rsz);

			printf("  BSR process\n");
			printf("   %-13s %-23s %s\n", "name", "rsz", "vsz");

#endif
			print_umem("bsradm", &bsradm_stat);
			print_umem("bsrsetup", &bsrsetup_stat);
			print_umem("bsrmeta", &bsrmeta_stat);
			print_umem("bsrmon", &bsrmon_stat);

			do_print = false;
			find_date = true;

			memset(&kmem, 0, sizeof(struct kmem_perf_stat));
			memset(&bsradm_stat, 0, sizeof(struct umem_perf_stat));
			memset(&bsrsetup_stat, 0, sizeof(struct umem_perf_stat));
			memset(&bsrmeta_stat, 0, sizeof(struct umem_perf_stat));
			memset(&bsrmon_stat, 0, sizeof(struct umem_perf_stat));
#ifdef _WIN
			memset(&total_stat, 0, sizeof(struct perf_stat));
			memset(&total_usage_stat, 0, sizeof(struct perf_stat));
			memset(&bsrservice_stat, 0, sizeof(struct umem_perf_stat));
#endif
			goto read_continue;
		}

		fclose(fp);
	}

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);

}


void watch_io_stat(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_shared(path);
	if (fp == NULL)
		return;


	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);

		/* time riops rios rkbs rkb wiops wios rkbs rkb */
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long r_iops = 0, r_ios = 0, r_kbs = 0, r_kb = 0;
			unsigned long w_iops = 0, w_ios = 0, w_kbs = 0, w_kb = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr);
			r_iops = atol(strtok_r(NULL, " ", &save_ptr));
			r_ios = atol(strtok_r(NULL, " ", &save_ptr));
			r_kbs = atol(strtok_r(NULL, " ", &save_ptr));
			r_kb = atol(strtok_r(NULL, " ", &save_ptr));
			w_iops = atol(strtok_r(NULL, " ", &save_ptr));
			w_ios = atol(strtok_r(NULL, " ", &save_ptr));
			w_kbs = atol(strtok_r(NULL, " ", &save_ptr));
			w_kb = atol(strtok_r(NULL, " ", &save_ptr));

			printf("  read : IO count=%lu, BW=%lukb/s (%luKB)\n", 
						r_ios, r_kbs, r_kb);
			printf("  write: IO count=%lu, BW=%lukb/s (%luKB)\n", 
						w_ios, w_kbs, w_kb);	
			
		} else {
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}

		continue;
		
	}

	
	fclose(fp);
	
}


void watch_io_complete(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		
		/* time local_min local_max local_avg master_min master_max master_avg */
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long local_cnt = 0, local_min = 0, local_max = 0, local_avg = 0;
			unsigned long master_cnt = 0, master_min = 0, master_max = 0, master_avg = 0;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr);

			local_cnt = atol(strtok_r(NULL, " ", &save_ptr));
			local_min = atol(strtok_r(NULL, " ", &save_ptr));
			local_max = atol(strtok_r(NULL, " ", &save_ptr));
			local_avg = atol(strtok_r(NULL, " ", &save_ptr));
			master_cnt = atol(strtok_r(NULL, " ", &save_ptr));
			master_min = atol(strtok_r(NULL, " ", &save_ptr));
			master_max = atol(strtok_r(NULL, " ", &save_ptr));
			master_avg = atol(strtok_r(NULL, " ", &save_ptr));
			// BSR-1072 print completed local/master IO count data
			printf("  local clat  (usec): complete_count=%lu, min=%lu, max=%lu, avg=%lu\n", local_cnt, local_min, local_max, local_avg);
			printf("  master clat (usec): complete_count=%lu, min=%lu, max=%lu, avg=%lu\n", master_cnt, master_min, master_max, master_avg);
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}
	

	fclose(fp);
	
}

// BSR-1054
void watch_io_pending(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		
		// upper_pending pending_latency lower_pending al_suspended al_pending_changes al_wait_req upper_blocked suspended suspend_cnt unstable pending_bitmap_work
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr);
			printf("  upper_pending     : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    pending_latency (usec): %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  lower_pending     : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  al_suspended      : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  al_pending_changes: %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  al_wait_req       : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  upper_blocked     : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    suspended          : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    suspend_cnt        : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    unstable           : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    pending_bitmap_work: %s\n", strtok_r(NULL, " ", &save_ptr));
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}
	

	fclose(fp);
	
}


void print_req_stat(char ** save_ptr, const char * name) 
{	
	unsigned long t_min = 0, t_max = 0, t_avg = 0;
	
	t_min = atol(strtok_r(NULL, " ", save_ptr));
	t_max = atol(strtok_r(NULL, " ", save_ptr));
	t_avg = atol(strtok_r(NULL, " ", save_ptr));
	printf("%s: min=%lu, max=%lu, avg=%lu\n", name, t_min, t_max, t_avg);
}

void watch_req_stat(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;
	
	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long t_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();

			printf("%s\n", ptr);

			// req
			ptr = strtok_r(NULL, " ", &save_ptr);
			t_cnt = atol(strtok_r(NULL, " ", &save_ptr));
			printf("  requests  : %lu\n", t_cnt);
			print_req_stat(&save_ptr, "    before_queue    (usec)");
			print_req_stat(&save_ptr, "    before_al_begin (usec)");
			print_req_stat(&save_ptr, "    in_actlog       (usec)");
			print_req_stat(&save_ptr, "    submit          (usec)");
			print_req_stat(&save_ptr, "    bio_endio       (usec)");
			print_req_stat(&save_ptr, "    destroy         (usec)");

			// al
			ptr = strtok_r(NULL, " ", &save_ptr);
			t_cnt = atol(strtok_r(NULL, " ", &save_ptr));
			printf("  al_update  : %lu\n", t_cnt);
			print_req_stat(&save_ptr, "    before_bm_write (usec)");
			print_req_stat(&save_ptr, "    after_bm_write  (usec)");
			print_req_stat(&save_ptr, "    after_sync_page (usec)");

			/* peer_name */
			ptr = strtok_r(NULL, " ", &save_ptr);
			while (ptr) {
				// BSR-1032
				if (is_ipv6(ptr)) {
					char *ipv6_addr = NULL;
					ipv6_addr = strtok_r(NULL, " ", &save_ptr);
					printf("  PEER %s %s:\n", ptr, ipv6_addr); // peer_name
				} else {
					printf("  PEER %s:\n", ptr); // peer_name
				}
				print_req_stat(&save_ptr, "    pre_send (usec)");
				print_req_stat(&save_ptr, "    acked    (usec)");
				print_req_stat(&save_ptr, "    net_done (usec)");
				ptr = strtok_r(NULL, " ", &save_ptr);
			}
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}


	fclose(fp);

}

void watch_peer_req_stat(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	
		
		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long t_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr);

			ptr = strtok_r(NULL, " ", &save_ptr);
			while (ptr) {
				/* peer name */
				// BSR-1032
				if (is_ipv6(ptr)) {
					char *ipv6_addr = NULL;
					ipv6_addr = strtok_r(NULL, " ", &save_ptr);
					printf("  PEER %s %s:\n", ptr, ipv6_addr);
				} else {
					printf("  PEER %s:\n", ptr);
				}
				/* req cnt*/
				t_cnt = atol(strtok_r(NULL, " ", &save_ptr));
				printf("    peer requests : %lu\n", t_cnt);
				print_req_stat(&save_ptr, "    submit    (usec)");
				print_req_stat(&save_ptr, "    bio_endio (usec)");
				print_req_stat(&save_ptr, "    destroy   (usec)");

				ptr = strtok_r(NULL, " ", &save_ptr);
			}
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}


	fclose(fp);

}

void print_al_stat(char ** save_ptr, const char * name) 
{	
	unsigned long t_now = 0, t_total = 0;
	t_now = atol(strtok_r(NULL, " ", save_ptr));
	t_total = atol(strtok_r(NULL, " ", save_ptr));
	printf("%s: %10lu (total=%lu)\n", name, t_now, t_total);
}


// BSR-765 add al stat watching
void watch_al_stat(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;
	
	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);	
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned cnt, max, total;
			unsigned e_starving, e_pending, e_used, e_busy, e_wouldblock, e_cnt;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			/* time */
			printf("%s\n", ptr);
			
			ptr = strtok_r(NULL, " ", &save_ptr);
			if (!ptr) 
				continue;
			/* nr_elements used used_max */
			total = atol(ptr);
			cnt = atol(strtok_r(NULL, " ", &save_ptr));
			max = atol(strtok_r(NULL, " ", &save_ptr));

			printf("  used    : %10u/%u (max=%u)\n", cnt, total, max);

			/* hits_cnt hits misses_cnt misses starving_cnt starving locked_cnt locked changed_cnt changed */
			print_al_stat(&save_ptr, "  hits    ");
			print_al_stat(&save_ptr, "  misses  ");
			print_al_stat(&save_ptr, "  starving");
			print_al_stat(&save_ptr, "  locked  ");
			print_al_stat(&save_ptr, "  changed ");

			/* al_wait_retry_cnt al_wait_retry_total al_wait_retry_max*/
			cnt = atol(strtok_r(NULL, " ", &save_ptr));
			total = atol(strtok_r(NULL, " ", &save_ptr));
			max = atol(strtok_r(NULL, " ", &save_ptr));
			printf("  al_wait retry : %10u (total=%u, max=%u)\n", cnt, total, max);
				
			/* pending_changes max_pending_changes */
			cnt = atol(strtok_r(NULL, " ", &save_ptr));
			total = atol(strtok_r(NULL, " ", &save_ptr));
			printf("  pending_changes : %2u/%u\n", cnt, total);

			/* e_al_starving e_al_pending e_al_used e_al_busy e_al_wouldblock */
			e_starving = atoi(strtok_r(NULL, " ", &save_ptr));
			e_pending = atoi(strtok_r(NULL, " ", &save_ptr));
			e_used = atoi(strtok_r(NULL, " ", &save_ptr));
			e_busy = atoi(strtok_r(NULL, " ", &save_ptr));
			e_wouldblock = atoi(strtok_r(NULL, " ", &save_ptr));
			e_cnt = e_starving + e_pending + e_used + e_busy + e_wouldblock;
			
			printf("  error   : %u\n", e_cnt);
			printf("    NOBUFS - starving : %u\n", e_starving);
			printf("           - pending slot : %u\n", e_pending);
			printf("           - used slot : %u\n", e_used);
			printf("    BUSY : %u\n", e_busy);
			printf("    WOULDBLOCK : %u\n", e_wouldblock);

			
			/* flags ... */
			ptr = strtok_r(NULL, " ", &save_ptr);
			if (ptr)
				printf("  flags   : %s %s\n", ptr, save_ptr);
			else 
				printf("  flags   : NONE\n");
			
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}

		continue;
		
	}
	
	fclose(fp);
	
}

void watch_network_speed(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;
	
	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {	
			char *ptr, *save_ptr;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (!ptr)
				continue;

			if (!scroll)
				clear_screen();
			
			printf("%s\n", ptr); // time
			ptr = strtok_r(NULL, " ", &save_ptr);
			while (ptr) {
				// BSR-1032
				if (is_ipv6(ptr)) {
					char *ipv6_addr = NULL;
					ipv6_addr = strtok_r(NULL, " ", &save_ptr);
					printf("  PEER %s %s:\n", ptr, ipv6_addr); // peer_name
				} else {
					printf("  PEER %s:\n", ptr); // peer_name
				}
				printf("    send (byte/s) : %lu\n", 
					atol(strtok_r(NULL, " ", &save_ptr)));
				printf("    recv (byte/s) : %lu\n", 
					atol(strtok_r(NULL, " ", &save_ptr)));
				
				ptr = strtok_r(NULL, " ", &save_ptr);
			}
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}
	fclose(fp);

}


void watch_sendbuf(char *path, bool scroll)
{
	FILE *fp;
	char *peer_name, *type;
	int offset = 0;
	
	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			long long s_size = 0, s_used = 0;
			long long p_size = 0, p_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (!ptr)
				continue;
			if (!scroll) 
				clear_screen();
			
			printf("%s\n", ptr); // time

			type = strtok_r(NULL, " ", &save_ptr);
			while (type) {
				// BSR-1032
				if (is_ipv6(type)) {
					ptr = strtok_r(NULL, " ", &save_ptr);
					printf("  PEER %s %s:\n", type, ptr); // peer_name
					type = strtok_r(NULL, " ", &save_ptr);
				} else if (!strcmp(type, "no")) {
					/* no send buffer */
					strtok_r(NULL, " ", &save_ptr);
					strtok_r(NULL, " ", &save_ptr);
					printf("    no send buffer\n");
					type = strtok_r(NULL, " ", &save_ptr);
					continue;
				}
				else if (!strcmp(type, "data") || !strcmp(type, "control")) {
					/* sock_type size used */
					s_size = atoll(strtok_r(NULL, " ", &save_ptr));
					s_used = atoll(strtok_r(NULL, " ", &save_ptr));
					
					printf("    %s stream\n", type);
					printf("        size (bytes) : %lld\n", s_size);
					printf("        used (bytes) : %lld\n", s_used); 
					
					type = strtok_r(NULL, " ", &save_ptr);
				}
				// BSR-839 print highwater
				else if (!strcmp(type, "ap")) {
					long long ap_in_flight = 0, rs_in_flight = 0;
					int ap_cnt = 0, rs_cnt = 0;
					/* ap_in_flight size_bytes cnt */
					ap_in_flight = atoll(strtok_r(NULL, " ", &save_ptr));
					ap_cnt = atoi(strtok_r(NULL, " ", &save_ptr));

					type = strtok_r(NULL, " ", &save_ptr);
					if (strcmp(type, "rs"))
						continue;
					/* rs_in_flight size_bytes cnt */
					rs_in_flight = atoll(strtok_r(NULL, " ", &save_ptr));
					rs_cnt = atoi(strtok_r(NULL, " ", &save_ptr));
					
					printf("    highwater : %d, fill : %lldbytes\n", ap_cnt + rs_cnt, ap_in_flight + rs_in_flight);
					printf("        ap_in_flight : %d (%lldbytes)\n", ap_cnt, ap_in_flight);
					printf("        rs_in_flight : %d (%lldbytes)\n", rs_cnt, rs_in_flight);
					type = strtok_r(NULL, " ", &save_ptr);
				}
				else {
					ptr = strtok_r(NULL, " ", &save_ptr);

					if (!strcmp(ptr, "no") ||!strcmp(ptr, "data") || !strcmp(ptr, "control") || !strcmp(ptr, "ap")) {
						// peer_name
						peer_name = type;
						printf("  PEER %s:\n", peer_name); 
						type = ptr;
					} else {
						// packet info
						p_cnt = atoll(ptr);
						p_size = atoll(strtok_r(NULL, " ", &save_ptr));
						printf("         [%s]  -  cnt : %lld  size : %lldbytes\n", type, p_cnt, p_size);
						type = strtok_r(NULL, " ", &save_ptr);
					}
				}
			}
		} else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}

	fclose(fp);
}

void watch_memory(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;
	
	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr, *app_name;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (!ptr)
				continue;
			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr); // time
#ifdef _WIN
			printf("Total Memory (kbytes) : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("  TotalUsed        : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("  module (kbytes)\n");

			/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
			printf("    TotalUsed         : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("    NonPagedUsed      : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("    PagedUsed         : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("    UntagNonPagedUsed : %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));

			printf("  user (kbytes)\n");
			printf("    Top Memory\n");
			printf("      %-13s %-23s\n", "name", "WorkingSetSize");
			printf("      %-13s", strtok_r(NULL, " ", &save_ptr));
			printf(" %lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
			printf("    %-11s %-6s %-15s %-21s %-23s %-14s\n", "name", "pid", "WorkingSetSize", "QuotaPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage");

			app_name = strtok_r(NULL, " ", &save_ptr);
			while (app_name) {
				printf("    %-11s", app_name);
				printf(" %-6ld", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-15lld", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-21lld", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-23lld", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-14lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
				app_name = strtok_r(NULL, " ", &save_ptr);
			}
			
#else // LIN
			/* MemTotal MemUsed MemFree buff/cache */
			printf("Total Memory (kbytes): %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    used : %s, ", strtok_r(NULL, " ", &save_ptr));
			printf("free : %s, ", strtok_r(NULL, " ", &save_ptr));
			printf("buff/cache : %s\n", strtok_r(NULL, " ", &save_ptr));

			printf("  module (kbytes)\n");
			/* total slab memory (kbytes)*/
			//printf("    Total Slab memory (kbytes): %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    BSR Slab memory\n");
			/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
			printf("      bsr_req : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("      bsr_al  : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("      bsr_bm  : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("      bsr_ee  : %s\n", strtok_r(NULL, " ", &save_ptr));

			/* total_bio_set kmalloc vmalloc total_page_pool */
			printf("      bsr_bio_set : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("      kmalloc  : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    BSR Virtual memory : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("    BSR Pages memory : %s\n", strtok_r(NULL, " ", &save_ptr));
			printf("  user (kbytes)\n");
			printf("    Top process\n");
			printf("      %-9s %-6s %-10s %-10s\n", "name", "pid", "rsz", "vsz");
			printf("      %-9s", strtok_r(NULL, " ", &save_ptr));
			printf(" %-6s", strtok_r(NULL, " ", &save_ptr));
			printf(" %-10s", strtok_r(NULL, " ", &save_ptr));
			printf(" %-10s\n", strtok_r(NULL, " ", &save_ptr));

			printf("    BSR process\n");
			printf("      %-9s %-6s %-10s %-10s\n", "name", "pid", "rsz", "vsz");
			app_name = strtok_r(NULL, " ", &save_ptr);
			while (app_name) {
				printf("      %-9s", app_name);
				printf(" %-6s", strtok_r(NULL, " ", &save_ptr));
				printf(" %-10s", strtok_r(NULL, " ", &save_ptr));
				printf(" %-10s\n", strtok_r(NULL, " ", &save_ptr));

				app_name = strtok_r(NULL, " ", &save_ptr);
			}
#endif
		} 
		else {	
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}

	fclose(fp);

}

void watch_peer_resync_ratio(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_shared(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while (1) {
		char buf[MAX_BUF_SIZE] = { 0, };

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			long long repl_sended, resync_sended, resync_ratio;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (!scroll)
				clear_screen();
			printf("%s\n", ptr); // time

			ptr = strtok_r(NULL, " ", &save_ptr);
			while (ptr) {
				// BSR-1032
				if (is_ipv6(ptr)) {
					char *ipv6_addr = NULL;
					ipv6_addr = strtok_r(NULL, " ", &save_ptr);
					printf("%s %s\n", ptr, ipv6_addr); // peer name
				} else {
					printf("%s\n", ptr); // peer name
				}

				repl_sended = atoll(strtok_r(NULL, " ", &save_ptr));
				resync_sended = atoll(strtok_r(NULL, " ", &save_ptr));
				resync_ratio = atoll(strtok_r(NULL, " ", &save_ptr));
				printf("    replcation(%lldkb)/resync(%lldkb),  resync ratio %lld%%\n", repl_sended >> 10, resync_sended >> 10, resync_ratio);
				ptr = strtok_r(NULL, " ", &save_ptr);
			}
		}
		else {
#ifdef _WIN
			Sleep(1000);
#else // _LIN
			sleep(1);
#endif
		}
		continue;
	}

	fclose(fp);

}

// BSR-948 read last line of file
char * read_last_line(char * res_name, int vnr, char * file_name)
{
	FILE *fp;
	long leng = 2;
	char file_path[256];
	char * data;
	char c;

	data = (char*)malloc(MAX_BUF_SIZE);

	memset(file_path, 0, sizeof(file_path));
	memset(data, 0, sizeof(MAX_BUF_SIZE));

	if (res_name) {
		if (vnr != -1)
			sprintf_ex(file_path, "%s%s%svnr%d_%s", g_perf_path, res_name, _SEPARATOR_, vnr, file_name);
		else
			sprintf_ex(file_path, "%s%s%s%s", g_perf_path, res_name, _SEPARATOR_, file_name);
	} else {
		sprintf_ex(file_path, "%s%s", g_perf_path, file_name);
	}

	fp = open_shared(file_path);
	if (fp == NULL)
		return NULL;
	
	while(leng++ < MAX_BUF_SIZE){
		fseek(fp, -(leng), SEEK_END);
		c = fgetc(fp);
		if(c == '\n') {
			fgets(data, leng, fp);
			// remove EOL
			*(data + (strlen(data) - 1)) = 0;
			break;
		}
	}

	fclose(fp);
	if (!strlen(data)) {
		free(data);
		data = NULL;
	}

	return data;
}

static void print_head(const char * name)
{
	if (json)
		printf("\"%s\":{", name);
	else {
		printI("%s {\n", name);
		++indent;
	}
}

static void print_end(bool separator)
{	
	if (json)
		 printf("}%s", separator ? "," : "");
	else {
		--indent;
		printI("}\n");
	}
}


static void print_list_head(const char * name)
{
	if (json)
		printf("\"%s\":[{", name);
	else {
		printI("%s {\n", name);
		++indent;
	}
}

static void print_list_next()
{	
	if (json)
		printf("},{");
	else {
		--indent;
		printI("}\n");
	}
}

static void print_list_end(bool separator)
{
	if (json)
		printf("}]%s", separator ? "," : "");
	else {
		--indent;
		printI("}\n");
	}
}

static void print_data(const char * name, char * data, bool separator)
{
	if (json)
		printf("\"%s\":\"%s\"%s", name, data, separator ? "," : "");
	else {
		printI("%s\t%s;\n", name, data);
	}

}

static void print_data_unit(const char * name, char * data, const char * unit, bool separator)
{
	if (json)
		printf("\"%s\":\"%s%s\"%s", name, data, unit ? unit : "", separator ? "," : "");
	else {
		if (unit)
			printI("%s\t%s; # %s\n", name, data, unit);
		else
			printI("%s\t%s;\n", name, data);
	}

}

static void print_digit(const char * name, long long val, bool separator)
{
	if (json)
		printf("\"%s\":\"%lld\"%s", name, val, separator ? "," : "");
	else {
		printI("%s\t%lld;\n", name, val);
	}

}

static void print_digit_unit(const char * name, long long val, const char * unit, bool separator)
{
	if (json)
		printf("\"%s\":\"%lld%s\"%s", name, val, unit ? unit : "", separator ? "," : "");
	else
		printI("%s\t%lld; # %s\n", name, val, unit);
}

static void print_fields(char ** save_ptr, int nr, struct perf_field *field)
{
	char *ptr;
	int i;

	for (i = 0; i < nr; i++) {
		if (json && i)
			putchar(',');
		ptr = strtok_r(NULL, " ", save_ptr);
		if (!ptr)
			break;
		print_data_unit(field->name, ptr, field->unit, false);
		field++;
	}
}

static void print_sub_fields(char ** save_ptr, const char * name, const char * unit, bool sep)
{
	char *ptr;
	ptr = strtok_r(NULL, " ", save_ptr);
	if (!ptr)
		return;
	print_data_unit(name, ptr, unit, sep);
}

static void print_2fields(char ** save_ptr, int nr, struct perf_field *field, 
		const char * sub_name1, const char* sub_name2)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (json && i)
			putchar(',');
		print_head(field->name);
		print_sub_fields(save_ptr, sub_name1, field->unit, true);
		print_sub_fields(save_ptr, sub_name2, field->unit, false);
		field++;
		print_end(false);
	}
}

static void print_3fields(char ** save_ptr, int nr, struct perf_field *field, 
	const char * sub_name1, const char* sub_name2, const char * sub_name3)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (json && i)
			putchar(',');
		print_head(field->name);
		print_sub_fields(save_ptr, sub_name1, field->unit, true);
		print_sub_fields(save_ptr, sub_name2, field->unit, true);
		print_sub_fields(save_ptr, sub_name3, field->unit, false);
		field++;
		print_end(false);
	}
}

static void print_min_max_avg_group(char ** save_ptr, struct title_field *group, struct perf_field *field)
{
	print_head(group->name);
	print_3fields(save_ptr, group->nr, field, "min", "max", "avg");
	print_end(true);
}

static void print_group(char ** save_ptr, struct title_field *group, struct perf_field *fields, bool sep)
{	
	print_head(group->name);
	print_fields(save_ptr, group->nr, fields);
	print_end(sep);
}


static void print_timestamp()
{
	print_data("timestamp", g_timestamp, false);
}

static void print_current_memstat()
{
#ifdef _WIN
	// 4293943296 1975803904 53321536 53321536 0 0 explorer 148439040 bsr 2428 6258688 63248 9824 1736704 bsrmon 2468 4349952 56216 6248 1179648 
	char *data = NULL;
	struct title_field sys_stat = {"system", 2};
	struct title_field module_stat = {"module", 4};
	struct perf_field sys_fields[] = {
		{"total_memory", "bytes"},
		{"used_memory", "bytes"},
	};
	struct perf_field module_fields[] = {
		{"total_used", "bytes"}, 
		{"nonpaged_used", "bytes"},
		{"paged_used", "bytes"},
		{"untag_nonpaged_used", "bytes"},
	};

	
	struct title_field top_process = {"top_process", 2};
	struct title_field bsr_process = {"bsr_process", 6};
	struct perf_field top_process_fields[] = {
		{"name", NULL},
		{"workingset_size", "bytes"}, 
	};
	struct perf_field bsr_process_fields[] = {
		{"name", NULL},
		{"pid", NULL}, 
		{"workingset_size", "bytes"}, 
		{"quota_pagedpool_usage", "bytes"}, 
		{"quota_nonpagedpool_usage", "bytes"}, 
		{"pagefile_usage", "bytes"}, 
	};


	data = read_last_line(NULL, -1, (char *)"memory");
	if (data) {
		char *ptr, *save_ptr;
		bool first_proc = true;
			
		ptr = strtok_r(data, " ", &save_ptr);

		if (!strlen(g_timestamp))
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
	
		print_head("memory");
		print_group(&save_ptr, &sys_stat, sys_fields, true);
		print_group(&save_ptr, &module_stat, module_fields, true);
		print_head("user");
		print_group(&save_ptr, &top_process, top_process_fields, true);

		while (strlen(save_ptr)) {
			if (first_proc) {
				print_list_head(bsr_process.name);
				first_proc = false;
			}
			else {
				print_list_next();
				if (!json)
					print_list_head(bsr_process.name);
			}
			print_fields(&save_ptr, bsr_process.nr, bsr_process_fields);
		}
		if (!first_proc)
			print_list_end(false);

		print_end(true);
		print_timestamp();
		print_end(false);
		free(data);
	}
#else // _LIN
	char *data = NULL;
	struct title_field sys_stat = {"system", 4};
	struct title_field slab_stat = {"slab", 6};
	struct title_field module_stat = {"module", 2};
	
	// 3861252 1762740 253992 1844520 15616 1641 7732 2368 520 618 0 33504 gnome-shell 2445 281172 3683616 bsrmon 67027 1360 12776 bsrmon 76101 1188 12756 
	struct perf_field sys_fields[] = {
		{"total_memory", "kbytes"},
		{"used_memory", "kbytes"}, 
		{"free_memory", "kbytes"},
		{"buff/cache", "kbytes"}, 
	};
	struct perf_field slab_fields[] = {
		{"bsr_req", "kbytes"}, 
		{"bsr_al", "kbytes"},
		{"bsr_bm", "kbytes"},
		{"bsr_ee", "kbytes"}, 
		{"total_bio_set", "kbytes"},
		{"kmalloc", "kbytes"}, 
	};
	struct perf_field module_fields[] = {
		{"vmalloc", "kbytes"}, 
		{"total_page_pool", "kbytes"},
	};

	
	struct title_field top_process = {"top_process", 4};
	struct title_field bsr_process = {"bsr_process", 4};
	struct perf_field process_fields[] = {
		{"name", NULL},
		{"pid", NULL}, 
		{"rsz", "kbytes"}, 
		{"vsz", "kbytes"},
	};


	data = read_last_line(NULL, -1, (char *)"memory");
	if (data) {
		char *ptr, *save_ptr;
		bool first_proc = true;

		ptr = strtok_r(data, " ", &save_ptr);

		if (!strlen(g_timestamp))
			strcpy(g_timestamp, ptr); 

		print_head("memory");
		print_group(&save_ptr, &sys_stat, sys_fields, true);
		print_head(module_stat.name);
		print_group(&save_ptr, &slab_stat, slab_fields, true);
		print_fields(&save_ptr, module_stat.nr, module_fields);
		print_end(true);
		print_head("user");
		print_group(&save_ptr, &top_process, process_fields, true);

		while (strlen(save_ptr)) {
			if (first_proc) {
				print_list_head(bsr_process.name);
				first_proc = false;
			}
			else {
				print_list_next();
				if (!json)
					print_list_head(bsr_process.name);
			}
			print_fields(&save_ptr, bsr_process.nr, process_fields);
		}
		if (!first_proc)
			print_list_end(false);

		print_end(true);
		print_timestamp();
		print_end(false);
		
		free(data);
	}
#endif
}

static void print_current_iostat(char * name, int vnr)
{
	char *data = NULL;
	struct title_field read_stat = {"read", 4};
	struct title_field write_stat = {"write", 4};

	// 0 0 0 0 0 0 0 0
	struct perf_field fields[] = {
		{"iops", NULL},
		{"iocnt", NULL}, 
		{"kbs", "kbytes/second"},
		{"kb", "kbytes"},
	};

	data = read_last_line(name, vnr, (char *)"IO_STAT");
	
	if (data) {
		char *ptr, *save_ptr;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		print_head("iostat");
		print_group(&save_ptr, &read_stat, fields, true);
		print_group(&save_ptr, &write_stat, fields, false);
		print_end(true);
		free(data);
	}
}

static void print_current_ioclat(char * name, int vnr)
{
	char *data = NULL;
	struct title_field local = {"local", 4};
	struct title_field master = {"master", 4};


	// 0 0 0 0 0 0 0 0
	struct perf_field fields[] = {
		{"complete_count", NULL},
		{"min", "usec"}, 
		{"max", "usec"},
		{"avg", "usec"},
	};

	data = read_last_line(name, vnr, (char *)"IO_COMPLETE");
	
	if (data) {
		char *ptr, *save_ptr;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		print_head("ioclat");
		print_group(&save_ptr, &local, fields, true);
		print_group(&save_ptr, &master, fields, false);
		print_end(true);
		free(data);
	}
}

// BSR-1054
static void print_current_io_pending(char * name, int vnr)
{
	char *data = NULL;
	struct title_field io_pending_stat = {"io_pending", 6};
	struct title_field blocked_stat = {"upper_blocked", 4};
	// upper_pending pending_latency lower_pending al_suspended al_pending_changes al_wait_req upper_blocked suspended suspend_cnt unstable pending_bitmap_work
	struct perf_field pending_fields[] = {
		{"upper_pending", NULL},
		{"pending_latency", "usec"},
		{"lower_pending", NULL},
		{"al_suspended", NULL},
		{"al_pending_changes", NULL},
		{"al_wait_req", NULL},
	};
	struct perf_field blocked_fields[] = {
		{"suspended", NULL},
		{"suspend_cnt", NULL},
		{"unstable", NULL},
		{"pending_bitmap_work", NULL},
	};

	data = read_last_line(name, vnr, (char *)"IO_PENDING");
	
	if (data) {
		char *ptr, *save_ptr;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}
		print_head(io_pending_stat.name);
		print_fields(&save_ptr, io_pending_stat.nr, pending_fields);
		if (json)
			printf(",");
		strtok_r(NULL, " ", &save_ptr); // upper_blocked
		print_group(&save_ptr, &blocked_stat, blocked_fields, false);
		print_end(true);
		free(data);
	}
}

static void print_peer(struct connection *conn, const char *title, char **save_ptr, 
	struct title_field *stat, struct perf_field *fields, bool sub_group)
{
	char * ptr = NULL;

	if (title) {
		printI("%s {\n", title);
		++indent;
	}
	while (conn) {
		char *ipv6_addr = NULL;
		ptr = strtok_r(NULL, " ", save_ptr);
		if (ptr == NULL)
			break;
		if (is_ipv6(ptr)) {
			ipv6_addr = get_ipv6_name(save_ptr);
			ptr = ipv6_addr;
		}
		printI("%s %s {\n", stat->name, ptr);
		if (ipv6_addr)
			free(ipv6_addr);
		++indent;
		if (sub_group)
			print_3fields(save_ptr, stat->nr, fields, "min", "max", "avg");
		else 
			print_fields(save_ptr, stat->nr, fields);
		--indent;
		printI("}\n");
		
		conn = conn->next;
	}
	if (title) {
		--indent;
		printI("}\n");
	}
}

static void print_peer_json(struct connection *conn, const char *title, char **save_ptr, 
		struct title_field *stat, struct perf_field *fields, bool sub_group)
{
	bool first_conn = true;
	char * ptr = NULL;

	print_list_head(title);
	while (conn) {
		char *ipv6_addr = NULL;
		ptr = strtok_r(NULL, " ", save_ptr);
		if (ptr == NULL)
			break;
		if (first_conn)
			first_conn = false;
		else
			print_list_next();
		if (is_ipv6(ptr)) {
			ipv6_addr = get_ipv6_name(save_ptr);
			ptr = ipv6_addr;
		}
		print_data("peer", ptr, true);
		if (ipv6_addr)
			free(ipv6_addr);
		if (sub_group)
			print_3fields(save_ptr, stat->nr, fields, "min", "max", "avg");
		else
			print_fields(save_ptr, stat->nr, fields);			
		
		conn = conn->next;
	}
	print_list_end(false);
}

static void print_current_reqstat(char * name, int vnr, struct connection *conn)
{
	char *data = NULL;
	struct title_field req_stat = {"requests", 6};
	struct title_field al_stat = {"al_update", 3};
	
	// req 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 al 0 0 0 0 0 0 0 0 0 0 cent79_03 0 0 0 0 0 0 0 0 0 cent79_02 0 0 0 0 0 0 0 0 0
	struct perf_field req_fields[] = { // min, max, avg
		{"before_queue", "usec"},
		{"before_al_begin", "usec"},
		{"in_actlog", "usec"},
		{"submit", "usec"},
		{"bio_endio", "usec"},
		{"destroy", "usec"},
	};
	struct perf_field al_fields[] = { // min, max, avg
		{"before_bm_write", "usec"},
		{"after_bm_write", "usec"},
		{"after_sync_page", "usec"},
	};

	
	struct title_field peer_stat = {"peer", 3};
	struct perf_field peer_fields[] = { // min, max, avg
		{"pre_send", "usec"},
		{"acked", "usec"},
		{"net_done", "usec"},
	};

	data = read_last_line(name, vnr, (char *)"request");
	
	if (data) {
		char *ptr, *save_ptr;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		print_head("reqstat");
		strtok_r(NULL, " ", &save_ptr); // req
		print_data("count", strtok_r(NULL, " ", &save_ptr), true); // req count
		print_min_max_avg_group(&save_ptr, &req_stat, req_fields);
		strtok_r(NULL, " ", &save_ptr); // al
		print_data("count", strtok_r(NULL, " ", &save_ptr), true); // al count
		print_min_max_avg_group(&save_ptr, &al_stat, al_fields);
		if (json)
			print_peer_json(conn, "connections", &save_ptr, &peer_stat, peer_fields, true);
		else 
			print_peer(conn, NULL, &save_ptr, &peer_stat, peer_fields, true);
		print_end(true);

		free(data);
	}
}

static void print_current_peer_reqstat(char * name, int vnr, struct connection *conn)
{
	char *data = NULL;
	struct title_field stat = {"peer", 3};
	
	// cent79_03 0 0 0 0 0 0 0 0 0 0 cent79_02 0 0 0 0 0 0 0 0 0 0 
	struct perf_field fields[] = { // min, max, avg
		{"submit", "usec"},
		{"bio_endio", "usec"},
		{"destroy", "usec"},
	};

	data = read_last_line(name, vnr, (char *)"peer_request");
	
	if (data) {
		char *ptr, *save_ptr;
		bool first_conn = true;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		print_list_head("peer_reqstat");
		while (conn) {
			char *ipv6_addr = NULL;
			ptr = strtok_r(NULL, " ", &save_ptr);
			if (ptr == NULL)
			 	break;
			if (json) {
				if (first_conn) 
					first_conn = false;
				else  
					print_list_next();
			}
			else {
				if (is_ipv6(ptr)) {
					ipv6_addr = get_ipv6_name(&save_ptr);
					ptr = ipv6_addr;
				}
				printI("%s %s {\n", stat.name, ptr);
				++indent;
			}
			if (json) {
				if (is_ipv6(ptr)) {
					ipv6_addr = get_ipv6_name(&save_ptr);
					ptr = ipv6_addr;
				}
				print_data("peer", ptr, true);
			}
			if (ipv6_addr)
				free(ipv6_addr);
			print_data("count", strtok_r(NULL, " ", &save_ptr), true); // peer_req count
			print_3fields(&save_ptr, stat.nr, fields, "min", "max", "avg");
			
			if (!json)
				print_end(false);
			
			conn = conn->next;
		}
		print_list_end(true);
		free(data);
	}
}

static void print_current_alstat(char * name, int vnr)
{
	char *data = NULL;
	struct title_field al_stat = {"al_stat", 18};
	struct title_field err_stat = {"error", 5};

	// 6001 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 64 0 0 0 0 0
	struct perf_field al_ext_fields = {"al-extents", NULL};
	struct perf_field al_used_fields = {"al_used", NULL}; // cur, max
	struct perf_field al_cur_total_fields[] = { // cur, total
		{"hits", NULL},
		{"misses", NULL},
		{"starving", NULL},
		{"locked", NULL},
		{"changed", NULL},
	};
	struct perf_field al_wait_fields = {"al_wait_retry", NULL}; // cur, total, max
	struct perf_field pending_changes_fields = {"pending_changes", NULL}; // cur, max

	struct perf_field err_fields[] = {
		{"nobufs_starving", NULL},
		{"nobufs_pending_slot", NULL},
		{"nobufs_used_slot", NULL},
		{"busy", NULL},
		{"wouldblock", NULL},
		{"flags", NULL},
	};

	data = read_last_line(name, vnr, (char *)"al_stat");
	
	if (data) {
		char *ptr, *save_ptr;
		
        ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		print_head(al_stat.name);
		print_data(al_ext_fields.name, strtok_r(NULL, " ", &save_ptr), true);
		print_2fields(&save_ptr, 1, &al_used_fields, "cur", "max");
		if (json)
			putchar(',');
		print_2fields(&save_ptr, 5, al_cur_total_fields, "cur", "total");
		if (json)
			putchar(',');
		print_3fields(&save_ptr, 1, &al_wait_fields, "cur", "total", "max");
		if (json)
			putchar(',');
		print_2fields(&save_ptr, 1, &pending_changes_fields, "cur", "max");
		if (json)
			putchar(',');
		print_group(&save_ptr, &err_stat, err_fields, true);
		if (!strlen(save_ptr)) {
			print_data("flags", (char *)"NONE", false);
		} else {
			ptr = strtok_r(NULL, " ", &save_ptr);
			if (json)
				printf("\"flags\":\"%s", ptr);
			else
				printI("flags\t%s", ptr);		
			while((ptr = strtok_r(NULL, " ", &save_ptr)) != NULL) {
				printf(",%s", ptr);
			}
			if (json)
				printf("\"");
			else
				printf(";\n");
		}
		print_end(true);

		free(data);
	}
}

static void print_current_network(char * name, struct connection *conn)
{
	char *data = NULL;
	struct title_field stat = {"peer", 2};

	// cent79_02 0 0 cent79_03 0 0
	struct perf_field fields[] = {
		{"send", "byte/second"},
		{"recv", "byte/second"},
	};

	data = read_last_line(name, -1, (char *)"network");
	
	if (data) {
		char *ptr, *save_ptr;

		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		if (json) {
			print_peer_json(conn, "network", &save_ptr, &stat, fields, false);
			putchar(',');
		}
		else
			print_peer(conn, "network", &save_ptr, &stat, fields, false);
		
		free(data);
	}
}

static void print_current_resync_ratio(char * name, int vnr, struct connection *conn)
{
	char *data = NULL;
	struct title_field stat = {"peer", 3};

	// cent79_02 0 0 0 0 0 0 cent79_03 0 0 0 0 0 0 
	struct perf_field fields[] = {
		{"replication", "byte/second"},
		{"resync", "byte/second"},
		{"resync_ratio", "percent"},
	};

	data = read_last_line(name, vnr, (char *)"resync_ratio");
	
	if (data) {
		char *ptr, *save_ptr;
		
		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}

		if (json) {
			print_peer_json(conn, "resync_ratio", &save_ptr, &stat, fields, false);
			putchar(',');
		}
		else
			print_peer(conn, "resync_ratio", &save_ptr, &stat, fields, false);
	
		free(data);
	}
}

static bool is_peer(char *ptr, struct connection *conn)
{
	while (conn) {
		if (!strcmp(ptr, get_peer_name(conn->name)))
			return true;
		conn = conn->next;
	}
	return false;
}

static void print_current_sendbuf(char * name, struct connection *conn)
{
	char *data = NULL;

	// cent79_02 ap 0 0 rs 0 0 no send buffer cent79_03 ap 0 0 rs 0 0 no send buffer
	// cent79_02 ap 0 0 rs 0 0 data 20971520 0 control 5242880 0 cent79_03 ap 0 0 rs 0 0 data 20971520 0 control 5242880 0
	struct title_field in_flight_stat[] = {
		{"ap_in_flight", 2},
		{"rs_in_flight", 2},
	};

	struct title_field stream_stat[] = {
		{"data_stream", 2},
		{"control_stream", 2},
	};
	struct perf_field stream_fields[] = {
		{"size", "bytes"},
		{"used", "bytes"},
	};

	struct perf_field packet_fields[] = {
		{"count", NULL},
		{"size", "bytes"},
	};

	data = read_last_line(name, -1, (char *)"send_buffer");
	
	if (data) {
		char *ptr, *save_ptr;
		bool first_conn = true;

		ptr = strtok_r(data, " ", &save_ptr);
		if (!strlen(g_timestamp)) {
#ifdef _WIN
			strcpy_s(g_timestamp, sizeof(g_timestamp), ptr);
#else
			strcpy(g_timestamp, ptr);
#endif
		}


		print_list_head("sendbuf");		
		ptr = strtok_r(NULL, " ", &save_ptr);
		while (strlen(save_ptr)) {
			long long fill = 0;
			int highwater = 0;
			int i, j;
			bool no_buffer = false;
			bool packet_data = false;
			char *ipv6_addr = NULL;

			if (first_conn)
				first_conn = false;
			else
				print_list_next();
			
		
			if (is_ipv6(ptr)) {
				ipv6_addr = get_ipv6_name(&save_ptr);
				ptr = ipv6_addr;
			}
			if (json)
				print_data("peer", ptr, true);
			else {
				printI("peer %s {\n", ptr);
				++indent;
			}
			if (ipv6_addr)
				free(ipv6_addr);
			for (i = 0; i < 2; i++) {
				print_head(in_flight_stat[i].name);
				strtok_r(NULL, " ", &save_ptr); // type
				// size
				ptr = strtok_r(NULL, " ", &save_ptr);
				print_data_unit("size", ptr, "bytes", true);
				fill += atoll(ptr);
				// cnt
				ptr = strtok_r(NULL, " ", &save_ptr);
				print_data_unit("count", ptr, NULL, false);
				highwater += atoi(ptr);
				print_end(true);
			}

			print_digit("highwater", highwater, true);
			print_digit_unit("fill", fill, "bytes", true);
			
			while((ptr = strtok_r(NULL, " ", &save_ptr)) != NULL) {

				if (is_ipv6(ptr))
					ptr = strtok_r(NULL, " ", &save_ptr);

				if (is_peer(ptr, conn)) {
					if (packet_data) {
						packet_data = false;
						print_list_end(false);
					}
					break;
				}

				if (!strcmp(ptr, "control")) {
					if (packet_data) {
						packet_data = false;
						print_list_end(false);
					}
					print_end(true);
				}

				if (!strcmp(ptr, "data") || !strcmp(ptr, "control")) {
					char stream[15] = {0,};
#ifdef _WIN
					sprintf_s(stream, sizeof(stream), "%s_stream", ptr);
#else
					sprintf(stream, "%s_stream", ptr);
#endif
					print_head(stream);
					print_fields(&save_ptr, 2, stream_fields);
				} else if (!strcmp(ptr, "no")) {
					/* no send buffer */
					strtok_r(NULL, " ", &save_ptr);
					strtok_r(NULL, " ", &save_ptr);
					no_buffer = true;

					continue;
				} else {
					if (!packet_data) {
						if (json)
							putchar(',');
						print_list_head("packet");
						packet_data = true;
					}
					else {
						print_list_next();
						if (!json)
							print_list_head("packet");
					}
					print_data("name", ptr, true);
					print_fields(&save_ptr, 2, packet_fields);
				}
			}

			if (no_buffer) {
				for (i = 0; i < 2; i++) {
					print_head(stream_stat[i].name);
					for(j = 0; j <2; j++) {
						if (json && j)
							putchar(',');
						print_data_unit(stream_fields[j].name, (char *)"0", stream_fields[j].unit, false);
					}
					print_end(!i);
				}
			} else {
				if (packet_data) 
					print_list_end(false);
				print_end(false);
			}
		}
	
		if (!json)
			print_end(false);
		print_list_end(true);
		free(data);
	}
}

// BSR-948
void print_current(struct resource *res, int type_flags, bool json_print)
{
	bool first_print = true;
	indent = 0;
	json = json_print;
	memset(g_timestamp, 0, sizeof(g_timestamp));

	printf("{");
	if (!json) {
		printf("\n");
		++indent;
	}
	if (type_flags & (1 << MEMORY)) {
		first_print = false;
		print_current_memstat();
	}

	if (type_flags != (1 << MEMORY)) {
		bool first_res = true;
		while (res) {
			struct volume *vol = res->vol;
			if (json) {
				if (first_res) {
					first_res = false;
					if (!first_print)
						putchar(',');
					printf("\"resource\":[{");
				}
				else
					printf("},{");
				printf("\"name\":\"%s\",", res->name);
			}
			else {
				printI("resource %s {\n", res->name);
				++indent;
			}
			memset(g_timestamp, 0, sizeof(g_timestamp));

			if (type_flags & ~((1 << NETWORK_SPEED) | (1 << SEND_BUF))) {
				bool first_vnr = true;
				while (vol) {
					if (json) {
						if (first_vnr) {
							first_vnr = false;
							printf("\"devices\":[{");
						}
						else
							printf("},{");
					}
					else {
						printI("vnr %d {\n", vol->vnr);
						++indent;
					}

					if (type_flags & (1 << IO_STAT))
						print_current_iostat(res->name, vol->vnr);
					if (type_flags & (1 << IO_COMPLETE))
						print_current_ioclat(res->name, vol->vnr);
					if (type_flags & (1 << IO_PENDING))
						print_current_io_pending(res->name, vol->vnr);
					if (type_flags & (1 << REQUEST))
						print_current_reqstat(res->name, vol->vnr, res->conn);
					if (type_flags & (1 << PEER_REQUEST))
						print_current_peer_reqstat(res->name, vol->vnr, res->conn);
					if (type_flags & (1 << AL_STAT))
						print_current_alstat(res->name, vol->vnr);
					if (type_flags & (1 << RESYNC_RATIO))
						print_current_resync_ratio(res->name, vol->vnr, res->conn);

					if (json) {
						printf("\"vnr\":\"%d\"", vol->vnr);
					}
					else {
						--indent;
						printI("}\n");
					}
					vol = vol->next;
				}
				
				if (!first_vnr) {
					printf("}],");
				}
			}

			
			if (type_flags & (1 << NETWORK_SPEED))
				print_current_network(res->name, res->conn);
			if (type_flags & (1 << SEND_BUF))
				print_current_sendbuf(res->name, res->conn);

			res = res->next;

			print_timestamp();
			if (!json) {
				--indent;
				printI("}\n");
			}
		}

		if (!first_res)
			printf("}]");
	}

	if (!json)
		--indent;
	printI("}\n");

}
