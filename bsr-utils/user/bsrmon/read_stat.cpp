#include "bsrmon.h"
#include "read_stat.h"
#include "module_debug.h"
#ifdef _WIN
#include <share.h>
#else //_LIN
#include <unistd.h>
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

void set_min_max(perf_stat *stat, unsigned int min, unsigned int max)
{
	if (!stat->max)
		stat->max = max;
	else if (stat->max < max) 
		stat->max = max;
	
	if (!stat->min)
		stat->min = min;
	else if (stat->min > min)
		stat->min = min;
}

void set_min_max_val(perf_stat *stat, unsigned long long val)
{
	/* Excluded from statistics if:
		1. Current value is 0
		2. Previous value is 0
		3. Consecutive duplicate values
	*/
	if (val == 0 || stat->priv == 0 || (stat->priv == val && stat->duplicate)) {
		stat->priv = val;
		return;
	} else if (!stat->max){
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
	stat->sum += val;
	stat->cnt++;

}

void set_min_max_allval(perf_stat *stat, unsigned int val)
{
	/* all data statistics */
	if (!stat->max){
		stat->max = stat->min = val;
	} else if (stat->max < val) 
		stat->max = val;
	else if (stat->min > val)
		stat->min = val;

	stat->priv = val;
	stat->sum += val;
	stat->cnt++;

}

void set_min_max_fp(FILE *fp, perf_stat *stat)
{
	unsigned long t_min = 0, t_max = 0, t_avg = 0;
	fscanf_ex(fp, "%lu %lu %lu", &t_min, &t_max, &t_avg);

	
	/* Excluded from statistics if:
		1. Current value is 0
		2. Previous value is 0
		3. Consecutive duplicate values
	*/
	if (t_avg == 0 || stat->priv == 0 || (stat->priv == t_avg && stat->duplicate)) {
		stat->priv = t_avg;
		return;
	}
	if (t_max > 0) 
		set_min_max(stat, t_min, t_max);

	if (stat->priv == t_avg)
		stat->duplicate = true;
	else 
		stat->duplicate = false;

	stat->priv = t_avg;
	stat->sum += t_avg;
	stat->cnt ++;
}

unsigned int read_val_fp(FILE *fp)
{
	unsigned int val = 0;
	fscanf_ex(fp, "%u", &val);
	return val;
}

void print_stat(const char * name, perf_stat *s)
{
	printf("%s: min=%llu, max=%llu, avg=%llu, samples=%lu\n", 
			name, s->min, s->max, stat_avg(s->sum, s->cnt), s->cnt);
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
	if (tf->date && strncmp(save_t, tf->date, strlen(tf->date))) {
		return 0;
	}

	/* compare hh:mm:ss (escape yyyy-mm-dd_) */		
	if ((tf->start_time.use && (datecmp(&save_t[11], &tf->start_time) < 0)) ||
		(tf->end_time.use && (datecmp(&save_t[11], &tf->end_time) > 0))) {
		
		return 0;
	}
	
	return 1;

}

/**
 * Reports statistics of io performance.
 */
void read_io_stat_work(char *path, struct time_filter *tf)
{
	FILE *fp;
	char line[256] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,};
	unsigned long r_iops, r_ios, r_kbs, r_kb, w_iops, w_ios, w_kbs, w_kb;
	struct io_perf_stat read_io, write_io;
	int i = 0;
	bool do_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];

	memset(&read_io, 0, sizeof(struct io_perf_stat));
	memset(&write_io, 0, sizeof(struct io_perf_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	if (fopen_s(&fp, path, "r") != 0)
		return;

	while (!feof(fp)) {
		if (fgets(line, sizeof(line), fp) != NULL) {
			/* time riops rios rkbs rkb wiops wios rkbs rkb */
	#ifdef _WIN
			i = sscanf_s(line, "%s %lu %lu %lu %lu %lu %lu %lu %lu",
				save_t, sizeof(save_t), &r_iops, &r_ios, &r_kbs, &r_kb, &w_iops, &w_ios, &w_kbs, &w_kb);
	#else // _LIN
			i = sscanf(line, "%s %lu %lu %lu %lu %lu %lu %lu %lu",
				save_t, &r_iops, &r_ios, &r_kbs, &r_kb, &w_iops, &w_ios, &w_kbs, &w_kb);
	#endif
			if (i != 9)
				continue;

			if (strlen(start_t) == 0)
            	sprintf_ex(start_t, "%s", save_t);

			if (check_record_time(save_t, tf)) {
				if(!do_collect) {
					do_collect = true;
					do_print = false;
					sprintf_ex(filter_s, "%s", save_t);
				}
				
				set_min_max_val(&read_io.iops, r_iops);
				read_io.ios += r_ios;
				set_min_max_val(&read_io.kbs, r_kbs);
				read_io.kb += r_kb;
				set_min_max_val(&write_io.iops, w_iops);
				write_io.ios += w_ios;
				set_min_max_val(&write_io.kbs, w_kbs);
				write_io.kb += w_kb;
				sprintf_ex(filter_e, "%s", save_t);

				continue;
			}
			
		} 

		if (do_collect) {
			do_collect = false;
			do_print = true;
		}

		if (do_print) {
			printf(" Run: %s - %s\n", filter_s, filter_e);
			printf("  read : ios=%llu, bw=%llukbyte\n", read_io.ios, read_io.kb);
			print_stat("    IOPS        ", &read_io.iops);
			print_stat("    BW (kbyte/s)", &read_io.kbs);
			printf("  write: ios=%llu, bw=%llukbyte\n", write_io.ios, write_io.kb);
			print_stat("    IOPS        ", &write_io.iops);
			print_stat("    BW (kbyte/s)", &write_io.kbs);


			memset(&read_io, 0, sizeof(struct io_perf_stat));
			memset(&write_io, 0, sizeof(struct io_perf_stat));
			memset(&filter_s, 0, 64);
			memset(&filter_e, 0, 64);
			do_print = false;
			find_date = true;
		}
	
	}

	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

/**
 * Reports statistics of io_complete_latency
 */
void read_io_complete_work(char *path, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,};
	struct perf_stat local, master;
	bool do_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];

	memset(&local, 0, sizeof(struct perf_stat));
	memset(&master, 0, sizeof(struct perf_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	if (fopen_s(&fp, path, "r") != 0)
		return;

	while (!feof(fp)) {
		if (EOF != collection_time(fp, save_t)) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (strlen(start_t) == 0)
            	sprintf_ex(start_t, "%s", save_t);

			if (check_record_time(save_t, tf)) {
				if(!do_collect) {
					do_collect = true;
					do_print = false;
					sprintf_ex(filter_s, "%s", save_t);
				}
				
				/* local_min local_max local_avg master_min master_max master_avg */
				set_min_max_fp(fp, &local);
				set_min_max_fp(fp, &master);
				sprintf_ex(filter_e, "%s", save_t);

				fscanf_ex(fp, "%*[^\n]");
				continue;

			}
			fscanf_ex(fp, "%*[^\n]");
		}
		
		if (do_collect) {
			do_collect = false;
			do_print = true;
		}

		if (do_print) {	
			printf(" Run: %s - %s\n", filter_s, filter_e);
			print_stat("  local clat  (usec)", &local);
			print_stat("  master clat (usec)", &master);

			memset(&local, 0, sizeof(struct perf_stat));
			memset(&master, 0, sizeof(struct perf_stat));
			do_print = false;
			find_date = true;
		}
		
	}

	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}

void read_peer_ack_stat(FILE *fp, char * peer_name, struct time_filter *tf, int start_offset, int end_offset)
{
	char tok[64] = {0,};
	char save_t[64] = {0,}, filter_s[64] = {0,}, filter_e[64] = {0,}; 
	struct perf_stat pre_send, acked, net_done;
	bool do_collect = false;
	bool do_print = false;

	memset(&pre_send, 0, sizeof(struct perf_stat));
	memset(&acked, 0, sizeof(struct perf_stat));
	memset(&net_done, 0, sizeof(struct perf_stat));

	fseek(fp, start_offset, SEEK_SET);

	while (!feof(fp)) {
		if ((ftell(fp) < end_offset) &&
			(EOF != collection_time(fp, save_t))) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (check_record_time(save_t, tf)) {
				if (!do_collect) {
					do_collect = true;
					do_print = false;
					sprintf_ex(filter_s, "%s", save_t);
				}

				/* peer_name */
				while (EOF != fscanf_str(fp, "%s", tok)) {
					if (tok != NULL && strlen(tok) !=0 && strcmp(tok, peer_name))
						continue;
					
					set_min_max_fp(fp, &pre_send);
					set_min_max_fp(fp, &acked);
					set_min_max_fp(fp, &net_done);	
					sprintf_ex(filter_e, "%s", save_t);
					break;
				}
				
				fscanf_ex(fp, "%*[^\n]");
				continue;
				
			}
			fscanf_ex(fp, "%*[^\n]");
		}

		if (do_collect) {
			do_collect = false;
			do_print = true;
		}
		if (do_print) {
			printf("  PEER %s:\n", peer_name);
			print_stat("    pre_send (usec)", &pre_send);
			print_stat("    acked    (usec)", &acked);
			print_stat("    net_done (usec)", &net_done);

			memset(&pre_send, 0, sizeof(struct perf_stat));
			memset(&acked, 0, sizeof(struct perf_stat));
			memset(&net_done, 0, sizeof(struct perf_stat));
			do_print = false;
		}

		if (ftell(fp) >= end_offset)
			break;
	}
}

/**
 * Reports statistics of request performance.
 */
void read_req_stat_work(char *path, char *resname, struct time_filter *tf)
{
	FILE *fp, *pipe;
	char cmd[128] = {0,};
	char peer_name[64] = {0,};
	char tok[64] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	unsigned int t_cnt = 0;
	unsigned long long req_total = 0, al_total= 0;
	struct req_perf_stat req_stat;
	bool do_collect = false;
	bool do_print = false;
	bool find_date = false;
	long read_offset, start_offset, end_offset;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 

	memset(&req_stat, 0, sizeof(struct req_perf_stat));

	if (fopen_s(&fp, path, "r") != 0)
		return;

	// get file size
	start_offset = 0;
	fseek(fp, 0, SEEK_END);
	end_offset = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	while (!feof(fp)) {
		if ((ftell(fp) < end_offset) &&
			(EOF != collection_time(fp, save_t))) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (strlen(start_t) == 0)
            	sprintf_ex(start_t, "%s", save_t);
			if (check_record_time(save_t, tf)) {
				if(!do_collect) {
					do_collect = true;
					do_print = false;
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
				
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			fscanf_ex(fp, "%*[^\n]");	
		}

		if (do_collect) {
			do_collect = false;
			do_print = true;
		}

		if (do_print) {
			
			find_date = true;

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
			
			read_offset = ftell(fp);
			/* read peer stat */	
			sprintf_ex(cmd, "bsradm sh-peer-node-name %s", resname);
			if ((pipe = popen(cmd, "r")) != NULL) {
				while (fgets(peer_name, 64, pipe) != NULL) {
					*(peer_name + (strlen(peer_name) - 1)) = 0;

					read_peer_ack_stat(fp, peer_name, tf, start_offset, read_offset);
				}
				pclose(pipe);
			
			}
			
			memset(&req_stat, 0, sizeof(struct req_perf_stat));
			do_print = false;
			fseek(fp, read_offset, SEEK_SET);
			start_offset = read_offset;
		}
		
		if (ftell(fp) >= end_offset)
			break;
	}

	
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);
}


void read_peer_req_stat(FILE *fp, char * peer_name, struct time_filter *tf, int end_offset, bool print_runtime)
{
	char tok[64] = {0,};
	unsigned int t_cnt = 0;
	unsigned long long peer_req_total = 0;
	char save_t[64] = {0,}, filter_s[64] = {0,}, filter_e[64] = {0,}; 
	struct perf_stat submit, bio_endio, destroy;

	memset(&submit, 0, sizeof(struct perf_stat));
	memset(&bio_endio, 0, sizeof(struct perf_stat));
	memset(&destroy, 0, sizeof(struct perf_stat));

	while (!feof(fp)) {
		if ((ftell(fp) < end_offset) && (EOF != collection_time(fp, save_t))) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (check_record_time(save_t, tf)) {
				if (strlen(filter_s) == 0)
					sprintf_ex(filter_s, "%s", save_t);

				/* peer_name */
				while (EOF != fscanf_str(fp, "%s", tok)) {
					if (tok != NULL && strlen(tok) !=0 && 
						strcmp(tok, peer_name)) {
						continue;
					}

					/* peer request cnt */
					fscanf_ex(fp, "%u", &t_cnt);

					peer_req_total += t_cnt;
					set_min_max_fp(fp, &submit);
					set_min_max_fp(fp, &bio_endio);
					set_min_max_fp(fp, &destroy);

					fscanf_ex(fp, "%*[^\n]");	
					break;
				}

				sprintf_ex(filter_e, "%s", save_t);
				continue;
			} else {
				fscanf_ex(fp, "%*[^\n]");	
				break;
			}

		}
		if (ftell(fp) >= end_offset)
			break;
	}

	if (print_runtime)
		printf(" Run: %s - %s\n", filter_s, filter_e);
	printf("  PEER %s:\n", peer_name);
	printf("    peer requests : total=%llu\n", peer_req_total);
	print_stat("    submit    (usec)", &submit);
	print_stat("    bio_endio (usec)", &bio_endio);
	print_stat("    destroy   (usec)", &destroy);

	
}

// BSR-765 add al stat reporting
void read_al_stat_work(char *path, struct time_filter *tf)
{
	FILE *fp;
	char save_t[64] = { 0, }, start_t[64] = { 0, }, end_t[64] = { 0, };
	unsigned int t_cnt = 0, t_max = 0, t_total = 0, nr_elements = 0;;
	unsigned int all_slot_used_cnt = 0;
	struct al_stat al;
	bool do_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64], filter_e[64];
	bool change_nr = false, print_new_nr = false;


	memset(&al, 0, sizeof(struct al_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	if (fopen_s(&fp, path, "r") != 0)
		return;

	while (!feof(fp)) {
		if (change_nr || (EOF != collection_time(fp, save_t))) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (strlen(start_t) == 0)
				sprintf_ex(start_t, "%s", save_t);

			if (check_record_time(save_t, tf)) {
				if(!do_collect) {
					do_collect = true;
					do_print = false;
					sprintf_ex(filter_s, "%s", save_t);
				}

				/* nr_elements */
				if (!change_nr)
					fscanf_ex(fp, "%u", &nr_elements);
				if (al.nr_elements && (nr_elements != al.nr_elements)) {
					// changed nr_elements, print stat and reset
					do_print = true;
					change_nr = true;
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
					sprintf_ex(filter_e, "%s", save_t);
					continue;

				}
			}
			fscanf_ex(fp, "%*[^\n]");
		} 

		if (do_collect) {
			do_collect = false;
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

			
			sprintf_ex(filter_s, "%s", save_t);
			memset(&al, 0, sizeof(struct al_stat));
			all_slot_used_cnt = 0;

			if (change_nr) {
				al.nr_elements = nr_elements;
				print_new_nr = true;
				change_nr = false;
			}	

			do_print = false;
			find_date = true;
		}
	}

	fclose(fp);


	sprintf_ex(end_t, "%s", save_t);
	if (!find_date)
		printf("  please enter between %s - %s\n", start_t, end_t);

}


// BSR-838
void read_peer_resync_ratio_work(FILE *fp, char * peer_name, struct time_filter *tf, int end_offset, bool print_runtime)
{
	char save_t[64] = { 0, };
	char filter_s[64], filter_e[64];
	struct perf_stat repl_sended, resync_sended, resync_ratio;


	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	memset(&repl_sended, 0, sizeof(struct perf_stat));
	memset(&resync_sended, 0, sizeof(struct perf_stat));
	memset(&resync_ratio, 0, sizeof(struct perf_stat));

	while (!feof(fp)) {
		if ((ftell(fp) < end_offset) &&
			(EOF != collection_time(fp, save_t))) {

			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}

			 if (check_record_time(save_t, tf)) {
				char buf[MAX_BUF_SIZE];
				char *ptr, *save_ptr;

				if (strlen(filter_s) == 0)
					sprintf_ex(filter_s, "%s", save_t);

				if (fgets(buf, sizeof(buf), fp) != NULL) {
					// remove EOL
					*(buf + (strlen(buf) - 1)) = 0;
					/* peer */
					ptr = strtok_r(buf, " ", &save_ptr);
				
					while (ptr) {
						/* replication sended, resync sended, ratio */
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						set_min_max_val(&repl_sended, atoll(ptr));
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						set_min_max_val(&resync_sended, atoll(ptr));
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						set_min_max_val(&resync_ratio, atoll(ptr));
					}
				}

				sprintf_ex(filter_e, "%s", save_t);
				continue;
			}

			fscanf_ex(fp, "%*[^\n]");
			break;

		}

		if (ftell(fp) >= end_offset)
			break;
	}

	if (print_runtime)
		printf(" Run: %s - %s\n", filter_s, filter_e);
	printf("  PEER %s: replication sended=%llubyte/s, resync sended=%llubyte/s, resync ratio=%llu\n", peer_name, stat_avg(repl_sended.sum, repl_sended.cnt), stat_avg(resync_sended.sum, resync_sended.cnt), stat_avg(resync_ratio.sum, resync_ratio.cnt));
}

/**
 * Reports statistics of network performance.
 */
void read_network_stat(FILE *fp, char * peer_name, struct time_filter *tf, int end_offset, bool print_runtime)
{
	struct perf_stat send, recv;
	char save_t[64] = {0,}, filter_s[64] = {0,}, filter_e[64] = {0,}; 

	memset(&send, 0, sizeof(struct perf_stat));
	memset(&recv, 0, sizeof(struct perf_stat));
	

	while (!feof(fp)) {
		if ((ftell(fp) < end_offset) &&
			(EOF != collection_time(fp, save_t))) {

			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}

			if (check_record_time(save_t, tf)) {
				char buf[MAX_BUF_SIZE];
				char *ptr, *save_ptr;

				if (strlen(filter_s) == 0)
					sprintf_ex(filter_s, "%s", save_t);

				if (fgets(buf, sizeof(buf), fp) != NULL) {
					// remove EOL
					*(buf + (strlen(buf) - 1)) = 0;
					/* peer */
					ptr = strtok_r(buf, " ", &save_ptr);
					
					while (ptr) {
						if (strcmp(ptr, peer_name)) {
							// next peer
							ptr = strtok_r(NULL, " ", &save_ptr);
							continue;
						}

						/* send_byte/s recv_byte/s */
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						set_min_max_val(&send, atoi(ptr));
						ptr = strtok_r(NULL, " ", &save_ptr);
						if (!ptr)
							break;
						set_min_max_val(&recv, atoi(ptr));
						break;
					}
				}

				sprintf_ex(filter_e, "%s", save_t);
				continue;
			} 
			
			fscanf_ex(fp, "%*[^\n]");	
			break;

		}

		if (ftell(fp) >= end_offset)
			break;
	}

	if (print_runtime)
		printf(" Run: %s - %s\n", filter_s, filter_e);
	printf("  PEER %s: send=%llubyte/s, receive=%llubyte/s\n", peer_name,  stat_avg(send.sum, send.cnt), stat_avg(recv.sum, recv.cnt));
	print_stat("    send (byte/s)", &send);
	print_stat("    recv (byte/s)", &recv);
}

/**
 * Reports statistics of sendbuf performance.
 */
void read_sendbuf_stat(FILE *fp, char * peer_name, struct time_filter *tf, int end_offset, bool print_runtime)
{
	
	long long t_size = 0, t_used = 0;
	long long d_buf_size, c_buf_size;
	struct perf_stat data, control;
	struct perf_stat total_in_flight, highwater, ap_size, ap_cnt, rs_size, rs_cnt;
	char *read_name;
	char *type;
	char save_t[64] = {0,}, filter_s[64], filter_e[64]; 
	bool change_bufsize = false;
	bool do_reset = false;

reset:
	d_buf_size = 0;
	c_buf_size = 0;
	memset(&data, 0, sizeof(struct perf_stat));
	memset(&control, 0, sizeof(struct perf_stat));
	memset(&total_in_flight, 0, sizeof(struct perf_stat));
	memset(&highwater, 0, sizeof(struct perf_stat));
	memset(&ap_size, 0, sizeof(struct perf_stat));
	memset(&ap_cnt, 0, sizeof(struct perf_stat));
	memset(&rs_size, 0, sizeof(struct perf_stat));
	memset(&rs_cnt, 0, sizeof(struct perf_stat));
	memset(&filter_s, 0, 64);
	memset(&filter_e, 0, 64);

	while (!feof(fp)) {
		if (!do_reset && (ftell(fp) < end_offset) &&
			(EOF != collection_time(fp, save_t))) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (check_record_time(save_t, tf)) {
				char buf[MAX_BUF_SIZE];
				char *save_ptr;

				if (strlen(filter_s) == 0)
					sprintf_ex(filter_s, "%s", save_t);

				if (fgets(buf, sizeof(buf), fp) != NULL) {
					// remove EOL
					*(buf + (strlen(buf) - 1)) = 0;
					/* peer */
					read_name = strtok_r(buf, " ", &save_ptr);
					
					while (read_name) {
						
						if (strcmp(read_name, peer_name)) {
							// next peer
							read_name = strtok_r(NULL, " ", &save_ptr);
							continue;
						}

						type = strtok_r(NULL, " ", &save_ptr);
						
						if (type == NULL || strlen(type) == 0) {
							break;
						}

						// BSR-839 print highwater
						/* ap_in_flight size cnt */
						if (!strcmp(type, "ap")) {
							long long ap_s = 0, rs_s = 0;
							int ap_c = 0, rs_c = 0;

							ap_s = atoll(strtok_r(NULL, " ", &save_ptr));
							ap_c = atoi(strtok_r(NULL, " ", &save_ptr));
							
							
							/* rs_in_flight size cnt */
							type = strtok_r(NULL, " ", &save_ptr);
							if (strcmp(type, "rs"))
								continue;
							rs_s = atoll(strtok_r(NULL, " ", &save_ptr));
							rs_c = atoi(strtok_r(NULL, " ", &save_ptr));
							
							set_min_max_val(&ap_size, ap_s);
							set_min_max_val(&ap_cnt, ap_c);
							set_min_max_val(&rs_size, rs_s);
							set_min_max_val(&rs_cnt, rs_c);

							set_min_max_val(&total_in_flight, ap_s + rs_s);
							set_min_max_val(&highwater, ap_c + rs_c);

							type = strtok_r(NULL, " ", &save_ptr);
						}
							
						if (!strcmp(type, "no")) {
							if (d_buf_size != 0) {
								d_buf_size = c_buf_size = 0;
								memset(&data, 0, sizeof(struct perf_stat));
								memset(&control, 0, sizeof(struct perf_stat));
							}
							break;
						}

						/* datasock size used */
						t_size = atoll(strtok_r(NULL, " ", &save_ptr));
						t_used = atoll(strtok_r(NULL, " ", &save_ptr));

						if (!strcmp(type, "data")) {
							if (d_buf_size == 0) {
								d_buf_size = t_size;
							} 
							else if (d_buf_size != t_size) {
								do_reset = true;
								break;
							}
							
							set_min_max_val(&data, t_used);
							
						} 
						else 
							break;

						while ((type = strtok_r(NULL, " ", &save_ptr)) != NULL) {
							/* control sock */
							if (!strcmp(type, "control")) {
								/* size used */
								t_size = atoll(strtok_r(NULL, " ", &save_ptr));
								t_used = atoll(strtok_r(NULL, " ", &save_ptr));
								if (c_buf_size == 0 || c_buf_size != t_size) {
									c_buf_size = t_size;
									memset(&control, 0, sizeof(struct perf_stat));
								}
								
								set_min_max_val(&control, t_used);
								break;
							} else {
								// skip packet
								strtok_r(NULL, " ", &save_ptr);
								strtok_r(NULL, " ", &save_ptr);
							}
						}
						
						break;
					}
				}
				sprintf_ex(filter_e, "%s", save_t);

				if (do_reset)
					break;

				continue;
			} 
			
			fscanf_ex(fp, "%*[^\n]");
			break;

		}


		if (ftell(fp) >= end_offset)
			break;
	}

	if (change_bufsize) {
		printf(" -> %s send buffer size changed\n", peer_name);
		printf(" Run: %s - %s\n", filter_s, filter_e);
		change_bufsize = false;
	} else  {
		if (print_runtime || do_reset)
			printf(" Run: %s - %s\n", filter_s, filter_e);
	}	
	printf("  PEER %s: data stream size=%lldbyte, control stream size=%lldbyte\n", peer_name, d_buf_size, c_buf_size);
	print_stat("    data-used (bytes)", &data);
	print_stat("    cntl-used (bytes)", &control);
	// BSR-839 print highwater
	print_stat("    highwater", &highwater);
	print_stat("    fill (bytes)", &total_in_flight);
	print_stat("       ap_in_flight (bytes)", &ap_size);
	print_stat("                      (cnt)", &ap_cnt);
	print_stat("       rs_in_flight (bytes)", &rs_size);
	print_stat("                      (cnt)", &rs_cnt);

	if (do_reset) {
		do_reset = false;
		change_bufsize = true;
		goto reset;
	}

}


void read_peer_stat_work(char *path, char * resname, int type, struct time_filter *tf)
{
	FILE *fp, *pipe;
	char save_t[64] = {0,};
	char start_t[64] = {0,}, end_t[64] = {0,};
	bool find_date = false;
	long read_offset, end_offset;
	
	char cmd[128] = {0,};
	char peer_name[64] = {0,};

	if (fopen_s(&fp, path, "r") != 0) 
		return;

	fseek(fp, 0, SEEK_END);
	end_offset = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	while (!feof(fp)) {
		if (EOF != collection_time(fp, save_t)) {
			if (strlen(save_t) != COLLECTION_TIME_LENGTH) {
				fscanf_ex(fp, "%*[^\n]");
				continue;
			}
			if (strlen(start_t) == 0)
				sprintf_ex(start_t, "%s", save_t);
			if (check_record_time(save_t, tf)) {
				bool print_runtime = true;
				
				read_offset = ftell(fp) - (long)strlen(save_t);
				sprintf_ex(cmd, "bsradm sh-peer-node-name %s", resname);
				if ((pipe = popen(cmd, "r")) == NULL)
					return;
				
				while (fgets(peer_name, 64, pipe) != NULL) {
					*(peer_name + (strlen(peer_name) - 1)) = 0;
					fseek(fp, read_offset, SEEK_SET);
					if (type == PEER_REQUEST)
						read_peer_req_stat(fp, peer_name, tf, end_offset, print_runtime);
					else if (type == NETWORK_SPEED)
						read_network_stat(fp, peer_name, tf, end_offset, print_runtime);
					else if (type == SEND_BUF)
						read_sendbuf_stat(fp, peer_name, tf, end_offset, print_runtime);
					else if (type == RESYNC_RATIO) {
						read_peer_resync_ratio_work(fp, peer_name, tf, end_offset, print_runtime);
					}
					if (print_runtime)
						print_runtime = false;
					
				}
				pclose(pipe);

				find_date = true;
			} else {
				fscanf_ex(fp, "%*[^\n]");	
			}

		}
		if (ftell(fp) >= end_offset)
			break;
	}

	fclose(fp);

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
void read_memory_work(char *path, struct time_filter *tf)
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
	bool do_collect = false;
	bool do_print = false;
	bool find_date = false;
	char filter_s[64] = {0,}, filter_e[64] = {0,}; 
	int index = 0;
	
	if (fopen_s(&fp, path, "r") != 0)
		return;

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
				if(!do_collect) {
					do_collect = true;
					do_print = false;
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
						else if (!strcmp(ptr, "bsrservice"))
							temp = &bsrservice_stat;
		#endif
						else
							break;
						
						/* pid - skip */
						ptr = strtok_r(NULL, " ", &save_ptr);
		#ifdef _WIN
						/* WorkingSetSize(bytes) */ 
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->wss, STRING_TO_KBYTE(ptr));
						/* QuotaPagedPoolUsage(bytes) */
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->qpp, STRING_TO_KBYTE(ptr));
						/* QuotaNonPagedPoolUsage(bytes) */
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->qnpp, STRING_TO_KBYTE(ptr));
						/* PagefileUsage(bytes) */
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->pfu, STRING_TO_KBYTE(ptr));
		#else // _LIN	
						/* rsz(kbytes) */ 
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->rsz, atol(ptr));
						/* vsz(kbytes) */
						ptr = strtok_r(NULL, " ", &save_ptr);
						set_min_max_val(&temp->vsz, atol(ptr));
		#endif
						// next app
						ptr = strtok_r(NULL, " ", &save_ptr);
					}
				}

				sprintf_ex(filter_e, "%s", save_t);
				continue;
			}
			fscanf_ex(fp, "%*[^\n]");
		} 

		if (do_collect) {
			do_collect = false;
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

		}
	}

	fclose(fp);

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

			printf("  read : IOPS=%lu (IOs=%lu), BW=%lukb/s (%luKB)\n", 
						r_iops, r_ios, r_kbs, r_kb);
			printf("  write: IOPS=%lu (IOs=%lu), BW=%lukb/s (%luKB)\n", 
						w_iops, w_ios, w_kbs, w_kb);	
			
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
			unsigned long local_min = 0, local_max = 0, local_avg = 0;
			unsigned long master_min = 0, master_max = 0, master_avg = 0;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;

			if (!scroll) 
				clear_screen();
			printf("%s\n", ptr);
			local_min = atol(strtok_r(NULL, " ", &save_ptr));
			local_max = atol(strtok_r(NULL, " ", &save_ptr));
			local_avg = atol(strtok_r(NULL, " ", &save_ptr));
			master_min = atol(strtok_r(NULL, " ", &save_ptr));
			master_max = atol(strtok_r(NULL, " ", &save_ptr));
			master_avg = atol(strtok_r(NULL, " ", &save_ptr));
			printf("  local clat  (usec): min=%lu, max=%lu, avg=%lu\n", local_min, local_max, local_avg);
			printf("  master clat (usec): min=%lu, max=%lu, avg=%lu\n", master_min, master_max, master_avg);
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
				printf("  PEER %s:\n", ptr); // peer_name
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
				printf("  PEER %s:\n", ptr);
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
				printf("  PEER %s:\n", ptr); // peer_name
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
			unsigned long p_size = 0, p_cnt = 0;

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
				
				if (!strcmp(type, "no")) {
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
						p_cnt = atol(ptr);
						p_size = atol(strtok_r(NULL, " ", &save_ptr));
						printf("         [%s]  -  cnt : %lu  size : %lubytes\n", type, p_cnt, p_size);
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
			printf("Total Memory (kbytes) :%lld\n", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
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
				printf(" %-6lld", STRING_TO_KBYTE(strtok_r(NULL, " ", &save_ptr)));
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
				printf("%s\n", ptr); 

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