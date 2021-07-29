#include "bsrmon.h"
#include "read_stat.h"
#ifdef _WIN
#include <share.h>
#else //_LIN
#include <unistd.h>
#endif


// BSR-772
static FILE* open_readonly(char *filename)
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

ULONG_PTR stat_avg(ULONG_PTR sum, unsigned long cnt)
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

void set_min_max_val(perf_stat *stat, unsigned int val)
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
	if (t_min > 0) 
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
	printf("%s: min=%lu, max=%lu, avg=%lu, samples=%lu\n", 
			name, s->min, s->max, stat_avg(s->sum, s->cnt), s->cnt);
}

void print_range(const char * name, struct perf_stat *s, const char * ws)
{
	if ((s->min == s->max) || s->max == 0)
		printf("%s%-23lu%s", name, s->min, ws);
	else {
		char temp[32] = {0,};

		sprintf_ex(temp, "%lu - %lu", s->min, s->max);
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

/**
 * Reports statistics of io performance.
 */
void read_io_stat_work(char *path)
{
	FILE *fp;
	char line[256];
	char save_t[64], start_t[64], end_t[64]; 
	unsigned long r_iops, r_ios, r_kbs, r_kb, w_iops, w_ios, w_kbs, w_kb;
	struct perf_stat read_iops, read_kbs, write_iops, write_kbs;
	int i = 0;

	memset(&read_iops, 0, sizeof(struct perf_stat));
	memset(&read_kbs, 0, sizeof(struct perf_stat));
	memset(&write_iops, 0, sizeof(struct perf_stat));
	memset(&write_kbs, 0, sizeof(struct perf_stat));
	memset(&start_t, 0, 64);
	memset(&end_t, 0, 64);

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
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

		set_min_max_val(&read_iops, r_iops);
		set_min_max_val(&read_kbs, r_kbs);
		set_min_max_val(&write_iops, w_iops);
		set_min_max_val(&write_kbs, w_kbs);
	
	}
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	
	printf(" Run: %s - %s\n", start_t, end_t);
	printf("  read: IOPS=%lu, BW=%lukb/s samples=%lu\n", 
				stat_avg(read_iops.sum, read_iops.cnt), stat_avg(read_kbs.sum, read_kbs.cnt), read_iops.cnt);
	printf("    iops        : min=%lu, max=%lu\n", read_iops.min, read_iops.max);
	printf("    bw (kbyte/s): min=%lu, max=%lu\n", read_kbs.min, read_kbs.max);
	printf(" write: IOPS=%lu, BW=%lukb/s samples=%lu\n", 
				stat_avg(write_iops.sum, write_iops.cnt), stat_avg(write_kbs.sum, write_iops.cnt), write_iops.cnt);
	printf("    iops        : min=%lu, max=%lu\n", write_iops.min, write_iops.max);
	printf("    bw (kbyte/s): min=%lu, max=%lu\n", write_kbs.min, write_kbs.max);	
}

/**
 * Reports statistics of io_complete_latency
 */
void read_io_complete_work(char *path)
{
	FILE *fp;
	char save_t[64], start_t[64], end_t[64];
	struct perf_stat local, master;

	memset(&local, 0, sizeof(struct perf_stat));
	memset(&master, 0, sizeof(struct perf_stat));
	memset(&start_t, 0, 64);
	memset(&end_t, 0, 64);

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);
		
		/* local_min local_max local_avg master_min master_max master_avg */
		set_min_max_fp(fp, &local);
		set_min_max_fp(fp, &master);

		fscanf_ex(fp, "%*[^\n]");	
	}

	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	
	printf(" Run: %s - %s\n", start_t, end_t);
	print_stat("  local clat  (usec)", &local);
	print_stat("  master clat (usec)", &master);
}

/**
 * Reports statistics of request performance.
 */
void read_req_stat_work(char *path)
{
	FILE *fp;
	char tok[64] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	unsigned int t_cnt = 0;
	ULONG_PTR req_total = 0, al_total= 0;
	struct perf_stat before_queue = {0,}, before_al_begin = {0,}, in_actlog = {0,}, pre_submit = {0,}, post_submit = {0,}, destroy = {0,};
	struct perf_stat before_bm_write = {0,}, after_bm_write = {0,}, after_sync_page = {0,};

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);

		/* req cnt */
		fscanf_str(fp, "%s", tok, sizeof(tok));
		fscanf_ex(fp, "%u", &t_cnt);

		if (tok != NULL && strlen(tok) !=0 && 
			strcmp(tok, "req")) {
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}
		
		if (t_cnt > 0) {
			req_total += t_cnt;
			set_min_max_fp(fp, &before_queue);
			set_min_max_fp(fp, &before_al_begin);
			set_min_max_fp(fp, &in_actlog);
			set_min_max_fp(fp, &pre_submit);
			set_min_max_fp(fp, &post_submit);
			set_min_max_fp(fp, &destroy);
		}

		/* al_update cnt*/
		fscanf_str(fp, "%s", tok, sizeof(tok));
		fscanf_ex(fp, "%u", &t_cnt);

		if (tok != NULL && strlen(tok) !=0 && 
			strcmp(tok, "al")) {
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}
		
		if (t_cnt > 0) {
			al_total += t_cnt;
			set_min_max_fp(fp, &before_bm_write);
			set_min_max_fp(fp, &after_bm_write);
			set_min_max_fp(fp, &after_sync_page);
		}	
		fscanf_ex(fp, "%*[^\n]");	
	}
	
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);

	printf(" Run: %s - %s\n", start_t, end_t);
	printf("  requests  : total=%lu\n", req_total);
	print_stat("    before_queue    (usec)", &before_queue);
	print_stat("    before_al_begin (usec)", &before_al_begin);
	print_stat("    in_actlog       (usec)", &in_actlog);
	print_stat("    pre_submit      (usec)", &pre_submit);
	print_stat("    post_submit     (usec)", &post_submit);
	print_stat("    destroy         (usec)", &destroy);
	printf("  al_update : total=%lu\n", al_total);
	print_stat("    before_bm_write (usec)", &before_bm_write);
	print_stat("    after_bm_write  (usec)", &after_bm_write);
	print_stat("    after_sync_page (usec)", &after_sync_page);
}

void read_req_peer_stat_work(char *path, char * peer_name)
{
	FILE *fp;
	char tok[64] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct perf_stat pre_send = {0,}, acked = {0,}, net_done = {0,};

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);

		/* peer_name */
		while (EOF != fscanf_str(fp, "%s", tok, sizeof(tok))) {
			if (tok != NULL && strlen(tok) !=0 && 
				strcmp(tok, peer_name)) {
				continue;
			}

			set_min_max_fp(fp, &pre_send);
			set_min_max_fp(fp, &acked);
			set_min_max_fp(fp, &net_done);
			fscanf_ex(fp, "%*[^\n]");	
			break;
		}
	}
	
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	
	//printf(" Run: %s - %s\n", start_t, end_t);
	printf("  PEER %s:\n", peer_name);
	print_stat("    pre_send (usec)", &pre_send);
	print_stat("    acked    (usec)", &acked);
	print_stat("    net_done (usec)", &net_done);
}

void read_peer_req_stat_work(char *path, char * peer_name, bool print_runtime)
{
	FILE *fp;
	char tok[64] = {0,};
	unsigned int t_cnt = 0;
	ULONG_PTR peer_req_total = 0;
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct perf_stat pre_submit = {0,}, post_submit = {0,}, complete = {0,};

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);

		/* peer_name */
		while (EOF != fscanf_str(fp, "%s", tok, sizeof(tok))) {
			if (tok != NULL && strlen(tok) !=0 && 
				strcmp(tok, peer_name)) {
				continue;
			}

			/* peer request cnt */
			fscanf_ex(fp, "%u", &t_cnt);
			
			if (t_cnt > 0) {
				peer_req_total += t_cnt;
				set_min_max_fp(fp, &pre_submit);
				set_min_max_fp(fp, &post_submit);
				set_min_max_fp(fp, &complete);
			}

			fscanf_ex(fp, "%*[^\n]");	
			break;
		}
	}
	
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	if (print_runtime)
		printf(" Run: %s - %s\n", start_t, end_t);
	printf("  PEER %s:\n", peer_name);
	printf("    peer requests : total=%lu\n", peer_req_total);
	print_stat("    pre_submit  (usec)", &pre_submit);
	print_stat("    post_submit (usec)", &post_submit);
	print_stat("    complete    (usec)", &complete);
}

// BSR-765 add al stat reporting
void read_al_stat_work(char *path)
{
	FILE *fp;
	int n;
	char save_t[64] = {0,}, start_t[64] = {0,}; 
	unsigned int t_cnt = 0, t_max = 0, t_total = 0, nr_elements = 0;;
	unsigned int all_slot_used_cnt = 0;
	struct al_stat al;

	memset(&al, 0, sizeof(struct al_stat));

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	for (;;) {
		n = fscanf_str(fp, "%s", save_t, sizeof(save_t));

		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);

		/* nr_elements */
		fscanf_ex(fp, "%u", &nr_elements);
		if ((n <= 0) || (al.nr_elements && (nr_elements != al.nr_elements))) {
			// changed nr_elements
			// print stat and reset
			printf(" Run: %s - %s\n", start_t, save_t);
			printf("  al_extents : %u\n", al.nr_elements);
			printf("    used     : max=%lu(all_slot_used=%u), avg=%lu\n", 
						al.used.max, all_slot_used_cnt, al.used.sum ? al.used.sum / al.used.cnt : 0);
			printf("    hits     : total=%lu\n", al.hits);
			printf("    misses   : total=%lu\n", al.misses);
			printf("    starving : total=%lu\n", al.starving);
			printf("    locked   : total=%lu\n", al.locked);
			printf("    changed  : total=%lu\n", al.changed);
			printf("    al_wait retry count : max=%lu, total=%lu\n", al.wait.max, al.wait.sum);
			printf("    pending_changes     : max=%lu, total=%lu\n", al.pending.max, al.pending.sum);
			printf("    error : total=%u\n", 
							al.e_starving + al.e_pending + al.e_used + al.e_busy + al.e_wouldblock);
			printf("      NOBUFS - starving     : total=%u\n", al.e_starving);
			printf("             - pending slot : total=%u\n", al.e_pending);
			printf("             - used    slot : total=%u\n", al.e_used);
			printf("      BUSY       : total=%u\n", al.e_busy);
			printf("      WOULDBLOCK : total=%u\n", al.e_wouldblock);

			// EOF
			if (n <= 0)
				break;
			else {
				sprintf_ex(start_t, "%s", save_t);
				memset(&al, 0, sizeof(struct al_stat));
				all_slot_used_cnt = 0;
			}
		}

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
	}

	fclose(fp);

}

/**
 * Reports statistics of network performance.
 */
void read_network_speed_work(char *path, char *peer_name, bool print_runtime)
{
	FILE *fp;
	unsigned int t_send, t_recv;
	struct perf_stat send, recv;
	char read_name[64] = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	memset(&send, 0, sizeof(struct perf_stat));
	memset(&recv, 0, sizeof(struct perf_stat));
	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {	
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);

		/* peer */
		fscanf_str(fp, "%s", read_name, sizeof(read_name));
		if (read_name != NULL && strlen(read_name) !=0 && 
			strcmp(read_name, peer_name)) {
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}

		/* send_byte/s recv_byte/s */
		fscanf_ex(fp, "%u %u", &t_send, &t_recv);

		set_min_max_val(&send, t_send);
		set_min_max_val(&recv, t_recv);
		
		fscanf_ex(fp, "%*[^\n]");
	}

	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);

	if (print_runtime)
		printf(" Run: %s - %s\n", start_t, end_t);
	printf("  PEER %s: send=%lubyte/s, receive=%lubyte/s\n", peer_name,  stat_avg(send.sum, send.cnt), stat_avg(recv.sum, recv.cnt));
	print_stat("    send (byte/s)", &send);
	print_stat("    recv (byte/s)", &recv);
}

/**
 * Reports statistics of sendbuf performance.
 */
void read_sendbuf_work(char *path, char *peer_name, bool print_runtime)
{
	FILE *fp;
	unsigned int t_size = 0, t_used = 0;
	unsigned int d_buf_size = 0, c_buf_size = 0;
	struct perf_stat data, control;
	char read_name[64] = {0,};
	char type[10];
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 

	fp = open_readonly(path);
	if (fp == NULL)
		return;

	memset(&data, 0, sizeof(struct perf_stat));
	memset(&control, 0, sizeof(struct perf_stat));

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);
		fscanf_str(fp, "%s", read_name, sizeof(read_name));
		if (read_name != NULL && strlen(read_name) !=0 &&
			strcmp(read_name, peer_name)) {
			continue;
		}
		
		/* datasock size used */
		fscanf_str(fp, "%s", type, sizeof(type));
		fscanf_ex(fp, "%u %u", &t_size, &t_used);

		if (type == NULL || strlen(type) == 0) {
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}

		if (!strcmp(type, "no")) {
			if (d_buf_size != 0) {
				d_buf_size = c_buf_size = 0;
				memset(&data, 0, sizeof(struct perf_stat));
				memset(&control, 0, sizeof(struct perf_stat));
			}
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}

		if (!strcmp(type, "data")) {
			if (d_buf_size == 0 || d_buf_size != t_size) {
				d_buf_size = t_size;
				memset(&data, 0, sizeof(struct perf_stat));
				memset(&control, 0, sizeof(struct perf_stat));
			}
			
			set_min_max_val(&data, t_used);
			
		} else {
			fscanf_ex(fp, "%*[^\n]");
			continue;
		}
		
		while (EOF != fscanf_str(fp, "%s", type, sizeof(type))) {
			/* control sock */
			if (!strcmp(type, "control")) {
				/* size used */
				fscanf_ex(fp, "%u %u", &t_size, &t_used);
				if (c_buf_size == 0 || c_buf_size != t_size) {
					c_buf_size = t_size;
					memset(&control, 0, sizeof(struct perf_stat));
				}
				
				set_min_max_val(&control, t_used);
				
				fscanf_ex(fp, "%*[^\n]");
				break;
			} else
				fscanf_ex(fp, "%*u %*u");
			
		}
	}

	fclose(fp);
	sprintf_ex(end_t, "%s", save_t);

	if (print_runtime)
		printf(" Run: %s - %s\n", start_t, end_t);
	printf("  PEER %s: data stream size=%ubyte, control stream size=%ubyte\n", peer_name, d_buf_size, c_buf_size);
	print_stat("    data-used (bytes)", &data);
	print_stat("    cntl-used (bytes)", &control);
}


/**
 * Reports statistics of memory performance.
 */
void read_memory_work(char *path)
{
	FILE *fp;
	struct kmem_perf_stat kmem = {0,};
	struct umem_perf_stat bsrmon_stat = {0,};
	struct umem_perf_stat bsradm_stat = {0,};
	struct umem_perf_stat bsrsetup_stat = {0,};
	struct umem_perf_stat bsrmeta_stat = {0,};
#ifdef _WIN
	struct umem_perf_stat bsrservice_stat = {0,};
	unsigned int t_used = 0, np_used = 0, p_use = 0;
#else // _LIN
	unsigned int t_req = 0, t_al = 0, t_bm = 0, t_ee = 0;
#endif
	struct umem_perf_stat *temp = {0,};
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	
	fp = open_readonly(path);
	if (fp == NULL)
		return;

	while (EOF != fscanf_str(fp, "%s", save_t, sizeof(save_t))) {
		char *ptr, *save_ptr;
		char buf[MAX_BUF_SIZE];
		if (strlen(start_t) == 0)
			sprintf_ex(start_t, "%s", save_t);
#ifdef _WIN
		/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
		fscanf_ex(fp, "%u %u %u", &t_used, &np_used, &p_use);
		set_min_max_val(&kmem.total, t_used);
		set_min_max_val(&kmem.npused, np_used);
		set_min_max_val(&kmem.pused, p_use);
#else // LIN
		/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
		fscanf_ex(fp, "%u %u %u %u", &t_req, &t_al, &t_bm, &t_ee);
		set_min_max_val(&kmem.req, t_req);
		set_min_max_val(&kmem.al, t_al);
		set_min_max_val(&kmem.bm, t_bm);
		set_min_max_val(&kmem.ee, t_ee);
#endif

		if (fgets(buf, sizeof(buf), fp) != NULL) {
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			
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
				set_min_max_val(&temp->wss, atol(ptr));
				/* QuotaPagedPoolUsage(bytes) */
				ptr = strtok_r(NULL, " ", &save_ptr);
				set_min_max_val(&temp->qpp, atol(ptr));
				/* QuotaNonPagedPoolUsage(bytes) */
				ptr = strtok_r(NULL, " ", &save_ptr);
				set_min_max_val(&temp->qnpp, atol(ptr));
				/* PagefileUsage(bytes) */
				ptr = strtok_r(NULL, " ", &save_ptr);
				set_min_max_val(&temp->pfu, atol(ptr));
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
	}

	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);
	printf(" Run: %s - %s\n", start_t, end_t);
	printf(" module (bytes)\n");
#ifdef _WIN
	/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
	print_range("  TotalUsed   : ", &kmem.total, "\n");
	print_range("  NonPagedUsed: ", &kmem.npused, "\n");
	print_range("  PagedUsed   : ", &kmem.pused, "\n");
#else
	/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
	print_range("  BSR_REQ: ", &kmem.req, "\n");
	print_range("  BSR_AL : ", &kmem.al, "\n");
	print_range("  BSR_BM : ", &kmem.bm, "\n");
	print_range("  BSR_EE : ", &kmem.ee, "\n");
#endif

#ifdef _WIN
	printf(" user (bytes)\n");
	printf("  %-13s %-23s %-23s %-23s %s\n", "name", "WorkingSetSize", "QuotaPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage");
#else // _LIN
	printf(" user (kbytes)\n");
	printf("  %-13s %-23s %s\n", "name", "rsz", "vsz");
#endif

	print_umem("bsradm", &bsradm_stat);
	print_umem("bsrsetup", &bsrsetup_stat);
	print_umem("bsrmeta", &bsrmeta_stat);
	print_umem("bsrmon", &bsrmon_stat);
#ifdef _WIN
	print_umem("bsrservice", &bsrservice_stat);
#endif

}


void watch_io_stat(char *path, bool scroll)
{
	FILE *fp;
	int offset = 0;

	fp = open_readonly(path);
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

	fp = open_readonly(path);
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
	
	fp = open_readonly(path);
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
			print_req_stat(&save_ptr, "    pre_submit      (usec)");
			print_req_stat(&save_ptr, "    post_submit     (usec)");
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

	fp = open_readonly(path);
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
				print_req_stat(&save_ptr, "    pre_submit   (usec)");
				print_req_stat(&save_ptr, "    post_submit  (usec)");
				print_req_stat(&save_ptr, "    complete     (usec)");

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
	
	fp = open_readonly(path);
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
	
	fp = open_readonly(path);
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
				printf("    send (byte/s): %lu\n", 
					atol(strtok_r(NULL, " ", &save_ptr)));
				printf("    recv (byte/s): %lu\n", 
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
	
	fp = open_readonly(path);
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };

		offset = ftell(fp);
		fseek(fp, offset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long s_size = 0, s_used = 0;
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
					s_size = atol(strtok_r(NULL, " ", &save_ptr));
					s_used = atol(strtok_r(NULL, " ", &save_ptr));
					
					printf("    %s stream\n", type);
					printf("        size (bytes): %lu\n", s_size);
					printf("        used (bytes): %lu\n", s_used); 
					
					type = strtok_r(NULL, " ", &save_ptr);
				}
				else {
					ptr = strtok_r(NULL, " ", &save_ptr);

					if (!strcmp(ptr, "no") ||!strcmp(ptr, "data") || !strcmp(ptr, "control")) {
						// peer_name
						peer_name = type;
						printf("  PEER %s:\n", peer_name); 
						type = ptr;
					} else {
						// packet info
						p_cnt = atol(ptr);
						p_size = atol(strtok_r(NULL, " ", &save_ptr));
						printf("         [%s]  -  cnt: %lu  size: %lu bytes\n", type, p_cnt, p_size);
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
	
	fp = open_readonly(path);
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
			printf("  module (bytes)\n");
	#ifdef _WIN
			/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
			printf("    TotalUsed    : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
			printf("    NonPagedUsed : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
			printf("    PagedUsed    : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
	#else // LIN
			/* BSR_REQ(bytes) BSR_AL(bytes) BSR_BM(bytes) BSR_EE(bytes) */
			printf("    BSR_REQ : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
			printf("    BSR_AL  : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
			printf("    BSR_BM  : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
			printf("    BSR_EE  : %lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
	#endif


	#ifdef _WIN
			printf("  user (bytes)\n");
			printf("    %-11s %-6s %-15s %-21s %-23s %-14s\n", "name", "pid", "WorkingSetSize", "QuotaPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage");
	#else // _LIN
			printf("  user (kbytes)\n");
			printf("    %-9s %-6s %-10s %-10s\n", "name", "pid", "rsz", "vsz");
	#endif
			app_name = strtok_r(NULL, " ", &save_ptr);
			while (app_name) {
	#ifdef _WIN
				printf("    %-11s", app_name);
				printf(" %-6lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-15lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-21lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-23lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-14lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
	#else // _LIN
				printf("    %-9s", app_name);
				printf(" %-6lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-10lu", atol(strtok_r(NULL, " ", &save_ptr)));
				printf(" %-10lu\n", atol(strtok_r(NULL, " ", &save_ptr)));
	#endif
				app_name = strtok_r(NULL, " ", &save_ptr);
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