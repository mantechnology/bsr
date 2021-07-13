#include "read_stat.h"
#ifdef _LIN
#include <unistd.h>
#endif

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

	if (t_min > 0) {
		/* Excluded from statistics if:
			1. Current value is 0
			2. Previous value is 0
			3. Consecutive duplicate values
		*/
		if (t_avg == 0 || stat->priv == 0 || (stat->priv == t_avg && stat->duplicate)) {
			stat->priv = t_avg;
			return;
		}
		
		set_min_max(stat, t_min, t_max);

		if (stat->priv == t_avg)
			stat->duplicate = true;
		else 
			stat->duplicate = false;

		stat->priv = t_avg;
		stat->sum += t_avg;
		stat->cnt ++;
	}
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

	if (fopen_s(&fp, path, "r") != 0)
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

	if (fopen_s(&fp, path, "r") != 0)
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
	struct perf_stat req = {0,}, before_queue = {0,}, before_al_begin = {0,}, in_actlog = {0,}, pre_submit = {0,}, post_submit = {0,}, destroy = {0,};
	struct perf_stat al = {0,}, before_bm_write = {0,}, after_bm_write = {0,}, after_sync_page = {0,};

	if (fopen_s(&fp, path, "r") != 0)
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
			set_min_max_val(&req, t_cnt);

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
			set_min_max_val(&al, t_cnt);
			set_min_max_fp(fp, &before_bm_write);
			set_min_max_fp(fp, &after_bm_write);
			set_min_max_fp(fp, &after_sync_page);
		}	
		fscanf_ex(fp, "%*[^\n]");	
	}
	
	fclose(fp);

	sprintf_ex(end_t, "%s", save_t);

	printf(" Run: %s - %s\n", start_t, end_t);
	printf("  requests  (per sec): min=%lu, max=%lu, avg=%lu (total=%lu)\n", req.min, req.max, stat_avg(req.sum, req.cnt), req.sum);
	print_stat("    before_queue    (usec)", &before_queue);
	print_stat("    before_al_begin (usec)", &before_al_begin);
	print_stat("    in_actlog       (usec)", &in_actlog);
	print_stat("    pre_submit      (usec)", &pre_submit);
	print_stat("    post_submit     (usec)", &post_submit);
	print_stat("    destroy         (usec)", &destroy);
	printf("  al_update (per sec): min=%lu, max=%lu, avg=%lu (total=%lu)\n", al.min, al.max, stat_avg(al.sum, al.cnt), al.sum);
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

	if (fopen_s(&fp, path, "r") != 0)
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
	char save_t[64] = {0,}, start_t[64] = {0,}, end_t[64] = {0,}; 
	struct perf_stat peer_req = {0,}, pre_submit = {0,}, post_submit = {0,}, complete = {0,};

	if (fopen_s(&fp, path, "r") != 0)
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
				set_min_max_val(&peer_req, t_cnt);

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
	printf("    peer requests  (per sec): min=%lu, max=%lu, avg=%lu (total=%lu)\n", 
		peer_req.min, peer_req.max, stat_avg(peer_req.sum, peer_req.cnt), peer_req.sum);
	print_stat("    pre_submit  (usec)", &pre_submit);
	print_stat("    post_submit (usec)", &post_submit);
	print_stat("    complete    (usec)", &complete);
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

	if (fopen_s(&fp, path, "r") != 0)
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

	if (fopen_s(&fp, path, "r") != 0)
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
	
	if (fopen_s(&fp, path, "r") != 0)
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


void watch_io_stat(char *cmd)
{
	FILE *fp;

	fp = popen(cmd, "r");
	if (!fp)
		return;

	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };		
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

	
	pclose(fp);
	
}


void watch_io_complete(char *cmd)
{
	FILE *fp;

	fp = popen(cmd, "r");
	if (!fp)
		return;

	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	
		
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
	

	pclose(fp);
	
}


void print_req_stat(char ** save_ptr, const char * name) 
{	
	unsigned long t_min = 0, t_max = 0, t_avg = 0;
	
	t_min = atol(strtok_r(NULL, " ", save_ptr));
	t_max = atol(strtok_r(NULL, " ", save_ptr));
	t_avg = atol(strtok_r(NULL, " ", save_ptr));
	printf("%s: min=%lu, max=%lu, avg=%lu\n", name, t_min, t_max, t_avg);
}

void watch_req_stat(char *cmd)
{
	FILE *fp;
	
	fp = popen(cmd, "r");
	if (!fp)
		return;


	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	
		
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long t_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;
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


	pclose(fp);

}

void watch_peer_req_stat(char *cmd)
{
	FILE *fp;
	
	fp = popen(cmd, "r");
	if (!fp)
		return;


	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };	
		
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long t_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);
			if (!ptr) 
				continue;
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


	pclose(fp);

}



void watch_network_speed(char *cmd)
{
	FILE *fp;

	fp = popen(cmd, "r");
	if (!fp)
		return;
	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };
		if (fgets(buf, sizeof(buf), fp) != NULL) {	
			char *ptr, *save_ptr;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (ptr)
				printf("%s\n", ptr); // time
			else
				continue;
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
	pclose(fp);

}


void watch_sendbuf(char *cmd)
{
	FILE *fp;

	char *peer_name, *type;
	
	fp = popen(cmd, "r");
	if (!fp)
		return;

	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr;
			unsigned long s_size = 0, s_used = 0;
			unsigned long p_size = 0, p_cnt = 0;

			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (ptr)
				printf("%s\n", ptr); // time
			else
				continue;

			type = strtok_r(NULL, " ", &save_ptr);

			while (type) {
				
				if (!strcmp(type, "no")) {
					/* no send buffer */
					strtok_r(NULL, " ", &save_ptr);
					strtok_r(NULL, " ", &save_ptr);
					printf("    no send buffer\n");
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

	pclose(fp);
}

void watch_memory(char *cmd)
{
	FILE *fp;
	
	fp = popen(cmd, "r");
	if (!fp)
		return;

	while(1) {
		char buf[MAX_BUF_SIZE] = {0, };
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			char *ptr, *save_ptr, *app_name;
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;
			ptr = strtok_r(buf, " ", &save_ptr);

			if (ptr)
				printf("%s\n", ptr); // time
			else
				continue;

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

	pclose(fp);

}