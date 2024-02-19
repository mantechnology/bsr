#include "bsr_split_req.h"


static int bit_count(unsigned int val)
{
	int count = 0;

	while (val != 0) {
		if ((val & 0x1) == 0x1)
			count++;
		val >>= 1;
	}

	return count;
}

struct bsr_peer_request *split_read_in_block(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_request, sector_t sector,
	ULONG_PTR offset, unsigned int size, struct split_req_bitmap_bit bb, ULONG_PTR flags, atomic_t* split_count, char* verify, int(*cb)(struct bsr_work *, int cancel)) __must_hold(local)

{
	struct bsr_peer_request *split_peer_request;
	struct bsr_transport *transport = &peer_device->connection->transport;
#ifdef _LIN
	// BSR-508
	struct page *page = peer_request->page_chain.head;
	struct page *split_req_page;
	int req_page_offset = offset;
	int req_page_idx = 0;
	int page_cnt = 0;
	int data_size = size;
	void* data;
#endif

	split_peer_request = bsr_alloc_peer_req(peer_device, GFP_TRY);

	if (!split_peer_request)
		return NULL;

	split_peer_request->i.size = size; /* storage size */
	split_peer_request->i.sector = sector;

	split_peer_request->flags |= EE_WRITE;
	split_peer_request->flags |= flags;

	split_peer_request->block_id = peer_request->block_id;

	// DW-1961 Save timestamp for IO latency measurement
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		split_peer_request->created_ts = timestamp();

	bsr_alloc_page_chain(transport, &split_peer_request->page_chain, DIV_ROUND_UP(split_peer_request->i.size, PAGE_SIZE), GFP_TRY);
	if (split_peer_request->page_chain.head == NULL) {
		bsr_free_peer_req(split_peer_request);
		return NULL;
	}

#ifdef _WIN
	split_peer_request->peer_req_databuf = split_peer_request->page_chain.head;
	memcpy(split_peer_request->peer_req_databuf, (char*)peer_request->peer_req_databuf + offset, split_peer_request->i.size);
#else // _LIN
	data = (void*)bsr_kmalloc(size, GFP_ATOMIC | __GFP_NOWARN);
	if (!data) {
		bsr_err(56, BSR_LC_MEMORY, peer_device, "Failed to read in block split due to failure to allocate size(%u) memory to data.", size);
		bsr_free_peer_req(split_peer_request);
		bsr_free_page_chain(transport, &split_peer_request->page_chain, 0);
		return NULL;
	}

	// BSR-508 get serialized data into the buffer from the page of peer_req.
	req_page_idx = (req_page_offset / PAGE_SIZE);
	page_chain_for_each(page) {
		if (page_cnt >= req_page_idx) {
			void *req_data = kmap(page);
			size_t len = min_t(int, data_size, PAGE_SIZE);
			len = min_t(int, len, (PAGE_SIZE - (req_page_offset % PAGE_SIZE)));

			memcpy(data + (req_page_offset - offset), req_data + (req_page_offset % PAGE_SIZE), len);
			req_page_offset += len;
			data_size -= len;
			kunmap(page);

			if (data_size == 0)
				break;
		}
		page_cnt++;
	}

	// BSR-508 copy buffer to page of split_peer_req
	data_size = size;
	split_req_page = split_peer_request->page_chain.head;
	page_chain_for_each(split_req_page) {
		void *split_req_data = kmap(split_req_page);
		size_t len = min_t(int, data_size, PAGE_SIZE);

		memcpy(split_req_data, data + (size - data_size), len);
		kunmap(split_req_page);
		set_page_chain_offset(split_req_page, 0);
		set_page_chain_size(split_req_page, len);
		data_size -= len;
	}

	kfree2(data);
#endif
	split_peer_request->sbb.start = bb.s.start;
	split_peer_request->sbb.end_next = bb.s.end_next;
	split_peer_request->count = split_count;
	split_peer_request->unmarked_count = NULL;
	split_peer_request->failed_unmarked = NULL;

	split_peer_request->w.cb = cb;
	split_peer_request->submit_jif = jiffies;

#ifdef _WIN
	if (verify != NULL) {
		memcpy(verify + offset, (char*)peer_request->peer_req_databuf + offset, split_peer_request->i.size);
	}
#endif

	bsr_debug(179, BSR_LC_RESYNC_OV, peer_device, "split request start_bb(%llu), e_bb(%llu), sector(%llu), offset(%llu), size(%u)",
		(unsigned long long)bb.s.start, (unsigned long long)(bb.s.end_next - 1), sector, (unsigned long long)offset, size);
	return split_peer_request;
}


bool is_marked_rl_bb(struct bsr_peer_device *peer_device, struct bsr_marked_replicate **marked_rl, ULONG_PTR bb)
{
	// BSR-380
	list_for_each_entry_ex(struct bsr_marked_replicate, (*marked_rl), &(peer_device->device->marked_rl_list), marked_rl_list) {
		if ((*marked_rl)->bb == bb) {
			return true;
		}
	}

	(*marked_rl) = NULL;
	return false;
}

bool prepare_split_peer_request(struct bsr_peer_device *peer_device, struct split_req_bitmap_bit *bb, atomic_t *split_count)
{
	bool find_isb = false;
	bool split_request = true;
	struct bsr_marked_replicate *marked_rl, *tmp;
	u16 i; ULONG_PTR ibb;

	list_for_each_entry_safe_ex(struct bsr_marked_replicate, marked_rl, tmp, &(peer_device->device->marked_rl_list), marked_rl_list) {
		if (bit_count(marked_rl->marked_rl) == (sizeof(marked_rl->marked_rl) * 8)) {
			bsr_set_in_sync(peer_device, BM_BIT_TO_SECT(marked_rl->bb), BM_SECT_PER_BIT << 9);
			list_del(&marked_rl->marked_rl_list);
			bsr_kfree(marked_rl);
			continue;
		}

		if (bsr_bm_test_bit(peer_device, marked_rl->bb) == 0) {
			list_del(&marked_rl->marked_rl_list);
			bsr_kfree(marked_rl);
			continue;
		}
	}

	// DW-1601 the last out of sync and split_cnt information are obtained before the resync write request.
	for (ibb = bb->s.start; ibb < bb->s.end_next; ibb++) {
		// BSR-380 modify split_count calculation method
		if (is_marked_rl_bb(peer_device, &marked_rl, ibb)) {
			for (i = 0; i < sizeof(marked_rl->marked_rl) * 8; i++) {
				// DW-1911 obtain the end unmakred sector.
				if (!(marked_rl->marked_rl & 1 << i)) {
					if (marked_rl->end_unmarked_rl < i)
						marked_rl->end_unmarked_rl = i;

					atomic_inc(split_count);
				}
			}
			split_request = true;
			find_isb = true;

			bb->end_oos = ibb;
		}
		else if (bsr_bm_test_bit(peer_device, ibb) == 1) {
			if (split_request) {
				atomic_inc(split_count);
				split_request = false;
			}

			bb->end_oos = ibb;
		}
		else {
			bsr_debug(180, BSR_LC_RESYNC_OV, peer_device, "find in sync bitmap bit : %llu, start (%llu) ~ end (%llu)",
				(unsigned long long)ibb, (unsigned long long)bb->s.start, (unsigned long long)(bb->s.end_next - 1));
			split_request = true;
			find_isb = true;
		}
	}

	return find_isb;
}

bool is_oos_belong_to_repl_area(struct bsr_peer_device *peer_device, ULONG_PTR start_bb, ULONG_PTR end_next_bb)
{
	ULONG_PTR i_bb;
	struct bsr_device *device = peer_device->device;

	// DW-1904 check that the resync data is within the out of sync range of the replication data.
	// DW-2065 modify to incorrect conditions
	// DW-2082 the range(s_rl_bb, e_rl_bb) should not be reset because there is no warranty coming in sequentially.
	if (device->e_rl_bb >= device->s_rl_bb) {
		if ((device->s_rl_bb <= start_bb && device->e_rl_bb >= start_bb))
			return true;

		if (device->s_rl_bb <= (end_next_bb - 1) && device->e_rl_bb >= (end_next_bb - 1))
			return true;

		if ((device->s_rl_bb >= start_bb && device->e_rl_bb <= (end_next_bb - 1)))
			return true;
	}

	// BSR-1160 verify that the replication area is not set, but there is already an in sync area due to the request for duplicate resync.
	for (i_bb = start_bb; i_bb < end_next_bb; i_bb++) {
		// BSR-1160 if there is an area where in sync is set, return a "true" to exclude some or all of it from writing.
		if (bsr_bm_test_bit(peer_device, i_bb) == 0)
			return true;
	}

	return false;
}

int split_request_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq, struct split_req_bitmap_bit bb, ULONG_PTR offset, atomic_t *split_count,
	int *submit_count, struct bsr_marked_replicate *marked_rl, int(*cb)(struct bsr_work *, int cancel))
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_request *split_peer_req = NULL;

	bsr_debug(182, BSR_LC_RESYNC_OV, peer_device, "sync bitmap bit %llu, split request %llu ~ %llu, size %llu, start(%llu) ~ end(%llu), end out of sync(%llu)",
		(unsigned long long)(bb.cur - 1), (unsigned long long)offset, (unsigned long long)(bb.cur - 1), (unsigned long long)(BM_BIT_TO_SECT(bb.cur - offset) << 9),
		(unsigned long long)bb.s.start, (unsigned long long)(bb.s.end_next - 1), (unsigned long long)bb.end_oos);
	split_peer_req = split_read_in_block(peer_device, peer_req,
		BM_BIT_TO_SECT(offset), (BM_BIT_TO_SECT(offset - bb.s.start) << 9), (unsigned int)(BM_BIT_TO_SECT(bb.cur - offset) << 9), bb,
		((bb.end_oos == (bb.cur - 1) && !marked_rl) ? EE_SPLIT_LAST_REQ : EE_SPLIT_REQ), split_count, NULL, cb);

	if (!split_peer_req) {
		bsr_err(26, BSR_LC_MEMORY, peer_device, "Failed to receive resync data due to failure to allocate memory for split peer request, bitmap offset(%llu)", (unsigned long long)bb.cur);
		return -ENOMEM;
	}

	bsr_debug(4, BSR_LC_VERIFY, peer_device, "%s => sector(%llu), size(%u), bitmap(%llu ~ %llu), replication received area(%llu ~ %llu)", __FUNCTION__,
		(unsigned long long)split_peer_req->i.sector, split_peer_req->i.size, (unsigned long long)BM_SECT_TO_BIT(split_peer_req->i.sector),
		(unsigned long long)BM_SECT_TO_BIT(split_peer_req->i.sector + (split_peer_req->i.size >> 9)), (unsigned long long)device->s_rl_bb, (unsigned long long)device->e_rl_bb);

	// BSR-1039
	split_peer_req->resync_seq = peer_seq;

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&split_peer_req->w.list, &peer_device->connection->sync_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(split_peer_req->i.size << 9, &device->rs_sect_ev);

	// BSR-380 set out of sync for split_request.
	bsr_set_all_out_of_sync(device, split_peer_req->i.sector, split_peer_req->i.size);

	if (!bsr_submit_peer_request(device, split_peer_req, REQ_OP_WRITE, 0, BSR_FAULT_RS_WR) == 0) {
		bsr_err(43, BSR_LC_RESYNC_OV, device, "Failed to receive resync data due to failure to submit I/O request, triggering re-connect");

		spin_lock_irq(&device->resource->req_lock);
		list_del(&split_peer_req->w.list);
		spin_unlock_irq(&device->resource->req_lock);
		bsr_free_peer_req(split_peer_req);

		return -EIO;
	}
	// DW-1601 submit_count is used for the split_cnt value in case of failure..
	*submit_count += 1;

	return 0;
}

int split_marked_request_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq,
	struct split_req_bitmap_bit bb, struct bsr_marked_replicate *marked_rl, atomic_t *split_count, int *submit_count, int(*cb)(struct bsr_work *, int cancel))
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_request *split_peer_req = NULL;
	atomic_t *unmarked_count;
	atomic_t *failed_unmarked;
	int i;

	unmarked_count = bsr_kzalloc(sizeof(atomic_t), GFP_KERNEL, '49SB');
	if (!unmarked_count) {
		bsr_err(27, BSR_LC_MEMORY, peer_device, "Failed to receive resync data due to failure to allocate memory for unmakred count");
		return -ENOMEM;
	}
	failed_unmarked = bsr_kzalloc(sizeof(atomic_t), GFP_KERNEL, '59SB');
	if (!failed_unmarked) {
		bsr_err(28, BSR_LC_MEMORY, peer_device, "Failed to receive resync data due to failure to allocate memory for failed unmarked");
		bsr_kfree(unmarked_count);
		return -ENOMEM;
	}

	// DW-1911 unmakred sector counting
	atomic_set(unmarked_count, (sizeof(marked_rl->marked_rl) * 8) - bit_count(marked_rl->marked_rl));
	atomic_set(failed_unmarked, 0);

	device->h_marked_bb++;

	for (i = 0; i < sizeof(marked_rl->marked_rl) * 8; i++) {
		// DW-1911 perform writing per unmarked sector.
		if (!(marked_rl->marked_rl & 1 << i)) {
			split_peer_req = split_read_in_block(peer_device, peer_req,
				// DW-2082 corrected incorrectly calculated start sector
				(BM_BIT_TO_SECT(marked_rl->bb) + i), ((BM_BIT_TO_SECT(marked_rl->bb - bb.s.start) + i) << 9), 1 << 9, bb,
				((marked_rl->bb == bb.end_oos && marked_rl->end_unmarked_rl == i) ? EE_SPLIT_LAST_REQ : EE_SPLIT_REQ), split_count, NULL, cb);

			if (!split_peer_req) {
				bsr_err(29, BSR_LC_MEMORY, peer_device, "Failed to allocate memory for split peer request, bitmap bit(%llu)", (unsigned long long)bb.cur);
				if (!atomic_sub_return((atomic_read(unmarked_count) - *submit_count), unmarked_count)) {
					bsr_kfree(failed_unmarked);
					bsr_kfree(unmarked_count);
				}
				return -ENOMEM;
			}

			bsr_debug(5, BSR_LC_VERIFY, peer_device, "%s => marked, sector(%llu), size(%u), bitmap(%llu ~ %llu), replication received area(%llu ~ %llu)", __FUNCTION__,
				(unsigned long long)split_peer_req->i.sector, split_peer_req->i.size, (unsigned long long)BM_SECT_TO_BIT(split_peer_req->i.sector),
				(unsigned long long)BM_SECT_TO_BIT(split_peer_req->i.sector + (split_peer_req->i.size >> 9)), (unsigned long long)device->s_rl_bb, (unsigned long long)device->e_rl_bb);
			// BSR-1039
			split_peer_req->resync_seq = peer_seq;

			split_peer_req->unmarked_count = unmarked_count;
			split_peer_req->failed_unmarked = failed_unmarked;

			spin_lock_irq(&device->resource->req_lock);
			list_add_tail(&split_peer_req->w.list, &peer_device->connection->sync_ee);
			spin_unlock_irq(&device->resource->req_lock);

			atomic_add(split_peer_req->i.size << 9, &device->rs_sect_ev);

			bsr_set_all_out_of_sync(device, split_peer_req->i.sector, split_peer_req->i.size);

			bsr_debug(183, BSR_LC_RESYNC_OV, peer_device, "unmarked bb(%llu), sector(%llu), offset(%d), count(%d)", (unsigned long long)marked_rl->bb,
				(unsigned long long)BM_BIT_TO_SECT(marked_rl->bb) + i, i, atomic_read(unmarked_count));
			if (!bsr_submit_peer_request(device, split_peer_req, REQ_OP_WRITE, 0, BSR_FAULT_RS_WR) == 0) {
				bsr_err(47, BSR_LC_RESYNC_OV, device, "Failed to receive resync data due to failure to submit I/O request, triggering re-connect");
				// DW-1923 
				if (!atomic_sub_return((atomic_read(unmarked_count) - *submit_count), unmarked_count)) {
					bsr_kfree(failed_unmarked);
					bsr_kfree(unmarked_count);
				}
				// DW-1601 If the bsr_submit_peer_request() fails, remove split_count - submit_count from the previously acquired split_cnt and turn off split_cnt if 0.
				spin_lock_irq(&device->resource->req_lock);
				list_del(&split_peer_req->w.list);
				spin_unlock_irq(&device->resource->req_lock);
				bsr_free_peer_req(split_peer_req);

				return -EIO;
			}
			*submit_count += 1;
		}
		else {
			// DW-1886
			atomic_add64(1 << 9, &peer_device->rs_written);
		}
	}

	return 0;
}

bool check_unmarked_and_processing(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req)
{
	bool unmakred = peer_req->unmarked_count != NULL;

	if (peer_req->unmarked_count &&
		0 == atomic_dec_return(peer_req->unmarked_count)) {
		unmakred = false;

		//DW-1911 if there is a failure, set the EE_WAS_ERROR setting.
		if (atomic_read(peer_req->failed_unmarked) == 1)
			peer_req->flags |= EE_WAS_ERROR;

		bsr_debug(177, BSR_LC_RESYNC_OV, peer_device, "finished unmarked start_bb(%llu), e_bb(%llu), sector(%llu), res(%s)", (unsigned long long)peer_req->sbb.start, (unsigned long long)(peer_req->sbb.end_next - 1),
			(unsigned long long)peer_req->i.sector, (atomic_read(peer_req->failed_unmarked) == 1 ? "failed" : "success"));

		// DW-2082
		peer_req->i.sector = BM_BIT_TO_SECT(BM_SECT_TO_BIT(peer_req->i.sector));
		peer_req->i.size = BM_SECT_PER_BIT << 9;

		bsr_debug(1, BSR_LC_VERIFY, peer_device, "%s, finished unmarked sector(%llu), size(%u), bitmap(%llu ~ %llu)", __FUNCTION__, (unsigned long long)peer_req->i.sector, peer_req->i.size,
			(unsigned long long)BM_SECT_TO_BIT(peer_req->i.sector), (unsigned long long)BM_SECT_TO_BIT(peer_req->i.sector + (peer_req->i.size >> 9)));

		kfree2(peer_req->unmarked_count);
		if (peer_req->failed_unmarked)
			kfree2(peer_req->failed_unmarked);
	}
	else {
		if (peer_req->flags & EE_WAS_ERROR) {
			//DW-1911 
			if (unmakred && peer_req->failed_unmarked)
				atomic_set(peer_req->failed_unmarked, 1);
		}
	}

	return unmakred;
}

bool get_resync_pending_range(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, sector_t *cst, bool locked)
{
	struct bsr_resync_pending_sectors *target = NULL;
	bool res = false;

	if (!locked)
		mutex_lock(&peer_device->device->resync_pending_fo_mutex);
	list_for_each_entry_ex(struct bsr_resync_pending_sectors, target, &(peer_device->device->resync_pending_sectors), pending_sectors) {
		if (est <= target->sst) {
			// all ranges are not duplicated with resync pending
			// cst (current sector)
			*cst = est;
			// return false not duplicate
			res = false;
			goto out;
		}
		else if ((sst >= target->sst && est <= target->est)) {
			// all ranges are duplicated with resync pending
			bsr_info(35, BSR_LC_RESYNC_OV, peer_device, "Resync duplicates. all out of sync sectors %llu ~ %llu => source %llu ~ %llu, target %llu ~ %llu", (unsigned long long)sst, (unsigned long long)est,
				(unsigned long long)sst, (unsigned long long)est, (unsigned long long)target->sst, (unsigned long long)target->est);
			*cst = est;
			// return true duplicate 
			res = true;
			goto out;
		}
		else if (sst < target->sst && est > target->sst) {
			// not all ranges duplicated
			*cst = target->sst;
			res = false;
			goto out;
		}
		else if (sst < target->sst && (est <= target->est || est >= target->est)) {
			// front range duplicated
			bsr_info(36, BSR_LC_RESYNC_OV, peer_device, "Resync duplicates. front out of sync sectors %llu ~ %llu => source %llu ~ %llu, target %llu ~ %llu", (unsigned long long)target->sst,
				(unsigned long long)(target->est < est ? target->est : est), (unsigned long long)sst, (unsigned long long)est, (unsigned long long)target->sst, (unsigned long long)target->est);
			*cst = (target->est < est ? target->est : est);
			res = true;
			goto out;
		}
		else if (sst >= target->sst && sst < target->est && est > target->est) {
			// end range duplicated 
			bsr_info(37, BSR_LC_RESYNC_OV, peer_device, "Resync duplicates. end out of sync sectors %llu ~ %llu => source %llu ~ %llu, target %llu ~ %llu",
				(unsigned long long)sst, (unsigned long long)target->est, (unsigned long long)sst, (unsigned long long)est, (unsigned long long)target->sst, (unsigned long long)target->est);
			*cst = target->est;
			res = true;
			goto out;
		}
	}
	*cst = est;
out:
	if (!locked)
		mutex_unlock(&peer_device->device->resync_pending_fo_mutex);

	return res;
}

int dedup_from_resync_pending(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	struct bsr_resync_pending_sectors *target, *tmp;

	mutex_lock(&peer_device->device->resync_pending_fo_mutex);
	list_for_each_entry_safe_ex(struct bsr_resync_pending_sectors, target, tmp, &(peer_device->device->resync_pending_sectors), pending_sectors) {
		if (sst <= target->sst && est >= target->est) {
			bsr_info(52, BSR_LC_RESYNC_OV, peer_device, "Resync pending remove sector %llu(%llu) ~ %llu(%llu)",
				(unsigned long long)target->sst, (unsigned long long)BM_SECT_TO_BIT(target->sst), (unsigned long long)target->est, (unsigned long long)BM_SECT_TO_BIT(target->est));
			// remove because it contains the full range
			list_del(&target->pending_sectors);
			kfree2(target);
			continue;
		}

		if (sst >= target->sst && est <= target->est) {
			// remove because the middle range is the same
			struct bsr_resync_pending_sectors *pending_st;

			// adding it to the list because it will disperse when the middle is removed
#ifdef _WIN
			pending_st = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_resync_pending_sectors), 'D9SB');
#else // _LIN
			pending_st = (struct bsr_resync_pending_sectors *)bsr_kmalloc(sizeof(struct bsr_resync_pending_sectors), GFP_ATOMIC | __GFP_NOWARN, '');
#endif
			if (!pending_st) {
				bsr_err(30, BSR_LC_MEMORY, peer_device, "Failed to check resync pending due to failure to allocate memory, sector(%llu ~ %llu)", (unsigned long long)sst, (unsigned long long)est);
				mutex_unlock(&peer_device->device->resync_pending_fo_mutex);
				return -ENOMEM;
			}

			pending_st->sst = est;
			pending_st->est = target->est;
			list_add(&pending_st->pending_sectors, &target->pending_sectors);
			bsr_info(54, BSR_LC_RESYNC_OV, peer_device, "Resync pending split new sector %llu(%llu) ~ %llu(%llu)",
				(unsigned long long)pending_st->sst, (unsigned long long)BM_SECT_TO_BIT(pending_st->sst), (unsigned long long)pending_st->est, (unsigned long long)BM_SECT_TO_BIT(pending_st->est));

			target->est = sst;
			bsr_info(55, BSR_LC_RESYNC_OV, peer_device, "Resync pending split sector %llu(%llu) ~ %llu(%llu)",
				(unsigned long long)target->sst, (unsigned long long)BM_SECT_TO_BIT(target->sst), (unsigned long long)target->est, (unsigned long long)BM_SECT_TO_BIT(target->est));
		}

		if (sst <= target->sst && est > target->sst && est <= target->est) {
			// remove because the start range is the same.
			target->sst = est;
			bsr_info(56, BSR_LC_RESYNC_OV, peer_device, "Resync pending modify sector %llu(%llu) ~ %llu(%llu)",
				(unsigned long long)target->sst, (unsigned long long)BM_SECT_TO_BIT(target->sst), (unsigned long long)target->est, (unsigned long long)BM_SECT_TO_BIT(target->est));
		}

		if (sst >= target->sst && sst < target->est && est >= target->est) {
			// remove because the end range is the same.
			target->est = sst;
			bsr_info(57, BSR_LC_RESYNC_OV, peer_device, "Resync pending modify sector %llu(%llu) ~ %llu(%llu)",
				(unsigned long long)target->sst, (unsigned long long)BM_SECT_TO_BIT(target->sst), (unsigned long long)target->est, (unsigned long long)BM_SECT_TO_BIT(target->est));
		}
	}
	mutex_unlock(&peer_device->device->resync_pending_fo_mutex);

	return 0;
}

int list_add_marked(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, unsigned int size, ULONG_PTR in_sync)
{
	ULONG_PTR start_bb, e_bb;
	struct bsr_device* device = peer_device->device;
	struct bsr_marked_replicate *marked_rl = NULL, *s_marked_rl = NULL, *e_marked_rl = NULL;
	u16 i = 0;
	u16 offset = 0;

	//DW-1904 range in progress for resync (peer_device->s_resync_bb ~ peer_device->e_resync_bb)
	ULONG_PTR s_resync_bb = (ULONG_PTR)atomic_read64(&peer_device->s_resync_bb);
	ULONG_PTR n_resync_bb = (ULONG_PTR)atomic_read64(&peer_device->e_resync_bb);

	start_bb = (ULONG_PTR)BM_SECT_TO_BIT(sst);
	e_bb = (ULONG_PTR)BM_SECT_TO_BIT(est);

	// DW-1911 use e_bb instead of e_next_b for replication.
	if (BM_BIT_TO_SECT(e_bb) == est)
		e_bb -= 1;

	// DW-2125 marked bit must be set even if the first(start_bb) or the end(e_bb) is equal to s_resync_bb in the replication range
	if ((s_resync_bb <= e_bb && n_resync_bb >= e_bb) ||
		(s_resync_bb <= start_bb && n_resync_bb >= start_bb)) {
		// DW-1911 check if marked already exists.
		list_for_each_entry_ex(struct bsr_marked_replicate, marked_rl, &(device->marked_rl_list), marked_rl_list) {
			if (marked_rl->bb == start_bb)
				s_marked_rl = marked_rl;
			if (marked_rl->bb == e_bb)
				e_marked_rl = marked_rl;

			if (s_marked_rl && e_marked_rl)
				break;
		}

		// DW-2065 modify to incorrect conditions
		if ((BM_BIT_TO_SECT(start_bb) != sst || (BM_BIT_TO_SECT(start_bb) == sst && start_bb == e_bb)) &&
			bsr_bm_test_bit(peer_device, start_bb) == 1) {
			if (!s_marked_rl) {
#ifdef _WIN
				s_marked_rl = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_marked_replicate), 'E8SB');
#else // _LIN
				s_marked_rl = (struct bsr_marked_replicate *)bsr_kmalloc(sizeof(struct bsr_marked_replicate), GFP_ATOMIC | __GFP_NOWARN, '');
#endif
				if (s_marked_rl != NULL) {
					s_marked_rl->bb = start_bb;
					s_marked_rl->marked_rl = 0;
					s_marked_rl->end_unmarked_rl = 0;
					list_add(&(s_marked_rl->marked_rl_list), &device->marked_rl_list);
				}
				else {
					bsr_err(31, BSR_LC_MEMORY, peer_device, "Failed to add marked replicate due to failure to allocate memory. bitmap bit(%llu)", (unsigned long long)start_bb);
					return -ENOMEM;
				}
			}

			// DW-1911 set the bit to match the sector.
			offset = (u16)(sst - BM_BIT_TO_SECT(start_bb));;
			for (i = offset; i < (offset + (size >> 9)); i++) {
				if (BM_SECT_TO_BIT(BM_BIT_TO_SECT(start_bb) + i) != start_bb)
					break;
				s_marked_rl->marked_rl |= 1 << i;
			}
			bsr_debug(184, BSR_LC_RESYNC_OV, peer_device, "sbb marking bb(%llu), ssector(%llu), sector(%llu), size(%u), marked(%u), offset(%u)",
				(unsigned long long)s_marked_rl->bb, (unsigned long long)sst, (unsigned long long)BM_BIT_TO_SECT(s_marked_rl->bb), (size >> 9), s_marked_rl->marked_rl, offset);
		}

		// DW-2065 modify to incorrect conditions
		if (start_bb != e_bb && BM_BIT_TO_SECT(BM_SECT_TO_BIT(est)) != est &&
			bsr_bm_test_bit(peer_device, e_bb) == 1) {
			if (!e_marked_rl) {
#ifdef _WIN
				e_marked_rl = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_marked_replicate), '79SB');
#else // _LIN
				e_marked_rl = (struct bsr_marked_replicate *)bsr_kmalloc(sizeof(struct bsr_marked_replicate), GFP_ATOMIC | __GFP_NOWARN, '');
#endif
				if (e_marked_rl != NULL) {
					e_marked_rl->bb = e_bb;
					e_marked_rl->marked_rl = 0;
					e_marked_rl->end_unmarked_rl = 0;
					list_add(&(e_marked_rl->marked_rl_list), &device->marked_rl_list);
				}
				else {
					bsr_err(32, BSR_LC_MEMORY, peer_device, "Failed to add marked replicate due to failure to allocate memory for marked replicate. bitmap bit(%llu)", (unsigned long long)e_bb);
					return -ENOMEM;
				}
			}

			// DW-1911 set the bit to match the sector.
			for (i = 0; i < (est - BM_BIT_TO_SECT(e_bb)); i++) {
				e_marked_rl->marked_rl |= 1 << i;
			}
			bsr_debug(185, BSR_LC_RESYNC_OV, peer_device, "marking bb(%llu), esector(%llu), sector(%llu), size(%u), marked(%u), offset(%u)",
				(unsigned long long)e_marked_rl->bb, est, (unsigned long long)BM_BIT_TO_SECT(e_marked_rl->bb), (size >> 9), e_marked_rl->marked_rl, 0);
		}
	}

	// DW-1904 this area is set up to check marked_rl and in sync bit when receiving resync data.
	if (in_sync) {
		// DW-1911 marked_rl bit is excluded.
		if (s_marked_rl != NULL)
			start_bb += 1;
		if (e_marked_rl != NULL)
			e_bb -= 1;

		if (device->s_rl_bb > start_bb)
			device->s_rl_bb = start_bb;
		if (device->e_rl_bb < e_bb)
			device->e_rl_bb = e_bb;
	}

	return 0;
}

struct bsr_resync_pending_sectors *resync_pending_check_and_expand_dup(struct bsr_device* device, sector_t sst, sector_t est)
{
	struct bsr_resync_pending_sectors *pending_st = NULL;

	if (list_empty(&device->resync_pending_sectors))
		return NULL;

	list_for_each_entry_ex(struct bsr_resync_pending_sectors, pending_st, &(device->resync_pending_sectors), pending_sectors) {
		if (sst >= pending_st->sst && sst <= pending_st->est && est <= pending_st->est) {
			// ignore them because they already have the all rangs.
			return pending_st;
		}

		if (sst <= pending_st->sst && est >= pending_st->sst && est > pending_st->est) {
			// update sst and est because it contains a larger range that already exists.
			pending_st->sst = sst;
			pending_st->est = est;
			return pending_st;
		}

		if (sst >= pending_st->sst && sst < pending_st->est && est > pending_st->est) {
			// existing ranges include start ranges, but end ranges are larger, so update the est values.
			pending_st->est = est;
			return pending_st;
		}

		if (sst < pending_st->sst && est > pending_st->sst && est <= pending_st->est) {
			// existing ranges include end ranges, but start ranges are small, so update the sst values.
			pending_st->sst = sst;
			return pending_st;
		}
	}
	// there is no equal range.
	return NULL;
}

void resync_pending_list_all_check_and_dedup(struct bsr_device* device, struct bsr_resync_pending_sectors *pending_st)
{
	struct bsr_resync_pending_sectors *target, *tmp;

	list_for_each_entry_safe_ex(struct bsr_resync_pending_sectors, target, tmp, &(device->resync_pending_sectors), pending_sectors) {
		if (pending_st == target)
			continue;

		if (pending_st->sst <= target->sst && pending_st->est >= target->est) {
			// remove all ranges as they are included.
			list_del(&target->pending_sectors);
			kfree2(target);
			continue;
		}
		if (pending_st->sst > target->sst && pending_st->sst <= target->est) {
			// the end range is included, so update the est.
			target->est = pending_st->sst;
		}

		if (pending_st->sst <= target->sst && pending_st->est > target->sst) {
			// the start range is included, so update the sst.
			target->sst = pending_st->est;
		}
	}
}

int list_add_resync_pending(struct bsr_device* device, sector_t sst, sector_t est)
{
	struct bsr_resync_pending_sectors *pending_st = NULL;
	struct bsr_resync_pending_sectors *target = NULL;

	int i = 0;

	// remove duplicates from items you want to add.
	mutex_lock(&device->resync_pending_fo_mutex);
	pending_st = resync_pending_check_and_expand_dup(device, sst, est);
	if (pending_st) {
		resync_pending_list_all_check_and_dedup(device, pending_st);
	}
	else {
		struct bsr_resync_pending_sectors *target;

#ifdef _WIN
		pending_st = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_resync_pending_sectors), 'E9SB');
#else // _LIN
		pending_st = (struct bsr_resync_pending_sectors *)bsr_kmalloc(sizeof(struct bsr_resync_pending_sectors), GFP_ATOMIC | __GFP_NOWARN, '');
#endif

		if (!pending_st) {
			bsr_err(34, BSR_LC_MEMORY, device, "Failed to add resync pending due to failure to allocate memory. sector(%llu ~ %llu)", (unsigned long long)sst, (unsigned long long)est);
			mutex_unlock(&device->resync_pending_fo_mutex);
			return -ENOMEM;
		}

		pending_st->sst = sst;
		pending_st->est = est;

		// add to the list in sequential sort.
		if (list_empty(&device->resync_pending_sectors)) {
			list_add(&pending_st->pending_sectors, &device->resync_pending_sectors);
		}
		else {
			list_for_each_entry_ex(struct bsr_resync_pending_sectors, target, &(device->resync_pending_sectors), pending_sectors) {
				if (pending_st->sst < target->sst) {
					if (device->resync_pending_sectors.next == &target->pending_sectors)
						list_add(&pending_st->pending_sectors, &device->resync_pending_sectors);
					else
						list_add_tail(&pending_st->pending_sectors, &target->pending_sectors);

					goto eof;
				}
			}
			list_add_tail(&pending_st->pending_sectors, &device->resync_pending_sectors);
		}
	}
eof:
	list_for_each_entry_ex(struct bsr_resync_pending_sectors, target, &(device->resync_pending_sectors), pending_sectors)
		bsr_info(101, BSR_LC_RESYNC_OV, device, "%d. Resync pending sector %llu(%llu) ~ %llu(%llu)", i++, (unsigned long long)target->sst, (unsigned long long)BM_SECT_TO_BIT(target->sst), (unsigned long long)target->est, (unsigned long long)BM_SECT_TO_BIT(target->est));
	mutex_unlock(&device->resync_pending_fo_mutex);

	return 0;
}

struct bsr_ov_skip_sectors *ov_check_and_expand_dup(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	struct bsr_ov_skip_sectors *ov_st = NULL;

	if (list_empty(&peer_device->ov_skip_sectors_list))
		return NULL;

	list_for_each_entry_ex(struct bsr_ov_skip_sectors, ov_st, &peer_device->ov_skip_sectors_list, sector_list) {
		if (sst >= ov_st->sst && sst <= ov_st->est && est <= ov_st->est) {
			// ignore them because they already have the all rangs.
			return ov_st;
		}

		if (sst <= ov_st->sst && est >= ov_st->sst && est > ov_st->est) {
			// update sst and est because it contains a larger range that already exists.
			ov_st->sst = sst;
			ov_st->est = est;
			return ov_st;
		}

		if (sst >= ov_st->sst && sst <= ov_st->est && est > ov_st->est) {
			// existing ranges include start ranges, but end ranges are larger, so update the est values.
			ov_st->est = est;
			return ov_st;
		}

		if (sst < ov_st->sst && est >= ov_st->sst && est <= ov_st->est) {
			// existing ranges include end ranges, but start ranges are small, so update the sst values.
			ov_st->sst = sst;
			return ov_st;
		}
	}
	// there is no equal range.
	return NULL;
}

void ov_list_all_check_and_dedup(struct bsr_peer_device *peer_device, struct bsr_ov_skip_sectors *ov_st)
{
	struct bsr_ov_skip_sectors *target, *tmp;

	list_for_each_entry_safe_ex(struct bsr_ov_skip_sectors, target, tmp, &peer_device->ov_skip_sectors_list, sector_list) {
		if (ov_st == target)
			continue;

		if (ov_st->sst <= target->sst && ov_st->est >= target->est) {
			// remove all ranges as they are included.
			list_del(&target->sector_list);
			kfree2(target);
			continue;
		}
		if (ov_st->sst > target->sst && ov_st->sst <= target->est) {
			// the end range is included, so update the est.
			target->est = ov_st->sst;
		}

		if (ov_st->sst <= target->sst && ov_st->est > target->sst) {
			// the start range is included, so update the sst.
			target->sst = ov_st->est;
		}
	}
}