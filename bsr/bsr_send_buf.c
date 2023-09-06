/*
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, bsr@mantech.co.kr

	Windows BSR is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows BSR is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows BSR; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "bsr_int.h"
#ifdef _WIN
#include "bsr-kernel-compat/windows/bsr_windows.h"
#include "../bsr-platform/windows/bsrvflt/wsk_wrapper.h"
#include "bsr-kernel-compat/windows/bsr_wingenl.h"
#include "bsr-kernel-compat/windows/bsr_endian.h"
#include "bsr-kernel-compat/windows/idr.h"
#include "../bsr-platform/windows/bsrvflt/disp.h" 
#include "bsr_send_buf.h"
#else // _LIN
#include <linux/vmalloc.h>
#include <linux/net.h>
#include <net/sock.h>
#endif
#include "../bsr-headers/linux/bsr_limits.h"

#ifdef _SEND_BUF
#define EnterCriticalSection mutex_lock
#define LeaveCriticalSection mutex_unlock

struct buffer {
	void *base;
	void *pos;
};

struct bsr_tcp_transport {
	struct bsr_transport transport; /* Must be first! */
	spinlock_t paths_lock;
	ULONG_PTR flags;
	struct socket *stream[2];
	struct buffer rbuf[2];
#ifdef _LIN_SEND_BUF
	struct _buffering_attr buffering_attr[2];
#endif
};

#ifdef _LIN_SEND_BUF
#define FALSE false;
#define TRUE true;
#endif

bool alloc_bab(struct bsr_connection* connection, struct net_conf* nconf) 
{
	ring_buffer* ring = NULL;
	signed long long sz = 0;

	if(0 == nconf->sndbuf_size) {
		return FALSE;
	}

	do {
		if(nconf->sndbuf_size < BSR_SNDBUF_SIZE_MIN ) {
			bsr_err(3, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to allocate data stream buffer because send-buffer is smaller than the minimum size. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
			goto $ALLOC_FAIL;
		}
#ifdef _WIN_SEND_BUF
		__try {
#endif
			sz = sizeof(*ring) + nconf->sndbuf_size;
#ifdef _WIN_SEND_BUF
			ring = (ring_buffer*)ExAllocatePoolWithTag(NonPagedPool|POOL_RAISE_IF_ALLOCATION_FAILURE, (size_t)sz, '0ASB'); //POOL_RAISE_IF_ALLOCATION_FAILURE flag is required for big pool
#else // _LIN_SEND_BUF
			// BSR-453 Exception handling when there is not enough memory available
			ring = (ring_buffer*)bsr_kvmalloc((size_t)sz, GFP_ATOMIC | __GFP_NOWARN);
#endif
			if(!ring) {
				bsr_err(62, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate data send buffer. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
				goto $ALLOC_FAIL;
			}
			memset(ring, 0, sizeof(ring_buffer));
			mutex_init(&ring->cs);
			// DW-1927 Sets the size value when the buffer is allocated.
			ring->length = nconf->sndbuf_size + 1;
#ifdef _WIN_SEND_BUF
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			bsr_err(5, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to allocate data stream buffer due to EXCEPTION_EXECUTE_HANDLER. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
			if(ring) {
				ExFreePool(ring);
			}
			goto $ALLOC_FAIL;
		}
#endif
		
		connection->ptxbab[DATA_STREAM] = ring;
		INIT_LIST_HEAD(&ring->packet_list);
#ifdef _WIN_SEND_BUF
		__try {
#endif
			sz = sizeof(*ring) + CONTROL_BUFF_SIZE; // meta bab is about 5MB
#ifdef _WIN_SEND_BUF
			ring = (ring_buffer*)ExAllocatePoolWithTag(NonPagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE, (size_t)sz, '2ASB');
#else // _LIN_SEND_BUF
			// BSR-453 Exception handling when there is not enough memory available
			ring = (ring_buffer*)bsr_kvmalloc((size_t)sz, GFP_ATOMIC | __GFP_NOWARN);
#endif
			if(!ring) {
				bsr_err(92, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate data send buffer. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
#ifdef _LIN
				sub_kvmalloc_mem_usage(connection->ptxbab[DATA_STREAM], sizeof(*ring) + nconf->sndbuf_size);
#endif
				kvfree2(connection->ptxbab[DATA_STREAM]); // fail, clean data bab
				goto $ALLOC_FAIL;
			}
			memset(ring, 0, sizeof(ring_buffer));
			mutex_init(&ring->cs);
			// DW-1927 Sets the size value when the buffer is allocated.
			ring->length = CONTROL_BUFF_SIZE + 1;
#ifdef _WIN_SEND_BUF
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			bsr_err(93, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate meta send buffer due to EXCEPTION_EXECUTE_HANDLER. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
			if(ring) {
				ExFreePool(ring);
			}
			goto $ALLOC_FAIL;
		}
#endif
		connection->ptxbab[CONTROL_STREAM] = ring;
		INIT_LIST_HEAD(&ring->packet_list);
		
	} while (false);

	bsr_info(8, BSR_LC_SEND_BUFFER, NO_OBJECT, "Send buffer allocation succeeded. peer node id(%u) send buffer size(%llu)", connection->peer_node_id, nconf->sndbuf_size);
	return TRUE;

$ALLOC_FAIL:
	connection->ptxbab[DATA_STREAM] = NULL;
	connection->ptxbab[CONTROL_STREAM] = NULL;
	return FALSE;
}

void destroy_packet_list(struct bsr_connection* connection)
{
	struct send_buf_packet_info *packet_info, *tmp;

	if (connection->ptxbab[DATA_STREAM] != NULL) {
		list_for_each_entry_safe_ex(struct send_buf_packet_info, packet_info, tmp, &connection->ptxbab[DATA_STREAM]->packet_list, list) {
			list_del(&packet_info->list);
			bsr_kfree(packet_info);
		}
	}

	if (connection->ptxbab[CONTROL_STREAM] != NULL) {
		list_for_each_entry_safe_ex(struct send_buf_packet_info, packet_info, tmp, &connection->ptxbab[CONTROL_STREAM]->packet_list, list) {
			list_del(&packet_info->list);
			bsr_kfree(packet_info);
		}
	}
}

void destroy_bab(struct bsr_connection* connection)
{
	// BSR-879 removed unsent packet information
	destroy_packet_list(connection);

	kvfree2(connection->ptxbab[DATA_STREAM]);
	kvfree2(connection->ptxbab[CONTROL_STREAM]);
	return;
}

ring_buffer *create_ring_buffer(struct bsr_connection* connection, char *name, signed long long length, enum bsr_stream stream)
{
	ring_buffer *ring;
	signed long long sz = sizeof(*ring) + length;

	if (length == 0 || length > BSR_SNDBUF_SIZE_MAX) {
		bsr_err(9, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to create send buffer due to incorrect size. name(%s), max(%ld), size(%lld)", name, length, BSR_SNDBUF_SIZE_MAX);
		return NULL;
	}

	//ring = (ring_buffer *) ExAllocatePoolWithTag(NonPagedPool, sz, '0ASB');
	if(stream == DATA_STREAM) {
		ring = connection->ptxbab[DATA_STREAM];
	} else {
		ring = connection->ptxbab[CONTROL_STREAM];
	}
	if (ring) {
		ring->mem = (char*) (ring + 1);
		ring->read_pos = 0;
		ring->write_pos = 0;
		ring->que = 0;
		ring->deque = 0;
		ring->seq = 0;
		ring->name = name;
		ring->sk_wmem_queued = 0;
		memset(ring->packet_cnt, 0, sizeof(ring->packet_cnt));
		memset(ring->packet_size, 0, sizeof(ring->packet_size));

		mutex_init(&ring->cs);

		//bsr_info(10, BSR_LC_SEND_BUFFER, NO_OBJECT,"bab(%s) size(%d)", name, length);
#ifdef SENDBUF_TRACE
		INIT_LIST_HEAD(&ring->send_req_list);
#endif
		INIT_LIST_HEAD(&ring->packet_list);
#ifdef _WIN_SEND_BUF
		ring->static_big_buf = (char *) ExAllocatePoolWithTag(NonPagedPool, MAX_ONETIME_SEND_BUF, '1ASB');
#else
		// BSR-453 Exception handling when there is not enough memory available
		ring->static_big_buf = (char *)bsr_kvmalloc(MAX_ONETIME_SEND_BUF, GFP_ATOMIC | __GFP_NOWARN);
#endif
		if (!ring->static_big_buf) {
			//ExFreePool(ring);
			//kfree2(ring);
			bsr_err(37, BSR_LC_MEMORY, NO_OBJECT, "Failed to create stream buffer due to failure to allocate memory for static big buffer. name(%s), size(%d)", name, MAX_ONETIME_SEND_BUF);
			return NULL;
		}
	} else {
		bsr_err(12, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to create send-buffer due to failure to get stream information. name(%s) size(%lld)", name, sz);
	}
	return ring;
}

void destroy_ring_buffer(ring_buffer *ring)
{
	if (ring) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(ring->static_big_buf, MAX_ONETIME_SEND_BUF);
#endif
		kvfree2(ring->static_big_buf);
		//ExFreePool(ring);
 		//kfree2(ring);
	}
}

signed long long get_ring_buffer_size(ring_buffer *ring)
{
	signed long long s;
	if (!ring) {
		return 0;
	}

	EnterCriticalSection(&ring->cs);
	s = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	LeaveCriticalSection(&ring->cs);

	return s;
}

// BSR-571
void add_packet_list(ring_buffer *ring, const char *data, signed long long write_len)
{
	struct p_header80 *h80 = (struct p_header80*)data;
	struct p_header95 *h95 = (struct p_header95*)data;
	struct p_header100 *h100 = (struct p_header100*)data;
	uint32_t length = 0;

	if (be32_to_cpu(h80->magic) == BSR_MAGIC) {
		ring->last_send_cmd = be16_to_cpu(h80->command);
		length = sizeof(*h80) + be16_to_cpu(h80->length);
	}
	else if (be32_to_cpu(h95->magic) == BSR_MAGIC_BIG) {
		ring->last_send_cmd = be16_to_cpu(h95->command);
		length = sizeof(*h95) + be32_to_cpu(h95->length);
	}
	else if	(be32_to_cpu(h100->magic) == BSR_MAGIC_100) {
		ring->last_send_cmd = be16_to_cpu(h100->command);
		length = sizeof(*h100) + be32_to_cpu(h100->length);
	}
	
	if (length > 0) {
		struct send_buf_packet_info* temp = bsr_kmalloc(sizeof(struct send_buf_packet_info), GFP_ATOMIC|__GFP_NOWARN, '8ASB');
		if (!temp) {
			struct send_buf_packet_info *packet_info, *tmp;
			bsr_warn(91, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate memory initialize packet info in send buffer");
			// BSR-571 if packet list add fails, it is not guaranteed that the current list is sequential, so all are initialized.
			memset(ring->packet_cnt, 0, sizeof(ring->packet_cnt));
			memset(ring->packet_size, 0, sizeof(ring->packet_size));
			list_for_each_entry_safe_ex(struct send_buf_packet_info, packet_info, tmp, &ring->packet_list, list) {
				list_del(&packet_info->list);
				bsr_kfree(packet_info);
			}
			INIT_LIST_HEAD(&ring->packet_list);
			return;
		}
		INIT_LIST_HEAD(&temp->list);
		temp->cmd = ring->last_send_cmd;
		temp->size = length;
		list_add_tail(&temp->list, &ring->packet_list);
		ring->packet_cnt[ring->last_send_cmd]++;
	}
	ring->packet_size[ring->last_send_cmd] += write_len;
}

void remove_packet_list(ring_buffer *ring, signed long long length)
{
	struct send_buf_packet_info *packet_info, *tmp;

	list_for_each_entry_safe_ex(struct send_buf_packet_info, packet_info, tmp, &ring->packet_list, list) {
		if (length >= packet_info->size) {
			length -= packet_info->size;
			ring->packet_cnt[packet_info->cmd]--;
			ring->packet_size[packet_info->cmd] -= packet_info->size;
			list_del(&packet_info->list);
			bsr_kfree(packet_info);
		} else {
			packet_info->size -= (uint32_t)length;
			ring->packet_size[packet_info->cmd] -= length;
			break;
		}
	}
}

signed long long write_ring_buffer(struct bsr_transport *transport, enum bsr_stream stream, ring_buffer *ring, const char *data, signed long long len, signed long long highwater, int retry)
{
	signed long long remain;
	signed long long ringbuf_size = 0;

	EnterCriticalSection(&ring->cs);

	ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;

	if ((ringbuf_size + len) > highwater) {
		int loop = 0;

		LeaveCriticalSection(&ring->cs);
		// DW-764 remove debug print "kocount" when congestion is not occurred.
		// BSR-983 removes a function to retry with kocount (bsr_stream_send_timed_out())
		for (loop = 0; loop < retry; loop++) {
			struct bsr_tcp_transport *tcp_transport;

			msleep(100);

			tcp_transport =	container_of(transport, struct bsr_tcp_transport, transport);

#ifdef _WIN_SEND_BUF
			if (tcp_transport->stream[stream]) {
				if (tcp_transport->stream[stream]->buffering_attr.quit == TRUE)	{
					bsr_info(13, BSR_LC_SEND_BUFFER, NO_OBJECT, "Quit the send buffer with the quit settings.");
					return -EIO;
				}
			}
#else // _LIN_SEND_BUF
			if (tcp_transport) {
				if (tcp_transport->buffering_attr[stream].quit == true)	{
					bsr_info(14, BSR_LC_SEND_BUFFER, NO_OBJECT,"Quit the send buffer with the quit settings.");
					return -EIO;
				}
			}
#endif
			EnterCriticalSection(&ring->cs);
			ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
			if ((ringbuf_size + len) > highwater) {
			} else {
				goto $GO_BUFFERING;
			}
			LeaveCriticalSection(&ring->cs);
		}
		 		
		return -EAGAIN;
	}

$GO_BUFFERING:

	remain = (ring->read_pos - ring->write_pos - 1 + ring->length) % ring->length;
	if (remain < len) {
		len = remain;
	}

	if (len > 0) {
		remain = ring->length - ring->write_pos;
		if (remain < len) {
			memcpy(ring->mem + (ring->write_pos), data, (size_t)remain);
			memcpy(ring->mem, data + remain, (size_t)(len - remain));
		} else {
			memcpy(ring->mem + ring->write_pos, data, (size_t)len);
		}

		ring->write_pos += len;
		ring->write_pos %= ring->length;

		// BSR-571
		add_packet_list(ring, data, len);
	}
	else {
		bsr_err(302, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to write ring buffer due to unknown reasons");
		BUG();
	}

	ring->que++;
	ring->seq++;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length;

	LeaveCriticalSection(&ring->cs);

	return len;
}

#ifdef _WIN_SEND_BUF
int read_ring_buffer(IN ring_buffer *ring, OUT char *data, OUT signed long long* pLen, bsr_stream stream, LONGLONG *retry_timestamp)
#else // _LIN_SEND_BUF
bool read_ring_buffer(ring_buffer *ring, char *data, signed long long* pLen)
#endif
{
	signed long long remain;
	signed long long ringbuf_size = 0;
	signed long long tx_sz = 0;

	EnterCriticalSection(&ring->cs);
	ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	
	if (ringbuf_size == 0) {
		LeaveCriticalSection(&ring->cs);
		return 0;
	}
 
	tx_sz = (ringbuf_size > MAX_ONETIME_SEND_BUF) ? MAX_ONETIME_SEND_BUF : ringbuf_size;

	// BSR-1116 to minimize send completion callbacks, windows send only when the following conditions are met.
#ifdef _WIN_SEND_BUF
	if (stream == DATA_STREAM) {
		if (*retry_timestamp == 0 && tx_sz < (MAX_ONETIME_SEND_BUF / 10)) {
			LeaveCriticalSection(&ring->cs);
			*retry_timestamp = timestamp();
			return 2;
		}

		if (*retry_timestamp &&
			timestamp_elapse(__FUNCTION__, *retry_timestamp, timestamp()) < (1000 * 1)) {
			LeaveCriticalSection(&ring->cs);
			return 2;
		}
	}
#endif

	remain = ring->length - ring->read_pos;
	if (remain < tx_sz) {
		memcpy(data, ring->mem + ring->read_pos, (size_t)remain);
		memcpy(data + remain, ring->mem, (size_t)(tx_sz - remain));
	}
	else {
		memcpy(data, ring->mem + ring->read_pos, (size_t)tx_sz);
	}

	ring->read_pos += tx_sz;
	ring->read_pos %= ring->length;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	*pLen = tx_sz;

	// BSR-571
	remove_packet_list(ring, tx_sz);
	LeaveCriticalSection(&ring->cs);
	
	return 1;
}

#ifdef _WIN_SEND_BUF
int send_buf(struct bsr_transport *transport, enum bsr_stream stream, socket *socket, PVOID buf, LONG size)
{
	struct _buffering_attr *buffering_attr = &socket->buffering_attr;
	ULONG timeout = socket->sk_linux_attr->sk_sndtimeo;

	if (buffering_attr->send_buf_thread_handle == NULL || buffering_attr->bab == NULL) {
		return Send(socket, buf, size, 0, timeout, NULL, transport, stream);
	}

	signed long long  tmp = (long long)buffering_attr->bab->length * 99;
	signed long long highwater = (signed long long)tmp / 100; // 99% // refacto: global
	// performance tuning point for delay time
	int retry = socket->sk_linux_attr->sk_sndtimeo / 100; //retry default count : 6000/100 = 60 => write buffer delay time : 100ms => 60*100ms = 6sec //retry default count : 6000/20 = 300 => write buffer delay time : 20ms => 300*20ms = 6sec

	size = (LONG)write_ring_buffer(transport, stream, buffering_attr->bab, buf, size, highwater, retry);

	KeSetEvent(&buffering_attr->ring_buf_event, 0, FALSE);
	return (int)size;
}
#else // _LIN_SEND_BUF
int send_buf(struct bsr_tcp_transport *tcp_transport, enum bsr_stream stream, struct socket *socket, void *buf, size_t size, unsigned msg_flags)
{
	struct _buffering_attr *buffering_attr = &tcp_transport->buffering_attr[stream];
	signed long long tmp;
	signed long long highwater;
	int retry;

	if (buffering_attr->send_buf_thread_handle == NULL || buffering_attr->bab == NULL) {
		struct kvec iov;
		struct msghdr msg;

		iov.iov_base = buf;
		iov.iov_len  = size;

		msg.msg_name       = NULL;
		msg.msg_namelen    = 0;
		msg.msg_control    = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

		return bsr_kernel_sendmsg(&tcp_transport->transport, socket, &msg, &iov);
	}

	tmp = (long long)buffering_attr->bab->length * 99;
	highwater = (signed long long)tmp / 100; // 99% // refacto: global
	// performance tuning point for delay time
	retry = socket->sk->sk_sndtimeo / 100;
	
	size = write_ring_buffer(&tcp_transport->transport, stream, buffering_attr->bab, buf, size, highwater, retry);

	set_bit(RING_BUF_EVENT, &buffering_attr->flags);
	wake_up(&buffering_attr->ring_buf_event);
	return (int)size;
}
#endif

#ifdef _WIN_SEND_BUF
int do_send(struct bsr_transport *transport, bsr_stream stream, struct socket *socket, struct ring_buffer *bab, int timeout, KEVENT *send_buf_kill_event)
{
	UNREFERENCED_PARAMETER(send_buf_kill_event);
	LONGLONG try_timestamp;

	int ret = 0;

	if (bab == NULL) {
		bsr_err(16, BSR_LC_SEND_BUFFER, NO_OBJECT, "Failed to send send-buffer due to send-buffer is not allocate.");
		return 0;
	}

	while (true) {
		long long tx_sz = 0;
		int offset = 0;

		// BSR-1116
		ret = read_ring_buffer(bab, bab->static_big_buf, &tx_sz, stream, &try_timestamp);
		if (ret == 2) {
			msleep(1);
			continue;
		} else if (ret == 0)
			break;

		try_timestamp = 0;

#ifndef _WIN64
		BUG_ON_UINT32_OVER(tx_sz);
#endif
		// BSR-983
		transport->ko_count[stream] = transport->net_conf->ko_count;

		while (tx_sz > 0) {
#if 0
			// DW-1095 SendAsync is only used on Async mode (adjust retry_count) 
			//ret = SendAsync(socket, bab->static_big_buf, tx_sz, 0, timeout, NULL, 0);
#endif
			ret = Send(socket, bab->static_big_buf + offset, (ULONG)tx_sz, 0, timeout, NULL, transport, 0);
			if (ret < 0) {
				if (ret == -EAGAIN) {
					// BSR-983 limit resend to the following functions when sending send buffer data
					if (!bsr_stream_send_timed_out(transport, stream))
						continue;
				}

				bsr_info(17, BSR_LC_SEND_BUFFER, NO_OBJECT, "Send Error(%d)", ret);
				return ret;
			}
			tx_sz -= ret;
			offset += ret;
		}
	}

	return ret;
}
#else // _LIN_SEND_BUF
int do_send(struct bsr_transport *transport, bsr_stream stream, struct socket *socket, struct ring_buffer *bab, int timeout)
{
	int rv = 0;
	int msg_flags = 0;

	if (bab == NULL) {
		bsr_err(19, BSR_LC_SEND_BUFFER, NO_OBJECT,"Failed to send ring buffer due to ring buffer is not allocate.");
		return 0;
	}

	while (true) {
		long long tx_sz = 0;
		int offset = 0;
		struct kvec iov;
		struct msghdr msg;

		if (!read_ring_buffer(bab, bab->static_big_buf, &tx_sz)) {
			break;
		}
		
		// BSR-983
		transport->ko_count[stream] = transport->net_conf->ko_count;

		while(tx_sz > 0) {
			iov.iov_base = bab->static_big_buf + offset;
			iov.iov_len  = (unsigned long)tx_sz;

			msg.msg_name       = NULL;
			msg.msg_namelen    = 0;
			msg.msg_control    = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

			rv = bsr_kernel_sendmsg(transport, socket, &msg, &iov);

			if (rv <= 0) {
				if (rv == -EAGAIN) {
					// BSR-983 limit resend to the following functions when sending send buffer data
					if(!bsr_stream_send_timed_out(transport, stream)) 
						continue;
				} 
				
				if (rv == -EINTR) {
					flush_signals(current);
					rv = 0;
				} else {
					bsr_err(36, BSR_LC_SEND_BUFFER, NO_OBJECT, "Send Error(%d)", rv);
					return rv;
				}
			}
			tx_sz -= rv;
			offset += rv;
		}
	}

	return rv;
}
#endif

//
// send buffring thread
//
#ifdef _WIN_SEND_BUF
VOID NTAPI send_buf_thread(PVOID p)
{
	struct bsr_tcp_transport* tcp_transport = (struct bsr_tcp_transport *)p;
	struct _buffering_attr *buffering_attr;
	struct socket *socket;
	NTSTATUS status;
	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;
	bsr_stream stream;

	if (test_bit(IDX_STREAM, &tcp_transport->flags))
		stream = CONTROL_STREAM;
	else
		stream = DATA_STREAM;

	buffering_attr = &tcp_transport->stream[stream]->buffering_attr;
	socket = container_of(buffering_attr, struct socket, buffering_attr);

	ct_add_thread((int)PsGetCurrentThreadId(), "sendbuf", FALSE, '25SB');

	buffering_attr->quit = FALSE;

	//KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);
	//bsr_info(51, BSR_LC_ETC, NO_OBJECT,"start send_buf_thread");

	KeSetEvent(&buffering_attr->send_buf_thr_start_event, 0, FALSE);
	nWaitTime = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * 10);
	pTime = &nWaitTime;

#define MAX_EVT		2
	PVOID waitObjects[MAX_EVT];
	waitObjects[0] = &buffering_attr->send_buf_kill_event;
	waitObjects[1] = &buffering_attr->ring_buf_event;

	while (true) {
		status = KeWaitForMultipleObjects(MAX_EVT, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
		switch (status) {
		case STATUS_TIMEOUT:
			break;

		case STATUS_WAIT_0:
			bsr_info(20, BSR_LC_SEND_BUFFER, NO_OBJECT, "Response kill-ack-event");
			goto done;

		case (STATUS_WAIT_0 + 1) :
			if (do_send(&tcp_transport->transport, stream, socket, buffering_attr->bab, socket->sk_linux_attr->sk_sndtimeo, &buffering_attr->send_buf_kill_event) < 0) {
				goto done;
			}
			break;

		default:
			bsr_err(21, BSR_LC_SEND_BUFFER, NO_OBJECT, "Unexpected wakeup case(0x%x). ignore.", status);
			goto done;
		}
	}

done:
	bsr_info(22, BSR_LC_SEND_BUFFER, NO_OBJECT, "Send buffer kill-ack-event");
	KeSetEvent(&buffering_attr->send_buf_killack_event, 0, FALSE);
	bsr_info(23, BSR_LC_SEND_BUFFER, NO_OBJECT, "Send buffer thread[%p] terminate", KeGetCurrentThread());
	ct_delete_thread((int)PsGetCurrentThreadId());
	PsTerminateSystemThread(STATUS_SUCCESS);
}
#else // _LIN_SEND_BUF
int send_buf_thread(void *p)
{
	struct bsr_tcp_transport *tcp_transport = (struct bsr_tcp_transport *)p;
	//struct bsr_tcp_transport *tcp_transport = container_of(buffering_attr, struct bsr_tcp_transport, buffering_attr);
	struct socket *socket;
	struct _buffering_attr *buffering_attr;
	int ret = 0;
	bsr_stream stream;
	
	long timeo = 1 * HZ;

	if (test_bit(IDX_STREAM, &tcp_transport->flags)) 
		stream = CONTROL_STREAM;
	else
		stream = DATA_STREAM;

	socket = tcp_transport->stream[stream];
	buffering_attr = &tcp_transport->buffering_attr[stream];

	buffering_attr->quit = false;

	set_bit(SEND_BUF_START, &buffering_attr->flags);
	wake_up(&buffering_attr->send_buf_thr_start_event);

	while (!buffering_attr->send_buf_kill_event) {
		wait_event_timeout_ex(buffering_attr->ring_buf_event, test_bit(RING_BUF_EVENT, &buffering_attr->flags), timeo, ret);
		// BSR-750 fix potential hang when using send buffer in protocol c
		// RING_BUF_EVENT flag setting race between send_buf_thread() and send_buf()
		if(test_and_clear_bit(RING_BUF_EVENT, &buffering_attr->flags)) {
			if (do_send(&tcp_transport->transport, stream, socket, buffering_attr->bab, socket->sk->sk_sndtimeo) < 0) {
				break;
			}
		}
	}

	bsr_info(24, BSR_LC_SEND_BUFFER, NO_OBJECT,"Send buffer kill-ack-event");
	set_bit(SEND_BUF_KILLACK, &buffering_attr->flags);
	wake_up(&buffering_attr->send_buf_killack_event);
	bsr_info(25, BSR_LC_SEND_BUFFER, NO_OBJECT,"Send buffer thread terminate!!");
	return 0;
}
#endif
#endif // _SEND_BUF