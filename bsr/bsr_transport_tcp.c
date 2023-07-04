/*
   bsr_transport_tcp.c

   This file is part of BSR.

   Copyright (C) 2014-2020, Man Technology inc.

   bsr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   bsr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with bsr; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#include "bsr_int.h"
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/bsr_transport.h"
#ifdef _WIN
#include <wsk_wrapper.h>
#include "./bsr-kernel-compat/windows/bsr_endian.h"
#include "../bsr-headers/linux/bsr_limits.h"
#else // _LIN
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#endif
#include "../bsr-headers/bsr_protocol.h"
#include "./bsr-kernel-compat/bsr_wrappers.h"
#include "../bsr-headers/linux/bsr_genl_api.h"

// The existing bsr_transport_tcp module has been integrated into bsr.
//#ifdef _LIN
//MODULE_AUTHOR("Man Technology inc <bsr@mantech.co.kr>");
//MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for BSR");
//MODULE_LICENSE("GPL");
//MODULE_VERSION("1.0.0");
//#endif


struct buffer {
	void *base;
	void *pos;
};

#define DTT_CONNECTING 1

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

struct dtt_listener {
	struct bsr_listener listener;
	void (*original_sk_state_change)(struct sock *sk);
	struct socket *s_listen;
#ifdef _WIN
	struct socket * paccept_socket;
#endif
	wait_queue_head_t wait; /* woken if a connection came in */
};

/* Since each path might have a different local IP address, each
path might need its own listener. Therefore the bsr_waiter object
is embedded into the dtt_path and _not_ the dtt_waiter */
#ifdef _LIN
struct dtt_socket_container {
	struct list_head list;
	struct socket *socket;
};
#endif

struct dtt_path {
	struct bsr_path path;
#ifdef _WIN
	struct socket *socket;
#else // _LIN
	struct list_head sockets; /* sockets passed to me by other receiver threads */
#endif
};

#ifdef _WIN
WSK_CLIENT_CONNECTION_DISPATCH dispatchDisco = { NULL, WskDisconnectEvent, NULL };
#endif

static int dtt_init(struct bsr_transport *transport);
static void dtt_free(struct bsr_transport *transport, enum bsr_tr_free_op free_op);
static int dtt_connect(struct bsr_transport *transport);
static int dtt_recv(struct bsr_transport *transport, enum bsr_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct bsr_transport *transport, struct bsr_page_chain_head *chain, size_t size);
static void dtt_stats(struct bsr_transport *transport, struct bsr_transport_stats *stats);
static void dtt_set_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream);
static int dtt_send_page(struct bsr_transport *transport, enum bsr_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtt_send_zc_bio(struct bsr_transport *, struct bio *bio);
static bool dtt_stream_ok(struct bsr_transport *transport, enum bsr_stream stream);
static bool dtt_hint(struct bsr_transport *transport, enum bsr_stream stream, enum bsr_tr_hints hint);
static void dtt_debugfs_show(struct bsr_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct bsr_tcp_transport *tcp_transport);
static int dtt_add_path(struct bsr_transport *, struct bsr_path *path);
static int dtt_remove_path(struct bsr_transport *, struct bsr_path *);
#ifdef _SEND_BUF
static bool dtt_start_send_buffring(struct bsr_transport *, signed long long size);
static void dtt_stop_send_buffring(struct bsr_transport *);
#endif

static struct bsr_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct bsr_tcp_transport),
	.path_instance_size = sizeof(struct dtt_path),
#ifdef _LIN
	.module = THIS_MODULE,
#endif
	.init = dtt_init,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static struct bsr_transport_ops dtt_ops = {
	.free = dtt_free,
	.connect = dtt_connect,
	.recv = dtt_recv,
	.recv_pages = dtt_recv_pages,
	.stats = dtt_stats,
	.set_rcvtimeo = dtt_set_rcvtimeo,
	.get_rcvtimeo = dtt_get_rcvtimeo,
	.send_page = dtt_send_page,
	.send_zc_bio = dtt_send_zc_bio,
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
#ifdef _SEND_BUF
	.start_send_buffring = dtt_start_send_buffring,
	.stop_send_buffring = dtt_stop_send_buffring,
#endif
};


/* Might restart iteration, if current element is removed from list!! */
#define for_each_path_ref(path, transport)			\
	for (path = __bsr_next_path_ref(NULL, transport);	\
	     path;						\
	     path = __bsr_next_path_ref(path, transport))

// BSR-683
#ifdef _LIN
int bsr_kernel_sendmsg(struct bsr_transport *transport, struct socket *socket, struct msghdr *msg, struct kvec *iov) {
	int rv;

	rv = kernel_sendmsg(socket, msg, iov, 1, iov->iov_len);
	// BSR-764 delay socket send
	if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE4) 
		force_delay(g_simul_perf.delay_time);
	if (atomic_read(&g_bsrmon_run) && (rv > 0) && transport)
		atomic_add64(rv, &transport->sum_sent);

	return rv;
}

int bsr_kernel_recvmsg(struct bsr_transport *transport, struct socket *socket, struct msghdr *msg, struct kvec *iov) {
	int rv;

	rv = kernel_recvmsg(socket, msg, iov, 1, iov->iov_len, msg->msg_flags);
	// BSR-764 delay socket receive
	if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE5) 
		force_delay(g_simul_perf.delay_time);
	if (atomic_read(&g_bsrmon_run) && (rv > 0) && transport)
		atomic_add64(rv, &transport->sum_recv);

	return rv;
}
#endif

/* This is save as long you use list_del_init() everytime something is removed
from the list. */
static struct bsr_path *__bsr_next_path_ref(struct bsr_path *bsr_path,
struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);

	spin_lock(&tcp_transport->paths_lock);
	if (!bsr_path) {
		bsr_path = list_first_entry_or_null(&transport->paths, struct bsr_path, list);
	}
	else {
		bool in_list = !list_empty(&bsr_path->list);
		kref_put(&bsr_path->kref, bsr_destroy_path);
		if (in_list) {
			/* Element still on the list, ref count can not drop to zero! */
			if (list_is_last(&bsr_path->list, &transport->paths))
				bsr_path = NULL;
			else{
				bsr_path = list_next_entry_ex(struct bsr_path, bsr_path, list);
			}
		}
		else {
			/* No longer on the list, element might be freed already, restart from the start */
			bsr_path = list_first_entry_or_null(&transport->paths, struct bsr_path, list);
		}
	}
	if (bsr_path)
		kref_get(&bsr_path->kref);
	spin_unlock(&tcp_transport->paths_lock);

	return bsr_path;
}

static void dtt_nodelay(struct socket *socket)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(socket);
	// nagle disable is supported (registry configuration)
#else // _LIN
#ifdef COMPAT_HAVE_TCP_SOCK_SET_NODELAY
    tcp_sock_set_nodelay(socket->sk);
#else
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
#endif
#endif
}

int dtt_init(struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	enum bsr_stream i;

	spin_lock_init(&tcp_transport->paths_lock);
	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
#ifdef _WIN
		void *buffer = kzalloc(4096, GFP_KERNEL, '09SB');
		if (!buffer) {
			tcp_transport->rbuf[i].base = NULL;
			bsr_warn(87, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate 4096 size memory for %s", i ? "CONTROL_STREAM" : "DATA_STREAM");
			goto fail;
		}
#else  // _LIN
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
#endif
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}

	return 0;
fail:
#ifdef _WIN
	kfree2(tcp_transport->rbuf[0].base);
#else // _LIN
	free_page((unsigned long)tcp_transport->rbuf[0].base);
#endif
	return -ENOMEM;
}

// DW-1204 added argument bFlush.
#ifdef _LIN_SEND_BUF
static void dtt_free_one_sock(struct socket *socket, bool bFlush, struct _buffering_attr *attr)
#else // _WIN_SEND_BUF, _LIN, _WIN
static void dtt_free_one_sock(struct socket *socket, bool bFlush)
#endif
{
	if (socket) {
#ifdef _LIN
		synchronize_rcu();
#endif

#ifdef _SEND_BUF
		// DW-1204 flushing send buffer takes too long when network is slow, just shut it down if possible.
		if (!bFlush)
			kernel_sock_shutdown(socket, SHUT_RDWR);
		

#ifdef _WIN_SEND_BUF
		struct _buffering_attr *attr = &socket->buffering_attr;
        if (attr->send_buf_thread_handle) {
            KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
            KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
			//ZwClose (attr->send_buf_thread_handle);
            attr->send_buf_thread_handle = NULL;
        }
#else // _LIN_SEND_BUF
		if (attr->send_buf_thread_handle) {
			attr->send_buf_kill_event = true;
			wait_event(attr->send_buf_killack_event, test_bit(SEND_BUF_KILLACK, &attr->flags));
			clear_bit(SEND_BUF_KILLACK, &attr->flags);
			//ZwClose (attr->send_buf_thread_handle);
            attr->send_buf_thread_handle = NULL;

			// BSR-12 its code present in sock_release() of bsr.
			if(attr->bab) {
				if(attr->bab->static_big_buf) {
					sub_kvmalloc_mem_usage(attr->bab->static_big_buf, MAX_ONETIME_SEND_BUF);
					kvfree(attr->bab->static_big_buf);
				}
			}
        }
#endif
#endif

		// DW-1173 shut the socket down after send buf thread goes down.
		if (bFlush) // DW-1204
			kernel_sock_shutdown(socket, SHUT_RDWR);

		sock_release(socket);
	}
}

static void dtt_free(struct bsr_transport *transport, enum bsr_tr_free_op free_op)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	enum bsr_stream i;
	struct bsr_path *bsr_path;
	/* free the socket specific stuff,
	 * mutexes are handled by caller */


	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
			// DW-1204 provide boolean if send buffer has to be flushed.
#ifdef _LIN_SEND_BUF
			dtt_free_one_sock(tcp_transport->stream[i], test_bit(DISCONNECT_FLUSH, &transport->flags), &tcp_transport->buffering_attr[i]);
#else // _WIN_SEND_BUF, _LIN, _WIN
			dtt_free_one_sock(tcp_transport->stream[i], test_bit(DISCONNECT_FLUSH, &transport->flags));
#endif
			clear_bit(DISCONNECT_FLUSH, &transport->flags);

			tcp_transport->stream[i] = NULL;
#ifdef _LIN_SEND_BUF
			// BSR-12 NULL assignment of bab for reallocation on reconnection.
			tcp_transport->buffering_attr[i].bab = NULL;
#endif
		}
	}

	for_each_path_ref(bsr_path, transport) {
		bool was_established = bsr_path->established;
		bsr_path->established = false;
		if (was_established)
			bsr_path_event(transport, bsr_path);
	}

	if (free_op == DESTROY_TRANSPORT) {
		struct bsr_path *tmp;

		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
#ifdef _WIN
			kfree((void *)tcp_transport->rbuf[i].base);
#else // _LIN
			free_page((unsigned long)tcp_transport->rbuf[i].base);
#endif	
			tcp_transport->rbuf[i].base = NULL;
		}
		spin_lock(&tcp_transport->paths_lock);
		list_for_each_entry_safe_ex(struct bsr_path, bsr_path, tmp, &transport->paths, list) {
			list_del_init(&bsr_path->list);
			kref_put(&bsr_path->kref, bsr_destroy_path);
		}
		spin_unlock(&tcp_transport->paths_lock);
	}
}

static int _dtt_send(struct bsr_tcp_transport *tcp_transport, struct socket *socket,
		      void *buf, size_t size, unsigned msg_flags)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(tcp_transport);
	UNREFERENCED_PARAMETER(msg_flags);
	size_t iov_len = size;
	char* DataBuffer = (char*)buf;
#else // _LIN
	struct kvec iov;
	struct msghdr msg;
#endif
	int rv, sent = 0;

	/* THINK  if (signal_pending) return ... ? */
#ifdef _WIN
	BUG_ON_UINT32_OVER(iov_len); 
	// not support. 
#else // _LIN
	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;
#endif

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block BSR_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
#ifdef _WIN
#ifdef _WIN_SEND_BUF
		 // _dtt_send is only used when dtt_connect is processed(dtt_send_first_packet), at this time send buffering is not done yet.
		rv = Send(socket, DataBuffer, (ULONG)iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, &tcp_transport->transport, 0);
#else
		rv = Send(socket, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, &tcp_transport->transport, 0);
#endif
#else  // _LIN
		rv = bsr_kernel_sendmsg(&tcp_transport->transport, socket, &msg, &iov);
		if (rv == -EAGAIN) {
			struct bsr_transport *transport = &tcp_transport->transport;
			enum bsr_stream stream =
				tcp_transport->stream[DATA_STREAM] == socket ?
					DATA_STREAM : CONTROL_STREAM;

			if (bsr_stream_send_timed_out(transport, stream))
				break;
			else
				continue;
		}
#endif
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
#ifdef _WIN
		DataBuffer += rv;
		iov_len -= rv;
#else // _LIN
		iov.iov_base += rv;
		iov.iov_len  -= rv;
#endif
	} while (sent < (int)size);

	if (rv <= 0)
		return rv;

	return sent;
}

static int dtt_recv_short(struct bsr_transport *transport, struct socket *socket, void *buf, size_t size, int flags)
{
#ifdef _LIN
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};
#endif

#ifdef _WIN
	flags = WSK_FLAG_WAITALL;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(size);
#endif
	return Receive(socket, buf, (unsigned int)size, flags, socket->sk_linux_attr->sk_rcvtimeo, transport);
#else // _LIN
	return bsr_kernel_recvmsg(transport, socket, &msg, &iov);
#endif
}

static int dtt_recv(struct bsr_transport *transport, enum bsr_stream stream, void **buf, size_t size, int flags)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
	unsigned char* buffer = NULL;
	int rv;
	
	if (!socket)
#ifdef _WIN
		return SOCKET_ERROR;
#else // _LIN
		return -ENOTSOCK; //TODO: SOCKET_ERROR is -1, but -ENOTSOCK is -88. so return value is diffrent. required to check.
#endif

	if (flags & CALLER_BUFFER) {
		buffer = *buf;
		rv = dtt_recv_short(transport, socket, buffer, size, flags & ~CALLER_BUFFER);
	} else if (flags & GROW_BUFFER) {
		TR_ASSERT(transport, *buf == tcp_transport->rbuf[stream].base);
		buffer = tcp_transport->rbuf[stream].pos;
		TR_ASSERT(transport, (buffer - (unsigned char*)*buf) + size <= PAGE_SIZE);//gcc void* pointer increment is based by 1 byte operation
		rv = dtt_recv_short(transport, socket, buffer, size, flags & ~GROW_BUFFER);
	} else {
		buffer = tcp_transport->rbuf[stream].base;

		rv = dtt_recv_short(transport, socket, buffer, size, flags);
		if (rv > 0)
			*buf = buffer;
	}

	if (rv > 0)
		tcp_transport->rbuf[stream].pos = buffer + rv;

	return rv;
}

static int dtt_recv_pages(struct bsr_transport *transport, struct bsr_page_chain_head *chain, size_t size)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
	struct page *page;
	int err;

	if (!socket)
#ifdef _WIN
		return SOCKET_ERROR;
#else // _LIN
		return -ENOTSOCK; //TODO: SOCKET_ERROR is -1, but -ENOTSOCK is -88. so return value is diffrent. required to check.
#endif

#ifdef _WIN64
	BUG_ON_UINT32_OVER(DIV_ROUND_UP(size, PAGE_SIZE));
#endif
	bsr_alloc_page_chain(transport, chain, (unsigned int)DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	page = chain->head;
	if (!page)
		return -ENOMEM;

#ifdef _WIN
	err = dtt_recv_short(transport, socket, page, size, 0); // required to verify *peer_req_databuf pointer buffer , size value 's validity
	bsr_debug_rs("kernel_recvmsg(%d) socket(0x%p) size(%d) all_pages(0x%p)", err, socket, (int)size, page);
	if (err < 0) {
		goto fail;
	}
	else if (err != (int)size) {
		// DW-1502 If the size of the received data differs from the expected size, the consistency will be broken.
		bsr_err(23, BSR_LC_SOCKET, NO_OBJECT, "Failed to receive page due to wrong data (expected size:%d, received size:%d)", (int)size, err);
		err = -EIO;		
		
		goto fail;
	}
#else // _LIN
	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(transport, socket, data, len, 0);
		kunmap(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, len);
		bsr_debug_rs("kernel_recvmsg(%d) socket(0x%p) size(%d) data(0x%p)", err, socket, (int)len, data);
		if (err < 0) {
			goto fail;
		}
		else if (err != (int)len) {
			// DW-1502 If the size of the received data differs from the expected size, the consistency will be broken.
			bsr_err(24, BSR_LC_SOCKET, NO_OBJECT,"Failed to receive page due to wrong data (expected size:%d, received size:%d)", (int)len, err);
			err = -EIO;
			goto fail;
		}
		size -= len;
	}
#endif

	return 0;
fail:
	bsr_free_page_chain(transport, chain, 0);
#ifdef _WIN // page count is decreased by free_page, actual allocated memory is freed separately.
	kfree(page);
#endif
	return err;
}

static void dtt_stats(struct bsr_transport *transport, struct bsr_transport_stats *stats)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {
#ifdef _WIN
		struct sock *sk = socket->sk_linux_attr;
#else // _LIN
		struct sock *sk = socket->sk;
		struct tcp_sock *tp = tcp_sk(sk);

		stats->unread_received = tp->rcv_nxt - tp->copied_seq;
		stats->unacked_send = tp->write_seq - tp->snd_una;
#endif
		// not supported
		stats->send_buffer_size = sk->sk_sndbuf;
#ifdef _SEND_BUF
		{
#ifdef _WIN_SEND_BUF
			struct _buffering_attr *buffering_attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
#else // _LIN_SEND_BUF
			struct _buffering_attr *buffering_attr = &tcp_transport->buffering_attr[DATA_STREAM];
#endif
			struct ring_buffer *bab = buffering_attr->bab;
			if (bab) {
				stats->send_buffer_used = bab->sk_wmem_queued;
			} else {
				stats->send_buffer_used = 0; // don't know how to get WSK tx buffer usage yet. Ignore it.
			}
		}
#else
		stats->send_buffer_used = sk->sk_wmem_queued;
#endif
	}
}

static void dtt_setbufsize(struct socket *socket, signed long long snd,
			   unsigned int rcv)
{
#ifdef _WIN
    if (snd) { 
        socket->sk_linux_attr->sk_sndbuf = snd;
    }
    else { 
        socket->sk_linux_attr->sk_sndbuf = BSR_SNDBUF_SIZE_DEF;
    }

    if (rcv) {
        ControlSocket(socket, WskSetOption, SO_RCVBUF, SOL_SOCKET,
            sizeof(unsigned int), &rcv, 0, NULL, NULL);
    }
#else // _LIN
	/* open coded SO_SNDBUF, SO_RCVBUF */
	// BSR-456 When using send buffer, socket buffer uses the default size.
#ifndef _SEND_BUF
	if (snd) {
		socket->sk->sk_sndbuf = snd;
		socket->sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
#endif
	if (rcv) {
		socket->sk->sk_rcvbuf = rcv;
		socket->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
#endif
}

static bool dtt_path_cmp_addr(struct dtt_path *path, struct bsr_connection *connection)
{
	struct bsr_path *bsr_path = &path->path;
	int addr_size;

	addr_size = min(bsr_path->my_addr_len, bsr_path->peer_addr_len);

	// DW-1452 Consider interworking with DRX 
	if (bsr_path->my_addr_len == bsr_path->peer_addr_len) {
		int my_node_id, peer_node_id; 
		bsr_debug_conn("my_addr_len == peer_addr_len compare node_ids"); 
		
		my_node_id = connection->resource->res_opts.node_id; 
		peer_node_id = connection->peer_node_id; 

		bsr_debug_conn("my_node_id = %d, peer_node_id = %d", my_node_id, peer_node_id);
		return my_node_id > peer_node_id; 		 
	}

	return memcmp(&bsr_path->my_addr, &bsr_path->peer_addr, addr_size) > 0;
}


static int dtt_try_connect(struct bsr_transport *transport, struct dtt_path *path, struct socket **ret_socket)
{
	const char *what;
	struct socket *socket;	
	SOCKADDR_STORAGE_EX my_addr, peer_addr;
#ifdef _WIN
	NTSTATUS status = STATUS_UNSUCCESSFUL;
#endif
	struct net_conf *nc;
	int err;
	//int sndbuf_size, rcvbuf_size, connect_int;
	int rcvbuf_size, connect_int; signed long long sndbuf_size;
#ifdef _WIN	
	char sbuf[128] = {0,};
	char dbuf[128] = {0,};
#endif	
	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}

	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();

	my_addr = path->path.my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = path->path.peer_addr;

	what = "sock_create_kern";
#ifdef _WSK_SOCKETCONNECT // DW-1007 replace wskconnect with wsksocketconnect for VIP source addressing problem	

	socket = kzalloc(sizeof(struct socket), 0, 'D1SB');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	_snprintf(socket->name, sizeof(socket->name) - 1, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;

#ifdef _WIN
	socket->sk_state = WSK_DISCONNECTED; 
#endif
 
	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '35SB');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
	socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;
	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	what = "create-connect";

	if (my_addr.ss_family == AF_INET6) {
		bsr_debug(86, BSR_LC_SOCKET, NO_OBJECT,"dtt_try_connect: Connecting: %s -> %s", get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&my_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)&peer_addr));
	} else {
		bsr_debug(87, BSR_LC_SOCKET, NO_OBJECT, "dtt_try_connect: Connecting: %s -> %s", get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&my_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&peer_addr));
	}

	socket->sk = CreateSocketConnect(socket, SOCK_STREAM, IPPROTO_TCP, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, &status, &dispatchDisco, (PVOID*)socket);

	if (!NT_SUCCESS(status)) {
		err = status;
		bsr_debug(88, BSR_LC_SOCKET, NO_OBJECT, "dtt_try_connect: CreateSocketConnect fail status:%x socket->sk:%p", status, socket->sk);
		switch (status) {
		case STATUS_CONNECTION_REFUSED: err = -ECONNREFUSED; break;
		// DW-1272
		// DW-1290 retry CreateSocketConnect if STATUS_INVALID_ADDRESS_COMPONENT
		case STATUS_INVALID_ADDRESS_COMPONENT: err = -EAGAIN; break;
		case STATUS_INVALID_DEVICE_STATE: err = -EAGAIN; break;
		case STATUS_NETWORK_UNREACHABLE: err = -ENETUNREACH; break;
		case STATUS_HOST_UNREACHABLE: err = -EHOSTUNREACH; break;
		case STATUS_IO_TIMEOUT: err = -ETIMEDOUT; break;
		default: 
			bsr_err(25, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect try due to error(0x%08X) to create connect ", status);
			err = -EINVAL; 
			break;
		}
	} else {
		if (status == STATUS_TIMEOUT) { 
			err = -ETIMEDOUT; 
		} else { 
			if (status == 0) {
				err = 0;
			} else {
				err = -EINVAL;
			}
			if (socket->sk == NULL) {
				err = -1;
				goto out;
			}
		}
	}

	// _WSK_SOCKETCONNECT
#else 

#ifdef _WIN
	socket = kzalloc(sizeof(struct socket), 0, 'D1SB');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;
	
#ifdef _WIN
	if (my_addr.ss_family == AF_INET6) {
		socket->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	} else {
		socket->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	}
#endif

	if (socket->sk == NULL) {
		err = -1;
		goto out;
	}

	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '45SB');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
		socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;
#else // _LIN
	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (err < 0) {
		socket = NULL;
		goto out;
	}

	socket->sk->sk_rcvtimeo =
	socket->sk->sk_sndtimeo = connect_int * HZ;
#endif
	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	/* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for bsr.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
#ifdef _WIN
	// DW-835 Bind fail issue(fix with INADDR_ANY address parameter) 
	if(my_addr.ss_family == AF_INET ) {
		LocalAddressV4.sin_family = AF_INET;
		LocalAddressV4.sin_addr.s_addr = INADDR_ANY;
		LocalAddressV4.sin_port = HTONS(0);
	} else {
		//AF_INET6
		LocalAddressV6.sin6_family = AF_INET6;
		//LocalAddressV6.sin6_addr.s_addr = IN6ADDR_ANY_INIT;
		LocalAddressV6.sin6_port = HTONS(0); 
	}
	status = Bind(socket->sk, (my_addr.ss_family == AF_INET) ? (PSOCKADDR)&LocalAddressV4 : (PSOCKADDR)&LocalAddressV6 );
	if (!NT_SUCCESS(status)) {
		bsr_err(26, BSR_LC_SOCKET, NO_OBJECT,"Bind() failed with status 0x%08X ", status);
		err = -EINVAL;
		goto out;
	}
#else // _LIN
	err = socket->ops->bind(socket, (struct sockaddr *) &my_addr, path->path.my_addr_len);
#endif
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
#ifdef _WIN
	status = Connect(socket->sk, (struct sockaddr *) &peer_addr);
	if (!NT_SUCCESS(status)) {
		err = status;
		switch (status) {
		case STATUS_CONNECTION_REFUSED: err = -ECONNREFUSED; break;
		case STATUS_INVALID_DEVICE_STATE: err = -EAGAIN; break;
		case STATUS_NETWORK_UNREACHABLE: err = -ENETUNREACH; break;
		case STATUS_HOST_UNREACHABLE: err = -EHOSTUNREACH; break;
		default: err = -EINVAL; break;
		}
	} else {
		if (status == STATUS_TIMEOUT) { 
			err = -ETIMEDOUT; 
		} else { 
			if (status == 0) {
				err = 0;
			} else {
				err = -EINVAL;
			}
		}
	}
#else // _LIN
	err = socket->ops->connect(socket, (struct sockaddr *) &peer_addr,
				   path->path.peer_addr_len, 0);
#endif
	
#endif 	// _WSK_SOCKETCONNECT end

	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ECONNRESET:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
			break;
#ifdef _LIN
		// BSR-721
		case -EINVAL:
			err = -EADDRNOTAVAIL;
			break;
#endif
		}
	}

out:
	if (err < 0) {
		if (socket) {
			sock_release(socket);
#ifdef _WIN
			// DW-2139 socket may not be released after sock_release() call in case of connection failure
			if (socket && !socket->sk)
				kfree(socket);
#endif
		}
#ifdef _WIN
		// DW-1272 : retry CreateSocketConnect if STATUS_INVALID_ADDRESS_COMPONENT
		if (err != -EAGAIN && err != -EINVALADDR)
#else // _LIN
		// BSR-721
		if (err != -EAGAIN && err != -EADDRNOTAVAIL)
#endif
			tr_err(transport, "%s failed, err = %d", what, err);
	} else {
#ifdef _WIN
		status = SetEventCallbacks(socket, WSK_EVENT_DISCONNECT);
		if (!NT_SUCCESS(status)) {
			bsr_err(27, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect try due to failure to set wsk disconnect callback. err(0x%x)", status);
			err = -1;
			goto out;
		}
		socket->sk_state = WSK_ESTABLISHED;
#endif 
		*ret_socket = socket;
	}

	return err;
}


static int dtt_send_first_packet(struct bsr_tcp_transport *tcp_transport, struct socket *socket,
			     enum bsr_packet cmd, enum bsr_stream stream)
{
	struct p_header80 h;
	int msg_flags = 0;
	int err;

	UNREFERENCED_PARAMETER(stream);
	
	if (!socket)
		return -EIO;

	h.magic = cpu_to_be32(BSR_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	err = _dtt_send(tcp_transport, socket, &h, sizeof(h), msg_flags);

	return err;
}

/**
 * dtt_socket_ok_or_free() - Free the socket if its connection is not okay
 * @sock:	pointer to the pointer to the socket.
 */
static bool dtt_socket_ok_or_free(struct socket **socket)
{
	if (!*socket)
		return false;

#ifdef _WIN 
	if ((*socket)->sk_state == WSK_ESTABLISHED) {
		bsr_debug_conn("socket->sk_state == WSK_ESTABLISHED wsk = %p", (*socket)->sk);
		return true;
	}

	bsr_debug_conn("wsk = %p socket->sk_state = %d", (*socket)->sk, (*socket)->sk_state);
	
	kernel_sock_shutdown(*socket, SHUT_RDWR); // TODO Check if sk_state condition is required.

	if ((*socket)->sk_state >= WSK_DISCONNECTED) {
		sock_release(*socket);
		*socket = NULL;
	}
#else // _LIN

	if ((*socket)->sk->sk_state == TCP_ESTABLISHED)
		return true;
	kernel_sock_shutdown(*socket, SHUT_RDWR);
	sock_release(*socket);
	*socket = NULL;
#endif
	return false;
}

static bool dtt_connection_established(struct bsr_transport *transport,
				       struct socket **socket1,
				       struct socket **socket2,
				       struct dtt_path **first_path)
{
	struct net_conf *nc;
	int timeout, good = 0;

	if (!*socket1 || !*socket2) {
		bsr_debug_conn("!*socket || !*socket2 and return false"); 
		return false;
	}

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	// BSR-798 It's too long to use ping-timeout. Use sock-check-timeout to set it short.
	timeout = nc->sock_check_timeo * HZ / 10;
	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	good += dtt_socket_ok_or_free(socket1);
	good += dtt_socket_ok_or_free(socket2);

	if (good == 0)
		*first_path = NULL;

	return good == 2;
}

static struct dtt_path *dtt_wait_connect_cond(struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct bsr_listener *listener;
	struct bsr_path *bsr_path;
	struct dtt_path *path = NULL;

	bool rv = false;

	spin_lock(&tcp_transport->paths_lock);
	list_for_each_entry_ex(struct bsr_path, bsr_path, &transport->paths, list) {
		path = container_of(bsr_path, struct dtt_path, path);
		listener = bsr_path->listener;
#if 0
		extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
		char sbuf[64], dbuf[64];
		bsr_debug_co("[%p]dtt_wait_connect_cond: peer:%s sname=%s accept=%d", KeGetCurrentThread(), get_ip4(sbuf, &path->path.peer_addr), path->socket->name, listener->pending_accepts);		
#endif
		spin_lock_bh(&listener->waiters_lock);
#ifdef _WIN
		rv = listener->pending_accepts > 0 || path->socket != NULL;
#else // _LIN
		rv = listener->pending_accepts > 0 || !list_empty(&path->sockets);
#endif
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	spin_unlock(&tcp_transport->paths_lock);
	bsr_debug_conn("rv = %d? path : NULL", rv); 

	return rv ? path : NULL;
}

static void unregister_state_change(struct sock *sock, struct dtt_listener *listener)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(sock);

	// DW-1483 WSK_EVENT_ACCEPT disable	
	NTSTATUS status = SetEventCallbacks(listener->s_listen, WSK_EVENT_ACCEPT | WSK_EVENT_DISABLE);
	bsr_debug(89, BSR_LC_SOCKET, NO_OBJECT,"WSK_EVENT_DISABLE (listener = 0x%p)", listener);
	if (!NT_SUCCESS(status)) {
		bsr_debug(90, BSR_LC_SOCKET, NO_OBJECT, "WSK_EVENT_DISABLE failed (listener = 0x%p)", listener);
	}
#else // _LIN
	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_state_change = listener->original_sk_state_change;
	sock->sk_user_data = NULL;
	write_unlock_bh(&sock->sk_callback_lock);
#endif
}

static int dtt_wait_for_connect(struct bsr_transport *transport,
				struct bsr_listener *bsr_listener, struct socket **socket,
				struct dtt_path **ret_path)
{
// Frequent conditional compilation directives in functions hurt too much readability, 
// so Separated for conditional compilation into entire code blocks by platform.
#ifdef _WIN
	SOCKADDR_STORAGE_EX peer_addr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int connect_int, err = 0;
	long timeo;
	struct socket *s_estab = NULL;
	struct net_conf *nc;
	struct bsr_path *bsr_path2;
	struct dtt_listener *listener = container_of(bsr_listener, struct dtt_listener, listener);
	struct dtt_path *path = NULL;
	int rcvbuf_size; 
	signed long long sndbuf_size;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
	 wait_event_interruptible_timeout_ex(listener->wait,
		(path = dtt_wait_connect_cond(transport)),
		timeo, timeo);

	if (-BSR_SIGKILL == timeo)	{
		bsr_debug_conn("-BSR_SIGKILL == timeo return -BSR_SIGKILL");
		return -BSR_SIGKILL;
	}

	if (-ETIMEDOUT == timeo){
		bsr_debug_conn("-ETIMEOUT == timeout return -EAGAIN");
		return -EAGAIN;
	}

	spin_lock_bh(&listener->listener.waiters_lock);
	if (path->socket) {
		bsr_debug_conn("path->socket s_estab = path->socket(%p)", path->socket->sk);
		s_estab = path->socket;
		path->socket = NULL;
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
		// Accept and, create s_estab.
		memset(&peer_addr, 0, sizeof(SOCKADDR_STORAGE_EX));
		// saved paccept_socket in Accept Event Callback
		// paccept_socket = Accept(listener->s_listen->sk, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, status, timeo / HZ);
		// 
		if (listener->paccept_socket) {
			s_estab = listener->paccept_socket;
			bsr_debug_conn("create estab_sock s_estab = listener->paccept_socket(%p)", s_estab);
		}
		else {
			if (status == STATUS_TIMEOUT) {
				bsr_debug_conn("status == timeout err = -EAGAIN");
				err = -EAGAIN;
			}
			else {
				bsr_debug_conn("status else and err = -1 ");
				err = -1;
			}
		}
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */

		status = GetRemoteAddress(s_estab, (PSOCKADDR)&peer_addr);
		if(status != STATUS_SUCCESS) {
			kfree(s_estab->sk_linux_attr);
			kfree(s_estab);
			return -1;
		}
		char dbuf[128];
		bsr_debug_conn("GetRemoteAddress : peer_addr %s", get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&peer_addr));

		spin_lock_bh(&listener->listener.waiters_lock);
		bsr_path2 = bsr_find_path_by_addr(&listener->listener, &peer_addr);
		if (!bsr_path2) {
			struct sockaddr_in6 *from_sin6;
			struct sockaddr_in *from_sin;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
				       "%pI6", &from_sin6->sin6_addr);
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
					 "%pI4", &from_sin->sin_addr);
				break;
			}

			goto retry_locked;
		}
		if (bsr_path2 != &path->path) {
			struct dtt_path *path2 =
				container_of(bsr_path2, struct dtt_path, path);

			if (path2->socket) {
				tr_info(transport, /* path2->transport, */
					"No mem, dropped an incoming connection");
				goto retry_locked;
			}
			path2->socket = s_estab;
			s_estab = NULL;
			wake_up(&listener->wait);
			goto retry_locked;
		}
	}

#ifdef _WIN_SEND_BUF
	// DW-2174 prevents invalid memory references.
	rcu_read_lock_w32_inner();
	nc = rcu_dereference(transport->net_conf);
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();

	dtt_setbufsize(s_estab, sndbuf_size, rcvbuf_size);
#endif
		
	bsr_debug_co("%p dtt_wait_for_connect ok done.", KeGetCurrentThread());
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		kernel_sock_shutdown(s_estab, SHUT_RDWR);
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;

#else // _LIN

	struct dtt_socket_container *socket_c;
	SOCKADDR_STORAGE_EX peer_addr;
	int connect_int, err = 0;
	long timeo;
	struct socket *s_estab = NULL;
	struct net_conf *nc;
	struct bsr_path *bsr_path2;
	struct dtt_listener *listener = container_of(bsr_listener, struct dtt_listener, listener);
	struct dtt_path *path = NULL;
	int rcvbuf_size; 
	signed long long sndbuf_size;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
	timeo = wait_event_interruptible_timeout(listener->wait,
			(path = dtt_wait_connect_cond(transport)),
			timeo);
	if (timeo <= 0)
		return -EAGAIN;

	spin_lock_bh(&listener->listener.waiters_lock);
	socket_c = list_first_entry_or_null(&path->sockets, struct dtt_socket_container, list);
	if (socket_c) {
		s_estab = socket_c->socket;
		list_del(&socket_c->list);
		bsr_kfree(socket_c);
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
		err = kernel_accept(listener->s_listen, &s_estab, 0);
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
		unregister_state_change(s_estab->sk, listener);

		bsr_always_getpeername(s_estab, (struct sockaddr *)&peer_addr);

		spin_lock_bh(&listener->listener.waiters_lock);
		bsr_path2 = bsr_find_path_by_addr(&listener->listener, &peer_addr);
		if (!bsr_path2) {
			struct sockaddr_in6 *from_sin6;
			struct sockaddr_in *from_sin;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
				       "%pI6", &from_sin6->sin6_addr);
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
					 "%pI4", &from_sin->sin_addr);
				break;
			}

			goto retry_locked;
		}
		if (bsr_path2 != &path->path) {
			struct dtt_path *path2 =
				container_of(bsr_path2, struct dtt_path, path);

			socket_c = bsr_kmalloc(sizeof(*socket_c), GFP_ATOMIC, '');
			if (!socket_c) {
				tr_info(transport, /* path2->transport, */
					"No mem, dropped an incoming connection");
				goto retry_locked;
			}

			socket_c->socket = s_estab;
			s_estab = NULL;
			list_add_tail(&socket_c->list, &path2->sockets);
			wake_up(&listener->wait);
			goto retry_locked;
		}
	}

#ifdef _LIN_SEND_BUF	
	// DW-2174 prevents invalid memory references.
	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();
	dtt_setbufsize(s_estab, sndbuf_size, rcvbuf_size);
#endif

	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		kernel_sock_shutdown(s_estab, SHUT_RDWR);
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;

#endif
}

static int dtt_receive_first_packet(struct bsr_tcp_transport *tcp_transport, struct socket *socket)
{
	struct bsr_transport *transport = &tcp_transport->transport;
	struct p_header80 *h = tcp_transport->rbuf[DATA_STREAM].base;
	const unsigned int header_size = sizeof(*h);
	struct net_conf *nc;
	int err;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
	
	// BSR-798 It's too long to use ping-timeout. Use sock-check-timeout to set it short.
#ifdef _WIN
	socket->sk_linux_attr->sk_rcvtimeo = nc->sock_check_timeo * 4 * HZ / 10;
#else // _LIN
	socket->sk->sk_rcvtimeo = nc->sock_check_timeo * 4 * HZ / 10;
#endif
	rcu_read_unlock();

	err = dtt_recv_short(transport, socket, h, header_size, 0);
#ifdef _WIN
    bsr_debug_sk("socket(0x%p) err(%d) header_size(%u)", socket, err, header_size);
#endif
	if (err != (int)header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	if (h->magic != cpu_to_be32(BSR_MAGIC)) {
		tr_err(transport, "Wrong magic value 0x%08x in receive_first_packet",
			 be32_to_cpu(h->magic));
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}

#ifdef _WIN
NTSTATUS WSKAPI
dtt_incoming_connection (
    _In_  PVOID         SocketContext,
    _In_  ULONG         Flags,
    _In_  PSOCKADDR     LocalAddress,
    _In_  PSOCKADDR     RemoteAddress,
    _In_opt_  PWSK_SOCKET AcceptSocket,
    _Outptr_result_maybenull_ PVOID *AcceptSocketContext,
    _Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
#else // _LIN
static void dtt_incoming_connection(struct sock *sock)
#endif
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(Flags);
	struct bsr_resource *resource = (struct bsr_resource *) SocketContext;
	struct bsr_listener *listener = NULL;
	bool find_listener = false;

    if (AcceptSocket == NULL ) {
		bsr_debug_conn("NOT_ACCEPTED! AcceptSocket is null.");
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
	
	if (!resource) {
		bsr_debug_conn("NOT_ACCEPTED! SocketContext is null.");
        return STATUS_REQUEST_NOT_ACCEPTED;
	}

	char buf[128];
	bsr_debug_conn("LocalAddress:%s ", get_ip4(buf, sizeof(buf), (struct sockaddr_in*)LocalAddress));
	bsr_debug_conn("RemoteAddress:%s ", get_ip4(buf, sizeof(buf), (struct sockaddr_in*)RemoteAddress));

	
	spin_lock_bh(&resource->listeners_lock);	

	// DW-1498 Find the listener that matches the LocalAddress in resource-> listeners.
	list_for_each_entry_ex(struct bsr_listener, listener, &resource->listeners, list) {
		bsr_debug_conn("listener->listen_addr:%s ", get_ip4(buf, sizeof(buf), (struct sockaddr_in*)&listener->listen_addr));
		if (addr_and_port_equal(&listener->listen_addr, (const SOCKADDR_STORAGE_EX *)LocalAddress)) {
			find_listener = true;
			break;
		}
	}	

	if (!find_listener) {
		spin_unlock_bh(&resource->listeners_lock);
		bsr_debug_conn("NOT_ACCEPTED! listener not found.");
        return STATUS_REQUEST_NOT_ACCEPTED;
	}

    struct socket * s_estab = kzalloc(sizeof(struct socket), 0, 'E6SB');

    if (!s_estab) {
    	spin_unlock_bh(&resource->listeners_lock);
		bsr_debug_conn("NOT_ACCEPTED! s_estab alloc failed.");
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    s_estab->sk = AcceptSocket;

	*AcceptSocketDispatch = &dispatchDisco;
	*AcceptSocketContext = s_estab;
	s_estab->sk_state = WSK_ESTABLISHED;
	SetEventCallbacks(s_estab, WSK_EVENT_DISCONNECT);		

	_snprintf(s_estab->name, sizeof(s_estab->name) - 1, "estab_sock");
    s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, 'C6SB');

    if (s_estab->sk_linux_attr) {
        s_estab->sk_linux_attr->sk_sndbuf = BSR_SNDBUF_SIZE_DEF;
    }
    else {
        kfree(s_estab);
		spin_unlock_bh(&resource->listeners_lock);
		bsr_debug_conn("NOT_ACCEPTED! sk_linux_attr alloc failed.");
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

	spin_lock(&listener->waiters_lock);
	struct bsr_path *path = bsr_find_path_by_addr(listener, (SOCKADDR_STORAGE_EX *)RemoteAddress);
	if(!path) {
		kfree(s_estab->sk_linux_attr);
		kfree(s_estab);
		spin_unlock(&listener->waiters_lock);
		spin_unlock_bh(&resource->listeners_lock);
		bsr_debug_conn("NOT_ACCEPTED! bsr_path not found.");
		return STATUS_REQUEST_NOT_ACCEPTED;
	}


	struct dtt_path *path2 = container_of(path, struct dtt_path, path);

	struct dtt_listener *listener2 = container_of(listener, struct dtt_listener, listener);
	if (path2) {
		bsr_debug_conn("if(path) path->socket = s_estab");
		if (path2->socket) // DW-1567 fix system handle leak
		{
			bsr_info(28, BSR_LC_SOCKET, resource, "The socket that was previously accept socket(0x%p) has not been removed yet. Do not accept socket until uninstallation.", path2->socket);
			goto not_accept;
		}
		else {
			path2->socket = s_estab;
		}
	}
	else {
		bsr_debug_conn("else listener->paccept_socket = AccceptSocket");
		if (listener2->paccept_socket) // DW-1567 fix system handle leak
		{
			bsr_info(29, BSR_LC_SOCKET, resource, "The socket that was previously accept socket(0x%p) has not been removed yet. Do not accept socket until uninstallation.", listener2->paccept_socket);
			goto not_accept;
		}
		else {
			listener->pending_accepts++;
			listener2->paccept_socket = s_estab;
		}
	}
	wake_up(&listener2->wait);

	spin_unlock(&listener->waiters_lock);
	spin_unlock_bh(&resource->listeners_lock);
	bsr_debug_sk("s_estab(0x%p) wsk(0x%p) wake!!!!", s_estab, AcceptSocket);

	return STATUS_SUCCESS;

not_accept:
	kfree(s_estab->sk_linux_attr);
	kfree(s_estab);
	wake_up(&listener2->wait);
	spin_unlock(&listener->waiters_lock);
	spin_unlock_bh(&resource->listeners_lock);
			
	return STATUS_REQUEST_NOT_ACCEPTED;
		
#else // _LIN
	struct dtt_listener *listener;
	void(*state_change)(struct sock *sock);

	// BSR-1090 sock->sk_user_data is removed from unregister_state_change(), so a lock is added for synchronization
	write_lock_bh(&sock->sk_callback_lock);
	listener = sock->sk_user_data;
	if (listener) {
		state_change = listener->original_sk_state_change;
		if (sock->sk_state == TCP_ESTABLISHED) {
			spin_lock(&listener->listener.waiters_lock);
			listener->listener.pending_accepts++;
			spin_unlock(&listener->listener.waiters_lock);
			wake_up(&listener->wait);
		}
		write_unlock_bh(&sock->sk_callback_lock);
		state_change(sock);
	} else {
		write_unlock_bh(&sock->sk_callback_lock);
	}
#endif
}

static void dtt_destroy_listener(struct bsr_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

#ifdef _WIN
	unregister_state_change(listener->s_listen->sk_linux_attr, listener);
#else // _LIN
	unregister_state_change(listener->s_listen->sk, listener);
#endif

	sock_release(listener->s_listen);
	bsr_kfree(listener);

	// DW-1483
	listener = NULL;
}

#ifdef _WIN
WSK_CLIENT_LISTEN_DISPATCH dispatch = {
	dtt_incoming_connection,
    NULL,	// WskInspectEvent is required only if conditional-accept is used.
    NULL	// WskAbortEvent is required only if conditional-accept is used.
};
#endif



static int dtt_create_listener(struct bsr_transport *transport,
			       const struct sockaddr *addr,
			       struct bsr_listener **ret_listener)
{
#ifdef _WIN
	//int err = 0, sndbuf_size, rcvbuf_size; 
	int err = 0, rcvbuf_size;
	signed long long sndbuf_size;
	NTSTATUS status;
	SOCKADDR_IN ListenV4Addr = {0,};
	SOCKADDR_IN6 ListenV6Addr = {0,};
#else // _LIN
	int err, rcvbuf_size, addr_len;
	signed long long sndbuf_size;
#endif
	SOCKADDR_STORAGE_EX my_addr;
	struct dtt_listener *listener = NULL;
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();
	my_addr = *(SOCKADDR_STORAGE_EX *)addr;

	what = "sock_create_kern";
#ifdef _WIN
    s_listen = kzalloc(sizeof(struct socket), 0, '87SB');
    if (!s_listen) {
        err = -ENOMEM;
        goto out;
    }
	_snprintf(s_listen->name, sizeof(s_listen->name) - 1, "listen_sock\0");
    s_listen->sk_linux_attr = 0;
    err = 0;
	listener = kzalloc(sizeof(struct dtt_listener), 0, 'F6SB');
	if (!listener) {
        err = -ENOMEM;
        goto out;
    }

	struct bsr_connection *connection = container_of(transport, struct bsr_connection, transport);	
	
	if (my_addr.ss_family == AF_INET6) {
		s_listen->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, (PVOID*)connection->resource, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	} else {
		s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (PVOID*)connection->resource, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	}
    if (s_listen->sk == NULL) {
        err = -1;
        goto out;
    }
	
    s_listen->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '03SB');
    if (!s_listen->sk_linux_attr) {
        err = -ENOMEM;
        goto out;
    }
#else // _LIN
	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}
#endif

#ifdef _WIN
    s_listen->sk_linux_attr->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	LONG InputBuffer = 1;
    status = ControlSocket(s_listen, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
		bsr_err(30, BSR_LC_SOCKET, NO_OBJECT, "Failed to create listener due to failure set control socket(SO_REUSEADDR). status(0x%x)", status);
        err = -1;
        goto out;
    }
#else // _LIN
	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
#endif
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
#ifdef _WIN

	// DW-835 Bind fail issue(fix with INADDR_ANY address parameter) 
	if(my_addr.ss_family == AF_INET ) {
		ListenV4Addr.sin_family = AF_INET;
		ListenV4Addr.sin_port = *((USHORT*)my_addr.__data);
		ListenV4Addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		//AF_INET6
		ListenV6Addr.sin6_family = AF_INET6;
		ListenV6Addr.sin6_port = *((USHORT*)my_addr.__data); 
		//ListenV6Addr.sin6_addr = IN6ADDR_ANY_INIT;
	}

	status = Bind(s_listen, (my_addr.ss_family == AF_INET) ? (PSOCKADDR)&ListenV4Addr : (PSOCKADDR)&ListenV6Addr);
	
	if (!NT_SUCCESS(status)) {
    	if(my_addr.ss_family == AF_INET) {
			bsr_err(31, BSR_LC_SOCKET, NO_OBJECT, "Failed to create listener due to failure to socket bind. err(0x%x) %02X.%02X.%02X.%02X:0x%X%X", status, (UCHAR)my_addr.__data[2], (UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4], (UCHAR)my_addr.__data[5], (UCHAR)my_addr.__data[0], (UCHAR)my_addr.__data[1]);
    	} else {
			bsr_err(32, BSR_LC_SOCKET, NO_OBJECT, "Failed to create listener due to failure to socket bind. err(0x%x) [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]:0x%X%X", status, (UCHAR)my_addr.__data[2], (UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4], (UCHAR)my_addr.__data[5],
																		(UCHAR)my_addr.__data[6],(UCHAR)my_addr.__data[7], (UCHAR)my_addr.__data[8],(UCHAR)my_addr.__data[9],
																		(UCHAR)my_addr.__data[10],(UCHAR)my_addr.__data[11], (UCHAR)my_addr.__data[12],(UCHAR)my_addr.__data[13],
																		(UCHAR)my_addr.__data[14],(UCHAR)my_addr.__data[15],(UCHAR)my_addr.__data[16],(UCHAR)my_addr.__data[17],
																		(UCHAR)my_addr.__data[0], (UCHAR)my_addr.__data[1]);
    	}
		err = -1;
        goto out;
    }

#else // _LIN
	addr_len = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
		: sizeof(struct sockaddr_in);

	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, addr_len);
#endif
	if (err < 0)
		goto out;

	what = "kmalloc";
#ifdef _LIN
	listener = bsr_kmalloc(sizeof(*listener), GFP_KERNEL, '');
	if (!listener) {
		err = -ENOMEM;
		goto out;
	}
#endif

	listener->s_listen = s_listen;
#ifdef _LIN
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	listener->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = dtt_incoming_connection;
	s_listen->sk->sk_user_data = listener;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);

	what = "listen";
	err = s_listen->ops->listen(s_listen, BSR_PEERS_MAX * 2);
	if (err < 0)
		goto out;
#endif
	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;
	init_waitqueue_head(&listener->wait);

	*ret_listener = &listener->listener;

#ifdef _WIN
	// DW-845 fix crash issue(EventCallback is called when listener is not initialized, then reference to invalid Socketcontext at dtt_inspect_incoming.)
	status = SetEventCallbacks(s_listen, WSK_EVENT_ACCEPT);
    if (!NT_SUCCESS(status)) {
		bsr_err(33, BSR_LC_SOCKET, NO_OBJECT, "Failed to create listener due to failure to set wsk accept callback. err(0x%x)", status);
    	err = -1;
        goto out;
    }
#endif	

#ifdef _WIN
	s_listen->sk_state = WSK_DISCONNECTED; 
#endif
	return 0;
out:
	if (s_listen)
		sock_release(s_listen);

	if (err < 0 &&
	    err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE 
#ifdef _LIN // BSR-721
		&& err != -EADDRNOTAVAIL
#endif
		)
		tr_err(transport, "%s failed, err = %d", what, err);

	bsr_kfree(listener);

	return err;
}

static void dtt_cleanup_accepted_sockets(struct dtt_path *path)
{
#ifdef _WIN
		if (path->socket) {
			sock_release(path->socket);
			path->socket = NULL;
		}
#else // _LIN
	while (!list_empty(&path->sockets)) {
		struct dtt_socket_container *socket_c =
			list_first_entry(&path->sockets, struct dtt_socket_container, list);

		list_del(&socket_c->list);
		kernel_sock_shutdown(socket_c->socket, SHUT_RDWR);
		sock_release(socket_c->socket);
		bsr_kfree(socket_c);
	}
#endif
}

// DW-1398
void dtt_put_listeners(struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct bsr_path *bsr_path;
	bsr_debug_conn("dtt_put_listeners"); 

	spin_lock(&tcp_transport->paths_lock);
	clear_bit(DTT_CONNECTING, &tcp_transport->flags);
	spin_unlock(&tcp_transport->paths_lock);

	for_each_path_ref(bsr_path, transport) {
		struct dtt_path *path = container_of(bsr_path, struct dtt_path, path);
		bsr_put_listener(bsr_path);
		dtt_cleanup_accepted_sockets(path);
	}
}

static struct dtt_path *dtt_next_path(struct bsr_tcp_transport *tcp_transport, struct dtt_path *path)
{
	struct bsr_transport *transport = &tcp_transport->transport;
	struct bsr_path *bsr_path;

	spin_lock(&tcp_transport->paths_lock);
	if (list_is_last(&path->path.list, &transport->paths))
		bsr_path = list_first_entry(&transport->paths, struct bsr_path, list);
	else
		bsr_path = list_next_entry_ex(struct bsr_path, &path->path, list);
	spin_unlock(&tcp_transport->paths_lock);

	return container_of(bsr_path, struct dtt_path, path);
}
#ifdef _WIN
extern char * get_ip4(char *buf, size_t len, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, size_t len, struct sockaddr_in6 *sockaddr);
#endif

static int dtt_connect(struct bsr_transport *transport)
{
#ifdef _WIN // TODO
	NTSTATUS status;
	if (transport == NULL) {
		bsr_err(34, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect due to no assigned transport.");
		return -EDESTADDRREQ;
	}
#endif
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct bsr_path *bsr_path;
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	int timeout, err;
	bool ok;
#ifdef _WIN
	char sbuf[128], dbuf[128];
	ok = FALSE;
#endif
	dsocket = NULL;
	csocket = NULL;

	for_each_path_ref(bsr_path, transport) {
		struct dtt_path *path = container_of(bsr_path, struct dtt_path, path);
		dtt_cleanup_accepted_sockets(path);
	}

	spin_lock(&tcp_transport->paths_lock);
	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	err = -EDESTADDRREQ;
	if (list_empty(&transport->paths)) {
		spin_unlock(&tcp_transport->paths_lock);
		goto out;
	}

	list_for_each_entry_ex(struct bsr_path, bsr_path, &transport->paths, list) {
		if (!bsr_path->listener) {
			kref_get(&bsr_path->kref);
			spin_unlock(&tcp_transport->paths_lock);

#if 0// _WIN
		{		
			if (path->path.my_addr.ss_family == AF_INET6) {
				bsr_debug(91, BSR_LC_SOCKET, NO_OBJECT,"dtt_connect: dtt_connect: path: %s -> %s.", get_ip6(sbuf, (struct sockaddr_in6*)&path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&path->path.peer_addr));
			}
			else {
				bsr_debug(92, BSR_LC_SOCKET, NO_OBJECT,"dtt_connect: dtt_connect: path: %s -> %s.", get_ip4(sbuf, (struct sockaddr_in*)&path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&path->path.peer_addr));
			}
		}
#endif
		err = bsr_get_listener(transport, bsr_path, dtt_create_listener);
		kref_put(&bsr_path->kref, bsr_destroy_path);
		if (err)
			goto out;
		spin_lock(&tcp_transport->paths_lock);
		bsr_path = list_first_entry_or_null(&transport->paths, struct bsr_path, list);
		if (bsr_path)
			continue;
		else
			break;
		}
	}

	bsr_path = list_first_entry(&transport->paths, struct bsr_path, list);
	
	if (bsr_path == NULL) {
		spin_unlock(&tcp_transport->paths_lock);
		goto out;
	}
#ifdef _WIN
        {
		if (bsr_path->my_addr.ss_family == AF_INET6) {
			bsr_debug(93, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: bsr_path: %s -> %s ", get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&bsr_path->my_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)&bsr_path->peer_addr));
		} else {
			bsr_debug(94, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: bsr_path: %s -> %s ", get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&bsr_path->my_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&bsr_path->peer_addr));
		}
	}
#endif

	connect_to_path = container_of(bsr_path, struct dtt_path, path);
	if (connect_to_path == NULL) {
		spin_unlock(&tcp_transport->paths_lock);
		goto out;
	}
#ifdef _WIN
	{
		if(connect_to_path->path.my_addr.ss_family == AF_INET6) {
			bsr_debug(95, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: connect_to_path: %s -> %s ", get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
		} else {
			bsr_debug(96, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: connect_to_path: %s -> %s ", get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&connect_to_path->path.peer_addr));
		}
	}
#endif
	spin_unlock(&tcp_transport->paths_lock);

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(transport, connect_to_path, &s);

		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
#ifdef bsr_debug_ip4
			{
#ifdef _WIN
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					bsr_debug(97, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: Connected: %s -> %s", get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					bsr_debug(98, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect: Connected: %s -> %s", get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}
#endif
			}
#endif

			bool use_for_data;

			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed A");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
				connect_to_path = first_path;
				continue;
			}

	
			if (!dsocket && !csocket) {
				// DW-1452 remove DW-1297 and apply path comparison
				struct bsr_connection *connection =
					container_of(transport, struct bsr_connection, transport);
				use_for_data = dtt_path_cmp_addr(first_path, connection);
				bsr_debug_conn("use_for_date = %d", use_for_data); 
			} else if (!dsocket) {
           		use_for_data = true;
			} else {
				if (csocket) {
					tr_err(transport, "Logic error in conn_connect()");
					goto out_eagain;
				}	
				use_for_data = false;
			}

			if (use_for_data) {
				dsocket = s;
				// DW-1567 add error handling
				if (dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM) <= 0) {
					bsr_err(35, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect due to failure to send first packet, dsocket (%p)", dsocket->sk);
					sock_release(dsocket);
					dsocket = NULL;
					goto retry;
				}
			} else {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
				// DW-1567 add error handling
				if (dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM) <= 0) {
					bsr_err(36, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect due to failure to send first packet, csocket (%p)", csocket->sk);
					sock_release(csocket);
					csocket = NULL;
					goto retry;
				}
			}
		} else if (!first_path)
			connect_to_path = dtt_next_path(tcp_transport, connect_to_path);

		if (dtt_connection_established(transport, &dsocket, &csocket, &first_path)) {
			bsr_debug_conn("success dtt_connection_established break the loop"); 
			break;
		}

retry:
		s = NULL;
		err = dtt_wait_for_connect(transport, connect_to_path->path.listener, &s, &connect_to_path);
		if (err < 0 && err != -EAGAIN) {
			bsr_debug_conn("dtt_wait_for_connect fail err = %d goto out", err); 
			goto out;
		}

		if (s) {
#ifdef bsr_debug_ip4 
			{
#ifdef _WIN
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					bsr_debug(99, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect:(%p) Accepted:  %s <- %s", KeGetCurrentThread(), get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					bsr_debug(100, BSR_LC_SOCKET, NO_OBJECT, "dtt_connect:(%p) Accepted:  %s <- %s", KeGetCurrentThread(), get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}				
#endif				
			}
#endif
			int fp = dtt_receive_first_packet(tcp_transport, s);

			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed P");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
				connect_to_path = first_path;
				goto randomize;
			}
			//bsr_debug_conn("dtt_socket_ok_or_free(&dsocket)"); 
			dtt_socket_ok_or_free(&dsocket);
			//bsr_debug_conn("dtt_socket_ok_or_free(&csocket)");
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed");
					kernel_sock_shutdown(dsocket, SHUT_RDWR);
					sock_release(dsocket);
					dsocket = s;
					goto randomize;
				}
				dsocket = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
					tr_warn(transport, "initial packet M crossed");
					kernel_sock_shutdown(csocket, SHUT_RDWR);
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
randomize:
				if (prandom_u32() & 1) {
					bsr_debug_conn("goto retry:"); 
					goto retry;
				}
			}
		}

		if (bsr_should_abort_listening(transport)) {
			bsr_debug_conn("fail bsr_should_abort_listening and goto out_eagain"); 
			goto out_eagain;
		}

		ok = dtt_connection_established(transport, &dsocket, &csocket, &first_path);
		if (ok) {
			bsr_debug_conn("dtt_connection_established break the loop"); 
		}
	} while (!ok);

	TR_ASSERT(transport, first_path == connect_to_path);
	connect_to_path->path.established = true;
	bsr_path_event(transport, &connect_to_path->path);
#ifdef _LIN
	dtt_put_listeners(transport);
#endif

#ifdef _WIN
    LONG InputBuffer = 1;
    status = ControlSocket(dsocket, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
		bsr_err(37, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect due to failure to set socket control(SO_REUSEADDR).status(0x%x)", status);
		// DW-1896 
		//If no error code is returned, dtt_connect is considered successful.
		//so the following code is executed to reference socket.
		//but, since socket is NULL, BSOD can occur.
		err = status;
        goto out;
    }

    status = ControlSocket(csocket, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
		bsr_err(38, BSR_LC_SOCKET, NO_OBJECT, "Failed to connect due to failure to set socket control(SO_REUSEADDR).status(0x%x)", status);
		err = status;
        goto out;
    }
#else // _LIN
	dsocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	csocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */

	dsocket->sk->sk_allocation = GFP_NOIO;
	csocket->sk->sk_allocation = GFP_NOIO;

	dsocket->sk->sk_priority = TC_PRIO_INTERACTIVE_BULK;
	csocket->sk->sk_priority = TC_PRIO_INTERACTIVE;
#endif
	/* NOT YET ...
	 * sock.socket->sk->sk_sndtimeo = transport->net_conf->timeout*HZ/10;
	 * sock.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the P_CONNECTION_FEATURES timeout,
	 * which we set to 4x the configured ping_timeout. */

	/* we don't want delays.
	 * we use TCP_CORK where appropriate, though */
	dtt_nodelay(dsocket);
	dtt_nodelay(csocket);

	bsr_debug_conn("tcp_transport->[STREAMS] <= dsocket, csocket");

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

#ifdef _WIN
	dsocket->sk_linux_attr->sk_sndtimeo = timeout;
	csocket->sk_linux_attr->sk_sndtimeo = timeout;
#else // _LIN
	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;
#endif

	return 0;

out_eagain:
	err = -EAGAIN;

out:
	dtt_put_listeners(transport);

	if (dsocket) {
		kernel_sock_shutdown(dsocket, SHUT_RDWR);
		sock_release(dsocket);
	}
	if (csocket) {
		kernel_sock_shutdown(csocket, SHUT_RDWR);
		sock_release(csocket);
	}

	return err;
}

static void dtt_set_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream, long timeout)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
	if (socket) {
#ifdef _WIN
		socket->sk_linux_attr->sk_rcvtimeo = timeout;
#else // _LIN
		socket->sk->sk_rcvtimeo = timeout;
#endif
	}
}

static long dtt_get_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN
	return socket->sk_linux_attr->sk_rcvtimeo;
#else // _LIN
	return socket->sk->sk_rcvtimeo;
#endif
}

static bool dtt_stream_ok(struct bsr_transport *transport, enum bsr_stream stream)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	return socket && socket->sk;
}

static void dtt_update_congested(struct bsr_tcp_transport *tcp_transport)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(tcp_transport);
#if 0 
	// not support data socket congestion
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk_linux_attr;
	struct _buffering_attr *buffering_attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
	struct ring_buffer *bab = buffering_attr->bab;

    int sk_wmem_queued = 0;
    if (bab) {
        sk_wmem_queued = bab->sk_wmem_queued;
    }
	else {
		// don't know how to get WSK tx buffer usage yet. Ignore it.
	}
	
	bsr_debug_tr("dtt_update_congested:  sndbuf=%d sk_wmem_queued=%d", sock->sk_sndbuf, sk_wmem_queued);

	if (sk_wmem_queued > sock->sk_sndbuf * 4 / 5) // reached 80%
    {
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
    }
#endif
#else // _LIN
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk;

	if (sock->sk_wmem_queued > sock->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
#endif
}

static int dtt_send_page(struct bsr_transport *transport, enum bsr_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
	int len = (int)size;
	int err = -EIO;
	bool is_sendbuf = false;
	struct _buffering_attr *buffering_attr;

#ifdef _LIN
	mm_segment_t oldfs;
#endif

	// DW-674 safely uncork operation, if socket is not NULL.(bsr 8.4.x referenced)
	if(!socket) { 
		return -EIO;
	}
	
#ifdef _LIN
	oldfs = get_fs();
#endif
#ifdef _WIN64
	BUG_ON_INT32_OVER(size);
#endif

	msg_flags |= MSG_NOSIGNAL;
	dtt_update_congested(tcp_transport);
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif

#ifdef _WIN
	buffering_attr = &socket->buffering_attr;
#else
	buffering_attr = &tcp_transport->buffering_attr[stream];
#endif

	is_sendbuf = (buffering_attr->send_buf_thread_handle != NULL) && (buffering_attr->bab != NULL);

	// BSR-983
	if (!is_sendbuf) 
		transport->ko_count[stream] = transport->net_conf->ko_count;

	do {
		int sent;

#ifdef _WIN
#ifdef _WIN_SEND_BUF
		sent = send_buf(transport, stream, socket, (void *)((unsigned char *)(page) +offset), len);
		// WIN32_SEND_ERR_FIX: move we_should_drop_the_connection to inside of send_buf, because retransmission occurred
#else
		sent = Send(socket->sk, (void *)((unsigned char *)(page) + offset), len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, transport, stream);
#endif
#else // _LIN
#ifdef _LIN_SEND_BUF
		// BSR-12
		sent = send_buf(tcp_transport, stream, socket, (void *)((unsigned char *)(page_address(page)) +offset), len, msg_flags);
#else		
		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
#endif
#endif
		if (sent <= 0) {
#ifdef _SEND_BUF
			if (sent == -EAGAIN) 
			{
				// BSR-977 correct to resend if -EAGAIN error occurs when no send buffer is used
				if (!is_sendbuf) {
					if (!bsr_stream_send_timed_out(transport, stream)) 
						continue;
				}
			}
#else
			if (sent == -EAGAIN) {
				if (!bsr_stream_send_timed_out(transport, stream))
					continue;
			}
#endif
			tr_warn(transport, "%s: size=%d len=%d sent=%d",
			     __func__, (int)size, len, sent);
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;

		// BSR-977 set ko_count if no send buffer is used on successful send.
		if (!is_sendbuf)
			transport->ko_count[stream] = transport->net_conf->ko_count;
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
#ifdef _LIN
	set_fs(oldfs);
#endif
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}

static int dtt_send_zc_bio(struct bsr_transport *transport, struct bio *bio)
{
	BSR_BIO_VEC_TYPE bvec;
	BSR_ITER_TYPE iter;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = dtt_send_page(transport, DATA_STREAM, bvec BVD bv_page,
				      bvec BVD bv_offset, bvec BVD bv_len,
				      bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;

#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
#endif
	}
	return 0;
}

static void dtt_cork(struct socket *socket)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(socket);
	// not support.
#else // _LIN
#ifdef COMPAT_HAVE_TCP_SOCK_SET_CORK
    tcp_sock_set_cork(socket->sk, true);
#else
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
#endif
}

static void dtt_uncork(struct socket *socket)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(socket);
	// not support.
#else // _LIN
#ifdef COMPAT_HAVE_TCP_SOCK_SET_CORK
	tcp_sock_set_cork(socket->sk, false);
#else
	int val = 0;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
#endif
}

static void dtt_quickack(struct socket *socket)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(socket);
	// not support.
#else // _LIN
#ifdef COMPAT_HAVE_TCP_SOCK_SET_QUICKACK
    tcp_sock_set_quickack(socket->sk, 2);
#else
	int val = 2;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val));
#endif
#endif
}

static bool dtt_hint(struct bsr_transport *transport, enum bsr_stream stream,
		enum bsr_tr_hints hint)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	bool rv = true;
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return false;

	switch (hint) {
	case CORK:
		dtt_cork(socket);
		break;
	case UNCORK:
		dtt_uncork(socket);
		break;
	case NODELAY:
		dtt_nodelay(socket);
		break;
	case NOSPACE:
#ifdef _LIN
		if (socket->sk->sk_socket)
			set_bit(SOCK_NOSPACE, &socket->sk->sk_socket->flags);
#endif
		break;
	case QUICKACK:
		dtt_quickack(socket);
		break;
	default: /* not implemented, but should not trigger error handling */
		return true;
	}

	return rv;
}

static void dtt_debugfs_show_stream(struct seq_file *m, struct socket *socket)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(socket);
	UNREFERENCED_PARAMETER(m);
#else // _LIN
	struct sock *sk = socket->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	seq_printf(m, "unread receive buffer: %u Byte\n",
		   tp->rcv_nxt - tp->copied_seq);
	seq_printf(m, "unacked send buffer: %u Byte\n",
		   tp->write_seq - tp->snd_una);
	seq_printf(m, "send buffer size: %u Byte\n", sk->sk_sndbuf);
	seq_printf(m, "send buffer used: %u Byte\n", sk->sk_wmem_queued);
#endif
}

static void dtt_debugfs_show(struct bsr_transport *transport, struct seq_file *m)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(transport);
	UNREFERENCED_PARAMETER(m);

#else // _LIN
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	enum bsr_stream i;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct socket *socket = tcp_transport->stream[i];

		if (socket) {
			seq_printf(m, "%s stream\n", i == DATA_STREAM ? "data" : "control");
			dtt_debugfs_show_stream(m, socket);
		}
	}
#endif
}

static int dtt_add_path(struct bsr_transport *transport, struct bsr_path *bsr_path)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
#ifdef _LIN
	struct dtt_path *path = container_of(bsr_path, struct dtt_path, path);
#endif
	bool active; //TODO: The implementation of dtt_add_path differs from 9.0.6. Need to re-check

	bsr_path->established = false;
#ifdef _LIN
	INIT_LIST_HEAD(&path->sockets);
#endif
retry:
	active = test_bit(DTT_CONNECTING, &tcp_transport->flags);
	if (!active && bsr_path->listener)
		bsr_put_listener(bsr_path);

	if (active && !bsr_path->listener) {
		int err = bsr_get_listener(transport, bsr_path, dtt_create_listener);
		if (err)
			return err;
	}

	spin_lock(&tcp_transport->paths_lock);
	if (active != test_bit(DTT_CONNECTING, &tcp_transport->flags)) {
		spin_unlock(&tcp_transport->paths_lock);
		goto retry;
	}
	list_add(&bsr_path->list, &transport->paths);
	spin_unlock(&tcp_transport->paths_lock);

	return 0;
}

static int dtt_remove_path(struct bsr_transport *transport, struct bsr_path *bsr_path)
{
	struct bsr_tcp_transport *tcp_transport =
		container_of(transport, struct bsr_tcp_transport, transport);
	struct dtt_path *path = container_of(bsr_path, struct dtt_path, path);

	if (bsr_path->established)
		return -EBUSY;

	spin_lock(&tcp_transport->paths_lock);
	list_del_init(&bsr_path->list);
	spin_unlock(&tcp_transport->paths_lock);
	bsr_put_listener(&path->path);
	
	return 0;
}

#ifdef _WIN
int __init dtt_initialize(void)
#else // _LIN
//static int __init dtt_initialize(void) // TODO
int dtt_initialize(void)
#endif
{
	return bsr_register_transport_class(&tcp_transport_class,
					     BSR_TRANSPORT_API_VERSION,
					     sizeof(struct bsr_transport));
}
#if 0 // disable. Not used in bsr.
static void __exit dtt_cleanup(void)
{
	bsr_unregister_transport_class(&tcp_transport_class);
}
#endif

#ifdef _SEND_BUF
#ifdef _WIN_SEND_BUF

extern KSTART_ROUTINE send_buf_thread;

static bool dtt_start_send_buffring(struct bsr_transport *transport, signed long long size)
{
	struct bsr_tcp_transport* tcp_transport = container_of(transport, struct bsr_tcp_transport, transport);
	struct bsr_connection* connection = container_of(transport, struct bsr_connection, transport);

	if (size > 0 ) {
		for (int i = 0; i < 2; i++) {
			if (tcp_transport->stream[i] != NULL) {
				struct _buffering_attr *attr = &tcp_transport->stream[i]->buffering_attr;

				if (attr->bab != NULL) {
					tr_warn(transport, "Unexpected: send buffer bab(%s) already exists!", tcp_transport->stream[i]->name);
					return FALSE;
				}

				if (attr->send_buf_thread_handle != NULL) {
					tr_warn(transport, "Unexpected: send buffer thread(%s) already exists!", tcp_transport->stream[i]->name);
					return FALSE;
				}

				if (i == CONTROL_STREAM) {
					size = CONTROL_BUFF_SIZE; // meta bab is about 5MB
				}

				if ((attr->bab = create_ring_buffer(connection, tcp_transport->stream[i]->name, size, i)) != NULL) {
					KeInitializeEvent(&attr->send_buf_kill_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_killack_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_thr_start_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->ring_buf_event, SynchronizationEvent, FALSE);

					if (i == DATA_STREAM)
						clear_bit(IDX_STREAM, &tcp_transport->flags);
					else
						set_bit(IDX_STREAM, &tcp_transport->flags);

					NTSTATUS Status = PsCreateSystemThread(&attr->send_buf_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, send_buf_thread, tcp_transport);
					if (!NT_SUCCESS(Status)) {
						tr_warn(transport, "send-buffering: create thread(%s) failed(0x%08X)", tcp_transport->stream[i]->name, Status);
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
						return FALSE;
					}
					ZwClose(attr->send_buf_thread_handle);
					// wait send buffering thread start...
					KeWaitForSingleObject(&attr->send_buf_thr_start_event, Executive, KernelMode, FALSE, NULL);
				
				}
				else {
					if (i == CONTROL_STREAM) {
						attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
						
						// kill DATA_STREAM thread
						KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
						//bsr_info(47, BSR_LC_ETC, NO_OBJECT,"wait for send_buffering_data_thread(%s) ack", tcp_transport->stream[i]->name);
						KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
						//bsr_info(48, BSR_LC_ETC, NO_OBJECT,"send_buffering_data_thread(%s) acked", tcp_transport->stream[i]->name);
						//ZwClose(attr->send_buf_thread_handle);
						attr->send_buf_thread_handle = NULL;
						
						// free DATA_STREAM bab
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
					}
					return FALSE;
				}
			}
			else {
				tr_warn(transport, "Unexpected: send buffer socket(channel:%d) is null!", i);
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}
#else // _LIN_SEND_BUF
extern int send_buf_thread(void *p);

static bool dtt_start_send_buffring(struct bsr_transport *transport, signed long long size)
{
	struct bsr_tcp_transport* tcp_transport = container_of(transport, struct bsr_tcp_transport, transport);
	struct bsr_connection* connection = container_of(transport, struct bsr_connection, transport);
	int i = 0;

	if (size > 0 ) {
		for (i = 0; i < 2; i++) {
			if (tcp_transport->stream[i] != NULL) {
				struct _buffering_attr *attr = &tcp_transport->buffering_attr[i];
				if (attr->bab != NULL) {
					tr_warn(transport, "Unexpected: send buffer bab(channel:%d) already exists!", i);
					return false;
				}

				if (attr->send_buf_thread_handle != NULL) {
					tr_warn(transport, "Unexpected: send buffer thread(channel:%d) already exists!", i);
					return false;
				}

				if (i == CONTROL_STREAM) {
					size = CONTROL_BUFF_SIZE; // meta bab is about 5MB
				}

				if ((attr->bab = create_ring_buffer(connection, NULL, size, i)) != NULL) {
					attr->send_buf_kill_event = false;
					init_waitqueue_head(&attr->send_buf_killack_event);
					init_waitqueue_head(&attr->send_buf_thr_start_event);
					init_waitqueue_head(&attr->ring_buf_event);

					if(i == DATA_STREAM)
						clear_bit(IDX_STREAM, &tcp_transport->flags);
					else
						set_bit(IDX_STREAM, &tcp_transport->flags);

					attr->send_buf_thread_handle = kthread_run(send_buf_thread, (void *)tcp_transport, "send_buf_thr");

					if(!attr->send_buf_thread_handle || IS_ERR(attr->send_buf_thread_handle)) {
						tr_warn(transport, "send-buffering: create thread(channel:%d) failed(%d)", i, (int)IS_ERR(attr->send_buf_thread_handle));
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
						return false;
					}
					wait_event(attr->send_buf_thr_start_event, test_bit(SEND_BUF_START, &attr->flags));
					clear_bit(SEND_BUF_START, &attr->flags);
				}
				else {
					if (i == CONTROL_STREAM) {
						attr = &tcp_transport->buffering_attr[DATA_STREAM];
						attr->send_buf_kill_event = true;
						wait_event(attr->send_buf_killack_event, test_bit(SEND_BUF_KILLACK, &attr->flags));
						clear_bit(SEND_BUF_KILLACK, &attr->flags);
						attr->send_buf_thread_handle = NULL;
						
						// free DATA_STREAM bab
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
					}
					return false;
				}
			}
			else {
				tr_warn(transport, "Unexpected: send buffer socket(channel:%d) is null!", i);
				return false;
			}
		}
		return true;
	}
	return false;
}
#endif

#ifdef _WIN_SEND_BUF
static void dtt_stop_send_buffring(struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport = container_of(transport, struct bsr_tcp_transport, transport);
	struct _buffering_attr *attr;

	for (int i = 0; i < 2; i++) {
		if (tcp_transport->stream[i] != NULL) {
			attr = &tcp_transport->stream[i]->buffering_attr;

			if (attr->send_buf_thread_handle != NULL) {
				KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
				//bsr_info(49, BSR_LC_ETC, NO_OBJECT,"wait for send_buffering_data_thread(%s) ack", tcp_transport->stream[i]->name);
				KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
				//bsr_info(50, BSR_LC_ETC, NO_OBJECT,"send_buffering_data_thread(%s) acked", tcp_transport->stream[i]->name);
				//ZwClose(attr->send_buf_thread_handle);
				attr->send_buf_thread_handle = NULL;
			}
			else {
				bsr_warn(28, BSR_LC_SEND_BUFFER, NO_OBJECT, "Stop send_buffer, No send_buffering thread(%s)", tcp_transport->stream[i]->name);
			}
		}
		else {
			bsr_warn(29, BSR_LC_SEND_BUFFER, NO_OBJECT, "Stop send_buffer, No stream(channel:%d)", i);
		}
	}
	return;
}
#else // _LIN_SEND_BUF
static void dtt_stop_send_buffring(struct bsr_transport *transport)
{
	struct bsr_tcp_transport *tcp_transport = container_of(transport, struct bsr_tcp_transport, transport);
	struct _buffering_attr *attr;
	int i = 0;

	for (i = 0; i < 2; i++) {
		if (tcp_transport->stream[i] != NULL) {
			attr = &tcp_transport->buffering_attr[i];

			if (attr->send_buf_thread_handle != NULL) {
				attr->send_buf_kill_event = true;
				wait_event(attr->send_buf_killack_event, test_bit(SEND_BUF_KILLACK, &attr->flags));
				clear_bit(SEND_BUF_KILLACK, &attr->flags);
				attr->send_buf_thread_handle = NULL;
			}
			else {
				bsr_warn(30, BSR_LC_SEND_BUFFER, NO_OBJECT, "Stop send_buffer, No send_buffering thread(%s)", i);
			}
		}
		else {
			bsr_warn(31, BSR_LC_SEND_BUFFER, NO_OBJECT, "Stop send_buffer, No stream(channel:%d)", i);
		}
	}
	return;
}
#endif
#endif // _SEND_BUF

//#ifdef _LIN
//module_init(dtt_initialize)
//module_exit(dtt_cleanup)
//#endif

