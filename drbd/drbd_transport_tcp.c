﻿/*
   drbd_transport_tcp.c

   This file is part of DRBD.

   Copyright (C) 2014, LINBIT HA-Solutions GmbH.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#ifdef _WIN32
#include "windows/drbd.h"
#include <linux/drbd_genl_api.h>
#include <drbd_protocol.h>
#include <drbd_transport.h>
#include "drbd_wrappers.h"
#include <wsk2.h>
#include <linux-compat\drbd_endian.h>

#else
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#endif

#ifndef _WIN32
MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
#endif

struct buffer {
	void *base;
	void *pos;
};

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	struct socket *stream[2];
	struct buffer rbuf[2];
	bool in_use;
};

struct dtt_listener {
	struct drbd_listener listener;
	void (*original_sk_state_change)(struct sock *sk);
	struct socket *s_listen;
};

struct dtt_waiter {
	struct drbd_waiter waiter;
	struct socket *socket;
};

static int dtt_init(struct drbd_transport *transport);
static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int dtt_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
#ifdef _WIN32_V9
static int dtt_recv_pages(struct drbd_transport *transport, void* buffer, size_t size);
#else
static int dtt_recv_pages(struct drbd_transport *transport, struct page **page, size_t size);
#endif
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_transport *, struct drbd_path *path);
static int dtt_remove_path(struct drbd_transport *, struct drbd_path *);

static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
#ifndef _WIN32_V9 // tcp_transport_class 의 module 필드 어떻게 처리할지 검토필요. => module 필드 제거
	.module = THIS_MODULE,
#endif
	.init = dtt_init,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static struct drbd_transport_ops dtt_ops = {
	.free = dtt_free,
	.connect = dtt_connect,
	.recv = dtt_recv,
	.recv_pages = dtt_recv_pages,
	.stats = dtt_stats,
	.set_rcvtimeo = dtt_set_rcvtimeo,
	.get_rcvtimeo = dtt_get_rcvtimeo,
	.send_page = dtt_send_page,
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
};


static void dtt_nodelay(struct socket *socket)
{
	int val = 1;
#ifdef _WIN32_V9 // kernel_setsockopt linux kernel func. V9 포팅 필요.
	// nagle disable 은 기존 V8 방식으로 처리.
#else
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
#endif
}

int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
#ifdef _WIN32_V9 //적절한지 검토 필요. 할당이 실패했을 때 하단의 kfree 에서 제대로 해제가 되는지 확인 필요. => 해제 관련 문제 확인, 수정 완료.
		void *buffer = (void *)kzalloc(4096, GFP_KERNEL, '009D'); // _WIN32_CHECK 임시 Tag '009D'
		if (!buffer) {
			//DATA_STREAM 할당 실패 시 하단에서 해제 할 때 NULL 체크하기 위함. 
			// => DATA_STREAM 할당 성공, CONTROL_STREAM 할당 실패 했을 때에는 기존 코드가 문제 없다. 그러나 DATA_STREAM 할당 부터 실패 했을 경우엔 하단의 kfree 에서 잘못된 메모리가 넘겨질 가능성이 있다.
			tcp_transport->rbuf[i].base = NULL; // base가 NULL 초기화 보장이 되는지 모르겠다. 확실히 하기 위해.
			WDRBD_WARN("dtt_init kzalloc %s allocation fail\n", i ? "CONTROL_STREAM" : "DATA_STREAM" );
			goto fail;
		}
#else 
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
#endif
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}
	tcp_transport->in_use = false;

	return 0;
fail:

#ifdef _WIN32_V9 // 
	kfree((void *)tcp_transport->rbuf[0].base);
#else
	free_page((unsigned long)tcp_transport->rbuf[0].base);
#endif
	
	return -ENOMEM;
}

static struct drbd_path* dtt_path(struct drbd_transport *transport)
{
	return list_first_entry_or_null(&transport->paths, struct drbd_path, list);
}

static void dtt_free_one_sock(struct socket *socket)
{
#ifdef _WIN32_V9
	synchronize_rcu_w32_wlock();
#endif
	if (socket) {

		// 함수 scope 를 벗어난 rcu 해제... V9 포팅필요.
		// lock 획득이 제대로 되고 있는지...dtt_free_one_sock 호출 부 확인 필요 => rcu lock 에 대한 이해 부족으로 인한 주석.
		// synchronize_rcu_w32_wlock 방식의 V8 구현 반영 
		synchronize_rcu();

		kernel_sock_shutdown(socket, SHUT_RDWR);
		sock_release(socket);
#ifdef _WIN32_V9
		return;
#endif
	}
#ifdef _WIN32_V9
	synchronize_rcu();
#endif

}

static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
	struct drbd_path *path;

	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
			dtt_free_one_sock(tcp_transport->stream[i]);
			tcp_transport->stream[i] = NULL;
		}
	}
	tcp_transport->in_use = false;

	if (free_op == DESTROY_TRANSPORT) {
		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
#ifdef _WIN32_V9 
			kfree((void *)tcp_transport->rbuf[i].base);
#else
			free_page((unsigned long)tcp_transport->rbuf[i].base);
#endif	
			tcp_transport->rbuf[i].base = NULL;
		}
		path = dtt_path(transport);
		if (path) {
			list_del(&path->list);
			kfree(path);
		}
	}
}

//한번 더 재 검토 필요.
static int _dtt_send(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
		      void *buf, size_t size, unsigned msg_flags)
{
#ifdef _WIN32
	size_t iov_len = size;
#else
	struct kvec iov;
	struct msghdr msg;
#endif
	
	int rv, sent = 0;

#ifdef _WIN32 
	// not support. V8 기존 구현 유지.
#else
	iov.iov_base = buf;
	iov.iov_len = size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = msg_flags | MSG_NOSIGNAL;
#endif
	

	/* THINK  if (signal_pending) return ... ? */
#ifdef _WIN32_CHECK
	// 기존 V8에서 data 소켓인지 비교하여 rcu_dereference 하고 drbd_update_congested 하는 구현이 제거 되었다. 추후 확인 요망.
#endif

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block DRBD_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
#ifdef _WIN32
		rv = Send(socket->sk, buf, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo);
#else
		rv = kernel_sendmsg(socket, &msg, &iov, 1, size);
#endif
		if (rv == -EAGAIN) {
			struct drbd_transport *transport = &tcp_transport->transport;
			enum drbd_stream stream =
				tcp_transport->stream[DATA_STREAM] == socket ?
					DATA_STREAM : CONTROL_STREAM;

			if (drbd_stream_send_timed_out(transport, stream))
				break;
			else
				continue;
		}
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
#ifdef _WIN32 //기존 구현 유지
		(char*)buf += rv;
		iov_len -= rv;
#else
		iov.iov_base += rv;
		iov.iov_len -= rv;
#endif
	} while (sent < size);

#ifdef _WIN32_CHECK
	// 기존 V8에서 data 소켓인지 비교하여 clear_bit하는 구현이 제거 되었다. 추후 확인 요망.
#endif

	if (rv <= 0) {
#ifdef _WIN32_CHECK
		// 기존 V8에서 rv <=0 인 경우 conn_request_state 상태를 바꾸는 구현이 제거됨. 추후 확인 요망.
#endif
		return rv;
	}

	return sent;
}


static int dtt_recv_short(struct socket *socket, void *buf, size_t size, int flags)
{
#ifndef _WIN32
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};
#endif

#ifdef _WIN32
	flags = WSK_FLAG_WAITALL;
	return Receive(socket->sk, buf, size, flags, socket->sk_linux_attr->sk_rcvtimeo);
#else
	return kernel_recvmsg(socket, &msg, &iov, 1, size, msg.msg_flags); //_WIN32_CHECK 기존 V8에서 사용한 sock_recvmsg 와 차이점이 있는지 검토 필요.
#endif

}

// V8의 drbd_recv_short 가 dtt_recv , dtt_recv_short 로 대체 되었다. 추후 V8의 drbd_recv_short 를 참고하여 포팅한다.
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	void *buffer = NULL; 
#else
	void *buffer;
#endif
	int rv;

	if (flags & CALLER_BUFFER) {
		buffer = *buf;
		rv = dtt_recv_short(socket, buffer, size, flags & ~CALLER_BUFFER);
	} else if (flags & GROW_BUFFER) {
#ifdef _WIN32_V9
		ASSERT(*buf == tcp_transport->rbuf[stream].base);
#else
		TR_ASSERT(transport, *buf == tcp_transport->rbuf[stream].base);
#endif	

		buffer = tcp_transport->rbuf[stream].pos;

#ifdef _WIN32_V9
		ASSERT(((UCHAR*)buffer - (UCHAR*)*buf) + size <= PAGE_SIZE);//gcc void* 연산은 기본 1바이트 연산.
#else
		TR_ASSERT(transport, (buffer - *buf) + size <= PAGE_SIZE);
#endif
		rv = dtt_recv_short(socket, buffer, size, flags & ~GROW_BUFFER);
	} else {
		buffer = tcp_transport->rbuf[stream].base;

		rv = dtt_recv_short(socket, buffer, size, flags);
		if (rv > 0)
			*buf = buffer;
	}

	if (rv > 0) {
#ifdef _WIN32_V9
		tcp_transport->rbuf[stream].pos = (UCHAR*)buffer + rv; //buffer 포인터 연산 UCHAR* 타입 1바이트 연산 하면 되나???.... 찝찝하니...다시 확인.=> gcc 에서 void* 증감연산은 기본 1바이트 연산.
#else
		tcp_transport->rbuf[stream].pos = buffer + rv; 
#endif
	}

	return rv;
}

#ifdef _WIN32_V9
static int dtt_recv_pages(struct drbd_transport *transport, void* page, size_t size)
#else
static int dtt_recv_pages(struct drbd_transport *transport, struct page **page, size_t size)
#endif
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
#ifdef _WIN32
	void* win32_big_page = page;
	void* all_pages = NULL;
#else
	struct page *all_pages, *page;
#endif
	int err;

#ifdef _WIN32
	if (size) {
		all_pages = drbd_alloc_pages(transport, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!all_pages)
			return -ENOMEM;

		win32_big_page = all_pages;
	}
	else {
		win32_big_page = NULL;
	}
	// 기존 drbd_recv_all_warn 으로 처리되던 부분이 dtt_recv_short 로 간략하게 처리되고 있다.(drbd_recv_all_warn 내부로직이 복잡) 차이점에 대한 추후 분석 필요.
	err = dtt_recv_short(socket, win32_big_page, size, 0); // *win32_big_page 포인터 버퍼 , size 값 유효성 디버깅 필요
	if (err < 0) {
		goto fail;
	}
#else
	all_pages = drbd_alloc_pages(transport, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	if (!all_pages)
		return -ENOMEM;
	
	page = all_pages;

	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(socket, data, len, 0);
		kunmap(page);
		if (err < 0)
			goto fail;
		size -= len;
	}

	*pages = all_pages;
#endif
	return 0;
fail:
	drbd_free_pages(transport, all_pages, 0);
	return err;
}

static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {

		struct sock *sk = socket->sk;
#ifdef _WIN32_V9
		// TCP 전송 상태를 확인하여 부가 동작(dtt_hint)을 취할 수 있는 기능. => WSK 에 제공 기능이 없음. 현재로서는 포팅하지 않아도 무방. 추후 검토.
		// unread_received, unacked_send 정보 열람용. send_buffer_size, send_buffer_used 는 두 값을 비교하여 TCP 전송에 부하가 걸려있는 상태에 따라 dtt_hint 호출.
		stats->send_buffer_size = sk->sk_sndbuf; //sk->sk_sndbuf, sk->sk_wmem_queued 값이 정상적으로 들어가 있는지 모르겠다. 디버깅으로 확인 필요._WIN32_CHECK
		stats->send_buffer_used = sk->sk_wmem_queued;
#else
		struct tcp_sock *tp = tcp_sk(sk);

		stats->unread_received = tp->rcv_nxt - tp->copied_seq;
		stats->unacked_send = tp->write_seq - tp->snd_una;
		stats->send_buffer_size = sk->sk_sndbuf;
		stats->send_buffer_used = sk->sk_wmem_queued;
#endif
	}
}

static void dtt_setbufsize(struct socket *socket, unsigned int snd,
			   unsigned int rcv)
{
// [choi] V8 drbd_setbufsize 적용
#ifdef _WIN32
#ifdef _WIN32_SEND_BUFFING
    if (snd) 
    { 
        sock->sk_linux_attr->sk_sndbuf = snd;
    }
#endif

    if( rcv != 0 )
    {
        ControlSocket(socket->sk, WskSetOption, SO_RCVBUF, SOL_SOCKET,
            sizeof(unsigned int), &rcv, 0, NULL, NULL);
    }
#else
	/* open coded SO_SNDBUF, SO_RCVBUF */
	if (snd) {
		socket->sk->sk_sndbuf = snd;
		socket->sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
	if (rcv) {
		socket->sk->sk_rcvbuf = rcv;
		socket->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
#endif
}

// Connect(socket->sk, (struct sockaddr *) &peer_addr); 부분 ipv6 처리되는지 여부 확인 필요. _WIN32_CHECK
static int dtt_try_connect(struct drbd_transport *transport, struct socket **ret_socket)
{
	const char *what;
	struct socket *socket;
#ifdef _WIN32
	struct sockaddr_storage_win my_addr, peer_addr;
	SOCKADDR_IN	LocalAddress = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
#else
	struct sockaddr_storage my_addr, peer_addr;
#endif
	
	struct net_conf *nc;
	int err;

	int sndbuf_size, rcvbuf_size, connect_int;

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

	my_addr = dtt_path(transport)->my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = dtt_path(transport)->peer_addr;

	what = "sock_create_kern";
#ifdef _WIN32
	socket = kzalloc(sizeof(struct socket), 0, '42DW');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;
	
	socket->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
	if (socket->sk == NULL) {
		err = -1;
		goto out;
	}
	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '52DW');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
		socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;
#else
	err = sock_create_kern(my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
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
	*  able to use lo: interfaces for drbd.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
#ifdef _WIN32
	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;
	LocalAddress.sin_port = HTONS(0);

	status = Bind(socket->sk, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("Bind() failed with status 0x%08X \n", status);
		err = -EINVAL;
		goto out;
	}
#else
	err = socket->ops->bind(socket, (struct sockaddr *) &my_addr, dtt_path(transport)->my_addr_len);
#endif
	if (err < 0)
		goto out;
	
	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
	
#ifdef _WIN32
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
				err = 0; // Connect ok 
			} else {
				err = -EINVAL;
			}
		}
	}
#else
	err = socket->ops->connect(socket, (struct sockaddr *) &peer_addr,
		dtt_path(transport)->peer_addr_len, 0);
#endif
	
	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
		}
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		if (err != -EAGAIN)
#ifdef _WIN32_V9
			WDRBD_ERROR("%s failed, err = %d\n", what, err);
#else
			tr_err(transport, "%s failed, err = %d\n", what, err);
#endif
			
	} else {
		*ret_socket = socket;
	}

	return err;
}

static int dtt_send_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
			     enum drbd_packet cmd, enum drbd_stream stream)
{
	struct p_header80 h;
	int msg_flags = 0;
	int err;

	if (!socket)
		return -EIO;

	h.magic = cpu_to_be32(DRBD_MAGIC);
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
#ifdef _WIN32
	SIZE_T		out = 0;
	NTSTATUS	Status;
#else
	int rr;
	char tb[4];
#endif
	if (!*socket)
		return false;

#ifdef _WIN32 // 기존 구현 유지 ??? 소켓의 상태를 확인하고 상태가 유효하지 않으면 free 시키는 로직 => 소켓 상태 확인이...BACKLOG 정보 확인으로 가능한가?... history 를 알려주세요~...
	
	Status = ControlSocket( (*socket)->sk, WskIoctl, SIO_WSK_QUERY_RECEIVE_BACKLOG, 0, 0, NULL, sizeof(SIZE_T), &out, NULL );
	if (NT_SUCCESS(Status))	{
		if (out > 0) {
			WDRBD_INFO("socket(0x%p), ControlSocket(%s): backlog=%d\n", (*socket), (*socket)->name, out); // _WIN32
		}
		return true;
	}
	else {
		WDRBD_ERROR("socket(0x%p), ControlSocket(%s): SIO_WSK_QUERY_RECEIVE_BACKLOG failed=0x%x\n", (*socket), (*socket)->name, Status); // _WIN32
		sock_release(*socket);
		*socket = NULL;
		return false;
	}
#else
	rr = dtt_recv_short(*socket, tb, 4, MSG_DONTWAIT | MSG_PEEK);

	if (rr > 0 || rr == -EAGAIN) {
		return true;
	}
	else {
		sock_release(*socket);
		*socket = NULL;
		return false;
	}
#endif

}

static bool dtt_connection_established(struct drbd_transport *transport,
				   struct socket **socket1,
				   struct socket **socket2)
{
	struct net_conf *nc;
	int timeout;

	if (!*socket1 || !*socket2)
		return false;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

#ifdef _WIN32
	timeout = (nc->sock_check_timeo ? nc->sock_check_timeo : nc->ping_timeo) * HZ / 10;
#else
	timeout = (nc->sock_check_timeo ? : nc->ping_timeo) * HZ / 10;
#endif

	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	dtt_socket_ok_or_free(socket1);
	dtt_socket_ok_or_free(socket2);

	return *socket1 && *socket2;
}

static bool dtt_wait_connect_cond(struct dtt_waiter *waiter)
{
	struct drbd_listener *listener = waiter->waiter.listener;
	bool rv;

	spin_lock_bh(&listener->waiters_lock);
	rv = waiter->waiter.listener->pending_accepts > 0 || waiter->socket != NULL;

	spin_unlock_bh(&listener->waiters_lock);

	return rv;
}

static void unregister_state_change(struct sock *sock, struct dtt_listener *listener)
{
#ifdef _WIN32
	// not support => 지원하지 않는 이유?
#else 
	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_state_change = listener->original_sk_state_change;
	sock->sk_user_data = NULL;
	write_unlock_bh(&sock->sk_callback_lock);
#endif
}

static int dtt_wait_for_connect(struct dtt_waiter *waiter, struct socket **socket)
{
#ifdef _WIN32_V9
	struct sockaddr_storage_win my_addr, peer_addr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WSK_SOCKET*	paccept_socket = NULL;
#else
    struct sockaddr_storage peer_addr;
#endif
	int connect_int, peer_addr_len, err = 0;
	long timeo;
#ifdef _WIN32_V9
	struct socket *s_estab = NULL; //리턴하기 전 *socket = s_estab; 에서 s_estab 가 잠재적으로 초기화 안됬을 수 있다고 컴파일 에러를 뱉어낸다. 
#else
	struct socket *s_estab;
#endif
	
	struct net_conf *nc;
	struct drbd_waiter *waiter2_gen;
	struct dtt_listener *listener =
		container_of(waiter->waiter.listener, struct dtt_listener, listener);

	rcu_read_lock();
	nc = rcu_dereference(waiter->waiter.transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:

#ifdef _WIN32 // V8에서 accept 전 wait 하는 구조는 제거 되었으나... V9에서 구조가 많이 변경되어 일단 남겨 둔다.=> if (timeo <= 0)return -EAGAIN; => timeo에 따라 EAGAIN 리턴되는 구조. _WIN32_CHECK
	wait_event_interruptible_timeout(timeo, waiter->waiter.wait, dtt_wait_connect_cond(waiter), timeo);
#else
	timeo = wait_event_interruptible_timeout(waiter->waiter.wait, dtt_wait_connect_cond(waiter), timeo);
#endif	
	if (timeo <= 0)
		return -EAGAIN;
	
	spin_lock_bh(&listener->listener.waiters_lock);
	if (waiter->socket) {
		s_estab = waiter->socket;
		waiter->socket = NULL;
	}
	else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;

		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
#ifdef _WIN32_V9
		// Accept 하고, s_estab 구조를 생성한다.
		my_addr = dtt_path(waiter->waiter.transport)->my_addr; // my_addr 가 이전 시점에 잘 들어가 있는 지 검증 필요._WIN32_CHECK
		memset(&peer_addr, 0, sizeof(struct sockaddr_in));
		paccept_socket = Accept(listener->s_listen->sk, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, status, timeo / HZ);
		if (paccept_socket) {
			s_estab = kzalloc(sizeof(struct socket), 0, '82DW');
			if (!s_estab) {
				return -ENOMEM;
			}
			s_estab->sk = paccept_socket;
			sprintf(s_estab->name, "estab_sock");
			s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '92DW');
			if (!s_estab->sk_linux_attr) {
				kfree(s_estab);
				return -ENOMEM;
			}
		}
		else {
			if (status == STATUS_TIMEOUT) {
				err = -EAGAIN;
			}
			else {
				err = -1;
			}
		}
#else
		err = kernel_accept(listener->s_listen, &s_estab, 0);
#endif
		if (err < 0)
			return err;
		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
#ifdef _WIN32
		unregister_state_change(s_estab->sk_linux_attr, listener); // unregister_state_change 가 V8에서 내부 구현이 안되었다. => V9 포팅 여부 검토 필요 _WIN32_CHECK
		status = GetRemoteAddress(s_estab->sk, (PSOCKADDR)&peer_addr); //V8에 없던 s_estab->ops->getname 구현. Accept 를 하고 peer 주소를 다시 획득한다. 분석 필요. _WIN32_CHECK
		if(status != STATUS_SUCCESS) {
			kfree(s_estab->sk_linux_attr);
			kfree(s_estab);
			return -1;
		}
#else
		unregister_state_change(s_estab->sk, listener);
		s_estab->ops->getname(s_estab, (struct sockaddr *)&peer_addr, &peer_addr_len, 2);
#endif
		spin_lock_bh(&listener->listener.waiters_lock);
		waiter2_gen = drbd_find_waiter_by_addr(waiter->waiter.listener, &peer_addr);
		if (!waiter2_gen) {
			struct sockaddr_in6 *from_sin6, *to_sin6;
			struct sockaddr_in *from_sin, *to_sin;
			struct drbd_transport *transport = waiter->waiter.transport;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				to_sin6 = (struct sockaddr_in6 *)&dtt_path(transport)->my_addr;
#ifdef _WIN32_V9
				WDRBD_ERROR("Closing unexpected connection from %pI6 to port %u\n", &from_sin6->sin6_addr, be16_to_cpu(to_sin6->sin6_port));
#else
				tr_err(transport, "Closing unexpected connection from "
					"%pI6 to port %u\n",
					&from_sin6->sin6_addr,
					be16_to_cpu(to_sin6->sin6_port));
#endif
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				to_sin = (struct sockaddr_in *)&dtt_path(transport)->my_addr;
#ifdef _WIN32_V9
				WDRBD_ERROR("Closing unexpected connection from %pI4 to port %u\n", &from_sin->sin_addr, be16_to_cpu(to_sin->sin_port));
#else
				tr_err(transport, "Closing unexpected connection from "
					"%pI4 to port %u\n",
					&from_sin->sin_addr,
					be16_to_cpu(to_sin->sin_port));
#endif
				break;
			}

			goto retry_locked;
		}
		if (waiter2_gen != &waiter->waiter) {
			struct dtt_waiter *waiter2 =
				container_of(waiter2_gen, struct dtt_waiter, waiter);

			if (waiter2->socket) {
#ifdef _WIN32_V9
				WDRBD_ERROR("Receiver busy; rejecting incoming connection\n");
#else
				tr_err(waiter2->waiter.transport,
					"Receiver busy; rejecting incoming connection\n");
#endif		
				goto retry_locked;
			}
			waiter2->socket = s_estab;
			s_estab = NULL;
			wake_up(&waiter2->waiter.wait);
			goto retry_locked;
		}

	}
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;

	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;
}

static int dtt_receive_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket)
{
	struct drbd_transport *transport = &tcp_transport->transport;
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
#ifdef _WIN32_V9
	socket->sk_linux_attr->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
#else
	socket->sk->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
#endif

	rcu_read_unlock();

	err = dtt_recv_short(socket, h, header_size, 0);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	if (h->magic != cpu_to_be32(DRBD_MAGIC)) {
#ifdef _WIN32_V9
		WDRBD_ERROR("Wrong magic value 0x%08x in receive_first_packet\n", be32_to_cpu(h->magic));
#else
		tr_err(transport, "Wrong magic value 0x%08x in receive_first_packet\n",
			 be32_to_cpu(h->magic));
#endif
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}

static void dtt_incoming_connection(struct sock *sock)
{
#ifndef _WIN32 // 일단 V8 구현을 따라간다. => state change 관련 구현에 대한 V9 포팅 여부 추후 검토 필요._WIN32_CHECK
	struct dtt_listener *listener = sock->sk_user_data;
	void (*state_change)(struct sock *sock);

	state_change = listener->original_sk_state_change;
	if (sock->sk_state == TCP_ESTABLISHED) {
		struct drbd_waiter *waiter;

		spin_lock(&listener->listener.waiters_lock);
		listener->listener.pending_accepts++;
		waiter = list_entry(listener->listener.waiters.next, struct drbd_waiter, list);
		wake_up(&waiter->wait);
		spin_unlock(&listener->listener.waiters_lock);
	}
	state_change(sock);
#endif
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

#ifdef _WIN32_V9
    unregister_state_change(listener->s_listen->sk_linux_attr, listener);
#else
	unregister_state_change(listener->s_listen->sk, listener);
#endif
	sock_release(listener->s_listen);
	kfree(listener);
}


// [choi] V8 prepare_listen_socket() 적용. WSK_ACCEPT_EVENT_CALLBACK은 disable 시켜둠. 
#ifdef WSK_ACCEPT_EVENT_CALLBACK
const WSK_CLIENT_LISTEN_DISPATCH dispatch = {
    AcceptEvent,
    NULL, // WskInspectEvent is required only if conditional-accept is used.
    NULL  // WskAbortEvent is required only if conditional-accept is used.
};
#endif
static int dtt_create_listener(struct drbd_transport *transport, struct drbd_listener **ret_listener)
{
	
#ifdef _WIN32
	int err = 0, sndbuf_size, rcvbuf_size; //err 0으로 임시 초기화.
	struct sockaddr_storage_win my_addr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
#else
	int err , sndbuf_size, rcvbuf_size;
	struct sockaddr_storage my_addr;
#endif
	
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

	my_addr = dtt_path(transport)->my_addr;

	what = "sock_create_kern";
#ifdef _WIN32
    s_listen = kzalloc(sizeof(struct socket), 0, '62DW');
    if (!s_listen)
    {
        err = -ENOMEM;
        goto out;
    }
    sprintf(s_listen->name, "listen_sock\0");
    s_listen->sk_linux_attr = 0;
    err = 0;
#ifdef WSK_ACCEPT_EVENT_CALLBACK
    ad->s_accept = kzalloc(sizeof(struct socket), 0, '82DW');
    if (!ad->s_accept)
    {
        err = -ENOMEM;
        goto out;
    }
    s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, ad, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
#else
    s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
#endif
    if (s_listen->sk == NULL) {
        err = -1;
        goto out;
    }
    s_listen->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '72DW');
    if (!s_listen->sk_linux_attr)
    {
        err = -ENOMEM;
        goto out;
    }
#else
	err = sock_create_kern(my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}
#endif

#ifdef _WIN32
    s_listen->sk_linux_attr->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
#else
	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
#endif
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
#ifdef _WIN32
    status = Bind(s_listen->sk, (PSOCKADDR)&my_addr);
    if (!NT_SUCCESS(status))
    {
        err = status;
    }
#else
	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, dtt_path(transport)->my_addr_len);
#endif
	if (err < 0)
		goto out;

	what = "kmalloc";
#ifdef _WIN32_V9
    listener = kmalloc(sizeof(*listener), GFP_KERNEL, "87DW");
#else
	listener = kmalloc(sizeof(*listener), GFP_KERNEL);
#endif
	if (!listener) {
		err = -ENOMEM;
		goto out;
	}

	listener->s_listen = s_listen;

#ifdef _WIN32
#ifdef WSK_ACCEPT_EVENT_CALLBACK
    what = "enable event callbacks";
    NTSTATUS s = STATUS_UNSUCCESSFUL;
    s = SetEventCallbacks(s_listen->sk, WSK_EVENT_ACCEPT);
    if (!NT_SUCCESS(s))
    {
        err = s;
        goto out;
    }
#endif
    //tconn->s_listen = s_listen; //_WIN32_CHECK
#endif

#ifndef _WIN32
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	listener->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = dtt_incoming_connection;
	s_listen->sk->sk_user_data = listener;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);

	what = "listen";
	err = s_listen->ops->listen(s_listen, 5);
	if (err < 0)
		goto out;
#endif
	listener->listener.listen_addr = my_addr; 
	listener->listener.destroy = dtt_destroy_listener;  
	*ret_listener = &listener->listener;

	return 0;
out:
	if (s_listen)
#ifdef _WIN32
    {
        sock_release(s_listen);
        //tconn->s_listen = 0; //_WIN32_CHECK
    }
#else
        sock_release(s_listen);
#endif

	if (err < 0 &&
		err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE)
#ifdef _WIN32_V9
		WDRBD_ERROR("%s failed, err = %d\n", what, err);
#else
		tr_err(transport, "%s failed, err = %d\n", what, err);
#endif
	kfree(listener);

	return err;
}

static void dtt_put_listener(struct dtt_waiter *waiter)
{
	drbd_put_listener(&waiter->waiter);
	if (waiter->socket) {
		sock_release(waiter->socket);
		waiter->socket = NULL;
	}
}

static int dtt_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

#ifdef _WIN32_V9
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LONG InputBuffer = 1;
#endif
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	struct dtt_waiter waiter;
	int timeout, err;
	bool ok;

	dsocket = NULL;
	csocket = NULL;

	if (!dtt_path(transport))
		return -EDESTADDRREQ;
	tcp_transport->in_use = true;

	waiter.waiter.transport = transport;
	waiter.socket = NULL;
	err = drbd_get_listener(&waiter.waiter, dtt_create_listener);
	if (err)
		return err;

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(transport, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			if (!dsocket) {
				dsocket = s;
				dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM);
			} else if (!csocket) {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
				dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM);
			} else {
#ifdef _WIN32_V9
				WDRBD_ERROR("Logic error in conn_connect()\n");
#else
				tr_err(transport, "Logic error in conn_connect()\n");
#endif
				goto out_eagain;
			}
		}

		if (dtt_connection_established(transport, &dsocket, &csocket))
			break;

retry:
		s = NULL;
		err = dtt_wait_for_connect(&waiter, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			int fp = dtt_receive_first_packet(tcp_transport, s);

			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
#ifdef _WIN32_V9
					WDRBD_WARN("initial packet S crossed\n");
#else
					tr_warn(transport, "initial packet S crossed\n");
#endif
					sock_release(dsocket);
					dsocket = s;
					goto randomize;
				}
				dsocket = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
#ifdef _WIN32_V9
					WDRBD_WARN("initial packet M crossed\n");
#else
					tr_warn(transport, "initial packet M crossed\n");
#endif
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
#ifdef _WIN32_V9
				WDRBD_WARN("Error receiving initial packet\n");
#else
				tr_warn(transport, "Error receiving initial packet\n");
#endif
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket);
	} while (!ok);

	dtt_put_listener(&waiter);

#ifdef _WIN32
	// data socket 에 대해선 옵션을 설정하는데, 컨트롤소켓(메타소켓)에 대해선 옵션을 설정 안하는 이유? _WIN32_CHECK
	status = ControlSocket(dsocket->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, NULL, NULL, NULL );
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("ControlSocket: SO_REUSEADDR: failed=0x%x\n", status); // EVENTLOG
		goto out;
	}
#else
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

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

#ifdef _WIN32
	dsocket->sk_linux_attr->sk_sndtimeo = timeout;
	csocket->sk_linux_attr->sk_sndtimeo = timeout;
#else
	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;
#endif
	return 0;

out_eagain:
	err = -EAGAIN;
out:
	dtt_put_listener(&waiter);
	if (dsocket)
		sock_release(dsocket);
	if (csocket)
		sock_release(csocket);

	return err;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	socket->sk_linux_attr->sk_rcvtimeo = timeout;
#else
	socket->sk->sk_rcvtimeo = timeout;
#endif
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	return socket->sk_linux_attr->sk_rcvtimeo;
#else
	return socket->sk->sk_rcvtimeo;
#endif
}

static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	return socket && socket->sk;
}

static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport)
{
#ifdef _WIN32_CHECK
    // DRBD_DOC: DRBD_CONGESTED_PORTING
    // 송출시 혼잡 정도를 체크한다.
    //  - sk_wmem_queued is the amount of memory used by the socket send buffer queued in the transmit queue 
    // WDRBD WSK는 송출 혼잡 판단 API를 제공하지 않는다. 또한 송출 버퍼가 없다.
    // 따라서 WDRBD는 drbd_update_congested 기능을 제공 못함.

#ifdef _WIN32_SEND_BUFFING
    struct sock *sk = tconn->data.socket->sk_linux_attr;
    struct ring_buffer *bab = tconn->data.socket->bab;
    int sk_wmem_queued = 0;
    if (bab)
    {
        sk_wmem_queued = bab->sk_wmem_queued;
    }
    if (sk_wmem_queued > sk->sk_sndbuf * 4 / 5) // reached 80%
    {
        set_bit(NET_CONGESTED, &tconn->flags);
    }
#endif
#else
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk;
	// sk_wmem_queued 에 대해 현재 구현하고 있지 않다. 추후 검토 필요. _WIN32_CHECK
	if (sock->sk_wmem_queued > sock->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
#endif
}

// 기존 V8 에서 xxx_send_page 가 사용되지 않고는 있으나... V9 포팅에서 다시 확인이 필요하다. => BUG 처리하고, _drbd_no_send_page 로 유도한다.
// _drbd_no_send_page 는 결국 dtt_send_page 를 호출하게 된다.... dtt 계층에서 기존의 V8 의 _drbd_no_send_page 를 구현해줄 함수가 필요.
// V8 은 no_send_page 방식의 경우 drbd_sendall/drbd_send 를 호출하여 V9 기준의 _dtt_send 를 호출하는 구조이다.
// V9 은 no_send_page 방식의 경우에도 dtt_send_page 를 호출하여 send_page 방식과 동일한 인터페이스를 사용하게 되어 있다.
// _dtt_send 는 dtt_connect 시점의 dtt_send_first_packet 에 의해서만 사용된다.
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
#ifndef _WIN32
	mm_segment_t oldfs = get_fs();
#else
	//WDRBD_ERROR("not reached here\n"); //_WIN32
	//BUG(); // => V9은 no_send_page, send_page 두 방식 다 dtt_send_page 로 단일 인터페이스를 사용하여 전송한다. 
#endif
	int len = size;
	int err = -EIO;
#ifdef _WIN32
	// not support
#else
	msg_flags |= MSG_NOSIGNAL;
#endif
	dtt_update_congested(tcp_transport);
#ifndef _WIN32
	set_fs(KERNEL_DS);
#endif
	do {
		int sent;
#ifdef _WIN32
		sent = Send(socket->sk, (size_t)(page)+offset, len, 0, socket->sk_linux_attr->sk_sndtimeo);
#else
		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
#endif
		if (sent <= 0) {
			if (sent == -EAGAIN) {
				if (drbd_stream_send_timed_out(transport, stream))
					break;
				continue;
			}
#ifdef _WIN32_V9
			WDRBD_WARN("%s: size=%d len=%d sent=%d\n", __func__, (int)size, len, sent);
#else
			tr_warn(transport, "%s: size=%d len=%d sent=%d\n",
				__func__, (int)size, len, sent);
#endif
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
#ifndef _WIN32
	set_fs(oldfs);
#endif
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}


static void dtt_cork(struct socket *socket)
{
#ifndef _WIN32 // kernel_setsockopt linux kernel func. V9 포팅 필요. => not support.
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
}

static void dtt_uncork(struct socket *socket)
{
#ifndef _WIN32 // kernel_setsockopt linux kernel func. V9 포팅 필요. => not support.
	int val = 0;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
}

static void dtt_quickack(struct socket *socket)
{
#ifndef _WIN32 // kernel_setsockopt linux kernel func. V9 포팅 필요. => not support.
	int val = 2;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val));
#endif
}

static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
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
#ifndef _WIN32 // not support. SOCK_NOSPACE 옵션 필요한지 다시 검토 요망. _WIN32_CHECK 
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
#ifndef _WIN32 // 필요한지 추후 검토
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

static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m)
{
#ifndef _WIN32 // 필요한지 추후 검토
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

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

static int dtt_add_path(struct drbd_transport *transport, struct drbd_path *path)
{
	if (!list_empty(&transport->paths))
		return -EEXIST;

	list_add(&path->list, &transport->paths);

	return 0;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *existing = dtt_path(transport);

	if (tcp_transport->in_use)
		return -EBUSY;

	if (path && path == existing) {
		list_del_init(&existing->list);
		return 0;
	}

	return -ENOENT;
}

#ifdef _WIN32_V9
int __init dtt_initialize(void)
#else
static int __init dtt_initialize(void)
#endif
{
	return drbd_register_transport_class(&tcp_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtt_cleanup(void)
{
	drbd_unregister_transport_class(&tcp_transport_class);
}

#ifndef _WIN32
module_init(dtt_initialize)
module_exit(dtt_cleanup)
#endif