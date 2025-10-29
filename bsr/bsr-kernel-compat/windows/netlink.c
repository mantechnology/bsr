#include "../../../bsr/bsr_int.h"
#include "bsr_windows.h"
#include "wsk_wrapper.h"
#include "bsr_wingenl.h"
#include "idr.h"
#include "../../../bsr/bsr_nla.h"

NPAGED_LOOKASIDE_LIST bsr_workitem_mempool;
NPAGED_LOOKASIDE_LIST netlink_ctx_mempool;
NPAGED_LOOKASIDE_LIST genl_info_mempool;
NPAGED_LOOKASIDE_LIST genl_msg_mempool;

typedef struct _NETLINK_WORK_ITEM {
    WORK_QUEUE_ITEM Item;
    PWSK_SOCKET Socket;
	USHORT		RemotePort;
} NETLINK_WORK_ITEM, *PNETLINK_WORK_ITEM;

typedef struct _NETLINK_CTX {
	PETHREAD		NetlinkEThread;
    PWSK_SOCKET 	Socket;
} NETLINK_CTX, *PNETLINK_CTX;


extern int bsr_tla_parse(struct nlmsghdr *nlh, struct nlattr **attr);

extern int bsr_adm_new_resource(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_del_resource(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_down(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_set_role(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_attach(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_disk_opts(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_detach(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_connect(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_net_opts(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_resize(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_start_ov(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_stop_ov(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_disconnect(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_invalidate(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_pause_sync(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_resume_sync(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_suspend_io(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_resume_io(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_outdate(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_resource_opts(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_node_opts(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_get_status(struct sk_buff *skb, struct genl_info *info);
extern int bsr_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info);
// BSR-1392
extern int bsr_adm_apply_persist_role(struct sk_buff *skb, struct genl_info *info);
// BSR-1552
#ifdef _LIN
extenr int bsr_adm_minor_mount_path(struct sk_buff *skb, struct genl_info *info);
#endif
/* .dumpit */
extern int bsr_adm_send_reply(struct sk_buff *skb, struct genl_info *info);

extern int _bsr_adm_get_status(struct sk_buff *skb, struct genl_info * pinfo);

WORKER_THREAD_ROUTINE NetlinkWorkThread;

// BSR-1192
extern int netlink_work_thread_cnt;
extern void log_for_netlink_cli_recv(const u8 cmd);
extern void log_for_netlink_cli_done(const u8 cmd);
/*
static struct genl_ops bsr_genl_ops[] = {
{ .doit = bsr_adm_new_minor, .flags = 0x01, .cmd = BSR_ADM_NEW_MINOR, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_del_minor, .flags = 0x01, .cmd = BSR_ADM_DEL_MINOR, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_new_resource, .flags = 0x01, .cmd = BSR_ADM_NEW_RESOURCE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_del_resource, .flags = 0x01, .cmd = BSR_ADM_DEL_RESOURCE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_resource_opts, .flags = 0x01, .cmd = BSR_ADM_RESOURCE_OPTS, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_new_peer, .flags = 0x01, .cmd = BSR_ADM_NEW_PEER, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_new_path, .flags = 0x01, .cmd = BSR_ADM_NEW_PATH, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_del_peer, .flags = 0x01, .cmd = BSR_ADM_DEL_PEER, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_del_path, .flags = 0x01, .cmd = BSR_ADM_DEL_PATH, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_connect, .flags = 0x01, .cmd = BSR_ADM_CONNECT, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_net_opts, .flags = 0x01, .cmd = BSR_ADM_CHG_NET_OPTS, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_disconnect, .flags = 0x01, .cmd = BSR_ADM_DISCONNECT, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_attach, .flags = 0x01, .cmd = BSR_ADM_ATTACH, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_disk_opts, .flags = 0x01, .cmd = BSR_ADM_CHG_DISK_OPTS, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_resize, .flags = 0x01, .cmd = BSR_ADM_RESIZE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_set_role, .flags = 0x01, .cmd = BSR_ADM_PRIMARY, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_set_role, .flags = 0x01, .cmd = BSR_ADM_SECONDARY, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_new_c_uuid, .flags = 0x01, .cmd = BSR_ADM_NEW_C_UUID, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_start_ov, .flags = 0x01, .cmd = BSR_ADM_START_OV, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_detach, .flags = 0x01, .cmd = BSR_ADM_DETACH, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_invalidate, .flags = 0x01, .cmd = BSR_ADM_INVALIDATE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_invalidate_peer, .flags = 0x01, .cmd = BSR_ADM_INVAL_PEER, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_pause_sync, .flags = 0x01, .cmd = BSR_ADM_PAUSE_SYNC, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_resume_sync, .flags = 0x01, .cmd = BSR_ADM_RESUME_SYNC, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_suspend_io, .flags = 0x01, .cmd = BSR_ADM_SUSPEND_IO, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_resume_io, .flags = 0x01, .cmd = BSR_ADM_RESUME_IO, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_outdate, .flags = 0x01, .cmd = BSR_ADM_OUTDATE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_get_timeout_type, .flags = 0x01, .cmd = BSR_ADM_GET_TIMEOUT_TYPE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_down, .flags = 0x01, .cmd = BSR_ADM_DOWN, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_apply_persist_role, .flags = 0x01, .cmd = BSR_ADM_APPLY_PERSIST_ROLE, .policy = bsr_tla_nl_policy, },
{ .dumpit = bsr_adm_dump_resources, .cmd = BSR_ADM_GET_RESOURCES, .policy = bsr_tla_nl_policy, },
{ .dumpit = bsr_adm_dump_devices, .done = bsr_adm_dump_devices_done, .cmd = BSR_ADM_GET_DEVICES, .policy = bsr_tla_nl_policy, },
{ .dumpit = bsr_adm_dump_connections, .done = bsr_adm_dump_connections_done, .cmd = BSR_ADM_GET_CONNECTIONS, .policy = bsr_tla_nl_policy, },
{ .dumpit = bsr_adm_dump_peer_devices, .done = bsr_adm_dump_peer_devices_done, .cmd = BSR_ADM_GET_PEER_DEVICES, .policy = bsr_tla_nl_policy, },
{ .dumpit = bsr_adm_get_initial_state, .cmd = BSR_ADM_GET_INITIAL_STATE, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_forget_peer, .flags = 0x01, .cmd = BSR_ADM_FORGET_PEER, .policy = bsr_tla_nl_policy, },
{ .doit = bsr_adm_peer_device_opts, .flags = 0x01, .cmd = BSR_ADM_CHG_PEER_DEVICE_OPTS, .policy = bsr_tla_nl_policy, },
};
*/

/*
static struct genl_family bsr_genl_family  = {
	.id = 0,
	.name = "bsr",
	.version = 2,

	.hdrsize = (((sizeof(struct bsr_genlmsghdr)) + 4 - 1) & ~(4 - 1)),
	.maxattr = (sizeof(bsr_tla_nl_policy) / sizeof((bsr_tla_nl_policy)[0]))-1,
};
*/

#define cli_info(_minor, _fmt, ...)

// globals

extern struct mutex g_genl_mutex;
// DW-1998
extern u8 g_genl_run_cmd;
extern struct mutex g_genl_run_cmd_mutex;

static ERESOURCE    genl_multi_socket_res_lock;

PTR_ENTRY gSocketList =
{
    .slink = { .Next = NULL },
    .ptr = NULL,
};

/**
* @brief: Push socket pointers for multicast to list.
*/
static bool push_msocket_entry(void * ptr)
{
    if (!ptr) {
        return FALSE;
    }

    PPTR_ENTRY entry = (PPTR_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(PTR_ENTRY), '14SB');
	if (!entry) {
		return FALSE;
	}
    entry->ptr = ptr;

    MvfAcquireResourceExclusive(&genl_multi_socket_res_lock);

    PushEntryList(&gSocketList.slink, &(entry->slink));

    MvfReleaseResource(&genl_multi_socket_res_lock);

	return TRUE;
}

/**
* @brief: Pop the argument pointer from the socket pointer list
*/
static void pop_msocket_entry(void * ptr)
{
    PSINGLE_LIST_ENTRY iter = &gSocketList.slink;

    MvfAcquireResourceExclusive(&genl_multi_socket_res_lock);

    while (iter) {
        PPTR_ENTRY socket_entry = (PPTR_ENTRY)CONTAINING_RECORD(iter->Next, PTR_ENTRY, slink);

        if (socket_entry && socket_entry->ptr == ptr) {
            iter->Next = PopEntryList(iter->Next);

            ExFreePool(socket_entry);
			socket_entry = NULL;
            break;
        }
        iter = iter->Next;
    }

    MvfReleaseResource(&genl_multi_socket_res_lock);

    return;
}

/**
* @brief: Send all to socket in list, using global socket list variable for multicast (gSocketList)
*/
int bsr_genl_multicast_events(struct sk_buff * skb, const struct sib_info *sib)
{
	UNREFERENCED_PARAMETER(sib);

    int ret = 0;

    if (!skb) {
        return EINVAL;
    }

    PSINGLE_LIST_ENTRY iter = &gSocketList.slink;

    MvfAcquireResourceShared(&genl_multi_socket_res_lock);

    while (iter) {
        PPTR_ENTRY socket_entry = (PPTR_ENTRY)CONTAINING_RECORD(iter->Next, PTR_ENTRY, slink);

        if (socket_entry) {
			int sent = SendLocal(socket_entry->ptr, skb->data, skb->len, 0, (BSR_TIMEOUT_DEF*100));
            if (sent != skb->len) {
                bsr_err(1, BSR_LC_NETLINK, NO_OBJECT,"Failed to send event(notification) %d size, socket(0x%x)",  skb->len, socket_entry->ptr);
            }
        }
        iter = iter->Next;
    }

    MvfReleaseResource(&genl_multi_socket_res_lock);

    nlmsg_free(skb);

    return ret;
}

NTSTATUS reply_error(int type, int flags, int error, struct genl_info * pinfo)
{
    struct sk_buff * reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

    if (reply_skb) {
		struct nlmsghdr * nlh = nlmsg_put(reply_skb, pinfo->nlhdr->nlmsg_pid,
			pinfo->nlhdr->nlmsg_seq, type, GENL_HDRLEN, flags);
        if (nlh) {
            struct nlmsgerr * err = nlmsg_data(nlh);
            err->error = -error;
            err->msg.nlmsg_len = 0;

            bsr_adm_send_reply(reply_skb, pinfo);
        }
        nlmsg_free(reply_skb);
    } else {
        return STATUS_NO_MEMORY;
    }
              
    return STATUS_SUCCESS;
}

static int _genl_dump(struct genl_ops * pops, struct sk_buff * skb, struct netlink_callback * cb, struct genl_info * info)
{
    struct nlmsghdr * nlh = NULL;
    int err = pops->dumpit(skb, cb);

    if (0 == err) {
		nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_MULTI);
    } else if (err < 0) {
		nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_ACK);
        // -ENODEV : occured by first bsradm adjust. response?
			bsr_warn(2, BSR_LC_NETLINK, NO_OBJECT, "Failed to get the state of all objects. err(%d)", err);
    }

    if (nlh) {
        struct genlmsghdr * hdr = nlmsg_data(nlh);
        hdr->cmd = 0;
        hdr->version = 0;
        hdr->reserved = 0;
    }

	if(bsr_adm_send_reply(skb, info) < 0) {
		err = -1;
	}

    bsr_debug(87, BSR_LC_GENL, NO_OBJECT,"send_reply(%d) seq(%d)", err, cb->nlh->nlmsg_seq);

    return err;
}

int genlmsg_unicast(struct sk_buff *skb, struct genl_info *info)
{
    int sent;

    if (info->pSock->sk == NULL) {
        return -1; // return non-zero!
    }
	
	if ((sent = SendLocal(info->pSock, skb->data, skb->len, 0, (BSR_TIMEOUT_DEF*100))) == (skb->len)) {
        return 0; // success
    } else {
		bsr_warn(3, BSR_LC_NETLINK, NO_OBJECT, "Failed to local send. status(0x%x) socket(%p) data(%p) size=%d", sent, info->pSock->sk, skb->data, skb->len);
        return -2; // return non-zero!
    }
}

// DW-1229 using global attr may cause BSOD when we receive plural netlink requests. use local attr.
struct genl_info * genl_info_new(struct nlmsghdr * nlh, struct socket* sock, struct nlattr **attrs)
{
    struct genl_info * pinfo = ExAllocateFromNPagedLookasideList(&genl_info_mempool);

    if (!pinfo) {
		bsr_err(65, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory for genl inforamtion",
            sizeof(struct genl_info));
        return NULL;
    }

    RtlZeroMemory(pinfo, sizeof(struct genl_info));

    pinfo->seq = nlh->nlmsg_seq;
    pinfo->nlhdr = nlh;
    pinfo->genlhdr = nlmsg_data(nlh);
    pinfo->userhdr = genlmsg_data(nlmsg_data(nlh));
    pinfo->attrs = attrs;
    pinfo->snd_seq = nlh->nlmsg_seq;
    pinfo->snd_portid = nlh->nlmsg_pid;
	pinfo->pSock = sock;
	
    return pinfo;
}

void genl_info_free(struct genl_info* pInfo) 
{
	if(pInfo) {
		ExFreeToNPagedLookasideList(&genl_info_mempool, pInfo);
	}
}

__inline
void _genlmsg_init(struct sk_buff * pmsg, size_t size)
{
    RtlZeroMemory(pmsg, size);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(size - sizeof(*pmsg));
#endif
    pmsg->tail = 0;
    pmsg->end = (unsigned int)(size - sizeof(*pmsg));
}

struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
	UNREFERENCED_PARAMETER(flags);

    struct sk_buff *skb;

    if (NLMSG_GOODSIZE == payload) {
        payload = NLMSG_GOODSIZE - sizeof(*skb);
        skb = ExAllocateFromNPagedLookasideList(&genl_msg_mempool);
	}
	else {
#ifdef _WIN64
		BUG_ON_INT32_OVER(sizeof(*skb) + payload);
#endif
        skb = kmalloc((int)(sizeof(*skb) + payload), GFP_KERNEL, '67SB');
    }

    if (!skb)
        return NULL;

	// DW-1501 fix failure to alloc genl_msg_mempool
	RtlZeroMemory(skb, NLMSG_GOODSIZE);
    _genlmsg_init(skb, sizeof(*skb) + payload);

    return skb;
}

/**
* nlmsg_free - free a netlink message
* @skb: socket buffer of netlink message
*/
__inline void nlmsg_free(struct sk_buff *skb)
{
    ExFreeToNPagedLookasideList(&genl_msg_mempool, skb);
}


void
InitWskNetlink(void * pctx)
{
	UNREFERENCED_PARAMETER(pctx);

    NTSTATUS    status;
    PWSK_SOCKET netlink_socket = NULL;
    SOCKADDR_IN LocalAddress = {0};

    // Init WSK
    status = WskGetNPI();
    if (!NT_SUCCESS(status)) {
		bsr_err(5, BSR_LC_NETLINK, NO_OBJECT, "Failed to netlink socket initialization due to failure to init wsk. status(0x%x)", status);
        return;
    }

    // Init WSK Event Callback
    status = InitWskEvent();
    if (!NT_SUCCESS(status)) {
        return;
    }

	bsr_info(6, BSR_LC_NETLINK, NO_OBJECT, "Start server netlink");
	
	gpNetlinkServerSocket = kzalloc(sizeof(struct socket), 0, '32SB');
	if(!gpNetlinkServerSocket) {
		bsr_err(66, BSR_LC_MEMORY, NO_OBJECT, "Failed to netlink socket initialization due to failure to allocate %d size memory for socket", sizeof(struct socket));
		return;
	}
	
    netlink_socket = CreateEventSocket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP,
        WSK_FLAG_LISTEN_SOCKET);

    if (!netlink_socket) {
		bsr_err(8, BSR_LC_NETLINK, NO_OBJECT, "Failed to netlink socket initialization due to failure to create event socket");
        goto end;
    }

	gpNetlinkServerSocket->sk = netlink_socket;
	
    LocalAddress.sin_family = AF_INET;
    LocalAddress.sin_addr.s_addr = INADDR_ANY;
    LocalAddress.sin_port = HTONS(g_netlink_tcp_port);

    status = Bind(gpNetlinkServerSocket, (PSOCKADDR)&LocalAddress);
    if (!NT_SUCCESS(status)) {
		bsr_err(9, BSR_LC_NETLINK, NO_OBJECT, "Failed to netlink socket initialization due to failure to bind. status(0x%x)", status);
        CloseSocket(gpNetlinkServerSocket);
    }
    
	ExInitializeNPagedLookasideList(&bsr_workitem_mempool, NULL, NULL,
        0, sizeof(struct _NETLINK_WORK_ITEM), '17SB', 0);
    ExInitializeNPagedLookasideList(&netlink_ctx_mempool, NULL, NULL,
        0, sizeof(struct _NETLINK_CTX), '27SB', 0);
    ExInitializeNPagedLookasideList(&genl_info_mempool, NULL, NULL,
        0, sizeof(struct genl_info), '37SB', 0);
    ExInitializeNPagedLookasideList(&genl_msg_mempool, NULL, NULL,
        0, NLMSG_GOODSIZE, '47SB', 0);

    ExInitializeResourceLite(&genl_multi_socket_res_lock);

end:
    ReleaseProviderNPI();

    PsTerminateSystemThread(status);
}




NTSTATUS
ReleaseWskNetlink()
{
	ExDeleteNPagedLookasideList(&bsr_workitem_mempool);
    ExDeleteNPagedLookasideList(&netlink_ctx_mempool);
    ExDeleteNPagedLookasideList(&genl_info_mempool);
    ExDeleteNPagedLookasideList(&genl_msg_mempool);

    ExDeleteResourceLite(&genl_multi_socket_res_lock);
    
    return CloseEventSocket();
}


#if 0
static int w_connect(struct bsr_work *w, int cancel)
{
	struct connect_work* pcon_work = container_of(w, struct connect_work, w);
	struct bsr_resource* resource = pcon_work->resource;
	LARGE_INTEGER		timeout;
	NTSTATUS			status;

	timeout.QuadPart = (-1 * 10000 * 6000);   // wait 6000 ms relative

	pcon_work->ops.doit(NULL, &pcon_work->info);
	bsr_info(10, BSR_LC_NETLINK, NO_OBJECT,"w_connect:");

	status = KeWaitForSingleObject(&resource->workerdone, Executive, KernelMode, FALSE, &timeout);
	if (status == STATUS_TIMEOUT) {
		bsr_info(11, BSR_LC_NETLINK, NO_OBJECT,"w_connect:KeWaitForSingleObject timeout");
	}

	kfree(pcon_work);

	return 0;
}
#endif

static int _genl_ops(struct genl_ops * pops, struct genl_info * pinfo)
{
	if (pops->doit) {
        return pops->doit(NULL, pinfo);
    }

    if (pinfo->nlhdr->nlmsg_flags && NLM_F_DUMP) {
        struct sk_buff * skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

        if (skb) {
            struct netlink_callback ncb = {
                .skb = skb,
                .nlh = pinfo->nlhdr,
                .args = { 0, }
            };
            
            int ret = _genl_dump(pops, skb, &ncb, pinfo);
			int cnt = 0;
            while (ret > 0) {
                RtlZeroMemory(skb, NLMSG_GOODSIZE);
                _genlmsg_init(skb, NLMSG_GOODSIZE);

                ret = _genl_dump(pops, skb, &ncb, pinfo);
				if(cnt++ > 512) {
					bsr_err(12, BSR_LC_NETLINK, NO_OBJECT, "Failed to get object information within the specified number of times. count(%d)", cnt);
					break;
				}
            }

            if (pops->done) {
                pops->done(&ncb);
            }

            nlmsg_free(skb);
        }

        return 0;
    }

	return 0;
}

VOID
NetlinkWorkThread(PVOID context)
{
    ASSERT(context);

	PWSK_SOCKET socket = ((PNETLINK_WORK_ITEM)context)->Socket;
	struct socket* pSock = NULL;
    LONG readcount, minor = 0;
    int err = 0, errcnt = 0;
    struct genl_info * pinfo = NULL;
	void * psock_buf = NULL;

	// set thread priority
	KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);

	bsr_debug(27, BSR_LC_NETLINK, NO_OBJECT,"NetlinkWorkThread:%p begin...accept socket:%p remote port:%d",KeGetCurrentThread(),socket, HTON_SHORT(((PNETLINK_WORK_ITEM)context)->RemotePort));
    
    netlink_work_thread_cnt++;

	pSock = kzalloc(sizeof(struct socket), 0, 'F2SB'); 
	if(!pSock) {
		bsr_err(67, BSR_LC_MEMORY, NO_OBJECT, "Netlink thread clean up due to failure to allocate %d size memory for socket", sizeof(struct socket));
        goto cleanup;
	}

	pSock->sk = socket;
	pSock->sk_state = WSK_ESTABLISHED;
	
    psock_buf = ExAllocateFromNPagedLookasideList(&genl_msg_mempool);
    if (!psock_buf) {
		bsr_err(68, BSR_LC_MEMORY, NO_OBJECT, "Netlink thread clean up due to failure to allocate %d size memory for socket buffer", NLMSG_GOODSIZE);
        goto cleanup;
    }

    while (true) {
        readcount = Receive(pSock, psock_buf, NLMSG_GOODSIZE, 0, 0, NULL);

        if (readcount == 0) {
			bsr_debug(28, BSR_LC_NETLINK, NO_OBJECT, "Receive done...");
            goto cleanup;
        } else if(readcount < 0) {
            bsr_err(15, BSR_LC_NETLINK, NO_OBJECT,"Netlink thread clean up due to failure to receive. status(0x%x)", readcount);
            goto cleanup;
        }
		
		struct nlmsghdr *nlh = (struct nlmsghdr *)psock_buf;
		
		
		// bsrsetup events2
        if (strstr(psock_buf, BSR_EVENT_SOCKET_STRING)) {
			bsr_debug(29, BSR_LC_NETLINK, NO_OBJECT, "BSR_EVENT_SOCKET_STRING received. socket(0x%p)", socket);
			if (!push_msocket_entry(pSock)) {
				goto cleanup;
			}

			if (strlen(BSR_EVENT_SOCKET_STRING) < (size_t)readcount) {
				nlh = (struct nlmsghdr *)((char*)psock_buf + strlen(BSR_EVENT_SOCKET_STRING));
				readcount -= (LONG)strlen(BSR_EVENT_SOCKET_STRING);
			} else {
				continue;
			}
        }

		// DW-1701 Performs a sanity check on the netlink command, enhancing security.
		// verify nlh header field
		if( ((unsigned int)readcount != nlh->nlmsg_len) 
			|| (nlh->nlmsg_type < NLMSG_MIN_TYPE) 
			|| (nlh->nlmsg_pid != 0x5744) ) {
			bsr_warn(25, BSR_LC_NETLINK, NO_OBJECT, "Unrecognizable netlink command arrives and doesn't process...");
			bsr_debug(30, BSR_LC_NETLINK, NO_OBJECT, "rx(%d), len(%d), flags(0x%x), type(0x%x), seq(%d), magic(%x)",
            	readcount, nlh->nlmsg_len, nlh->nlmsg_flags, nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid);
			goto cleanup;
		}
		
        if (pinfo)
            ExFreeToNPagedLookasideList(&genl_info_mempool, pinfo);
		
		// DW-1229 using global attr may cause BSOD when we receive plural netlink requests. use local attr.
		struct nlattr *local_attrs[128];

		pinfo = genl_info_new(nlh, pSock, local_attrs);
        if (!pinfo) {
			bsr_err(16, BSR_LC_NETLINK, NO_OBJECT, "Netlink thread clean up due to failure to allocate %d size memory for genl informaiton", sizeof(struct genl_info));
            goto cleanup;
        }

        bsr_tla_parse(nlh, local_attrs);
        if (!nlmsg_ok(nlh, readcount)) {
			bsr_err(17, BSR_LC_NETLINK, NO_OBJECT, "Netlink thread clean up due to not match message. read count(%d)", readcount);
            goto cleanup;
        }

		bsr_debug(31, BSR_LC_NETLINK, NO_OBJECT, "rx readcount(%d), headerlen(%d), cmd(%d), flags(0x%x), type(0x%x), seq(%d), magic(%x)",
            readcount, nlh->nlmsg_len, pinfo->genlhdr->cmd, nlh->nlmsg_flags, nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid);

        // check whether resource suspended
        struct bsr_genlmsghdr * gmh = pinfo->userhdr;
        if (gmh) {
            minor = gmh->minor;
            struct bsr_conf * mdev = minor_to_device(minor);
            if (mdev && bsr_suspended(mdev)) {
                reply_error(NLMSG_ERROR, NLM_F_MULTI, EIO, pinfo);
                bsr_warn(26, BSR_LC_NETLINK, NO_OBJECT, "Resource suspended, minor(%d)", gmh->minor);
                goto cleanup;
            }
        }

        u8 cmd = pinfo->genlhdr->cmd;
        struct genl_ops * pops = get_bsr_genl_ops(cmd);

        if (pops) {
			NTSTATUS status = STATUS_UNSUCCESSFUL;
            bool locked = true;

			// DW-1432 Except status log
			// DW-1699 fixup netlink log level. the get series commands are adjusted to log at the trace log level.
			cli_info(gmh->minor, "Command (%s:%u)\n", pops->str, cmd);
			
			// BSR-1192
			log_for_netlink_cli_recv(cmd);
            // BSR-1550 
            if((BSR_ADM_GET_RESOURCES <= cmd) && (cmd <= BSR_ADM_GET_PEER_DEVICES)) {
                if(BSR_ADM_PRIMARY == g_genl_run_cmd || BSR_ADM_SECONDARY == g_genl_run_cmd || BSR_ADM_APPLY_PERSIST_ROLE == g_genl_run_cmd|| BSR_ADM_DOWN == g_genl_run_cmd) {
                    status = STATUS_SUCCESS;
                    locked = false;
                } else {
                    status = mutex_lock_timeout(&g_genl_mutex, CMD_TIMEOUT_SHORT_DEF * 1000);
                }
            } else {
                status = mutex_lock_timeout(&g_genl_mutex, CMD_TIMEOUT_SHORT_DEF * 1000);
            }
            // DW-1998 set STATUS_SUCNESS under the following conditions even if the mutex is not obtained.
            mutex_lock(&g_genl_run_cmd_mutex);

			// DW-1998 add an exception condition for the mutex when running BSR_ADM_GET_INITIAL_STATE
			if (status != STATUS_SUCCESS &&
				BSR_ADM_GET_INITIAL_STATE == cmd &&
				BSR_ADM_ATTACH == g_genl_run_cmd) {
				status = STATUS_SUCCESS;
				locked = false;
			}

			if (STATUS_SUCCESS == status) {
                // BSR-1550
                if(cmd != BSR_ADM_GET_INITIAL_STATE && 
                    !((BSR_ADM_GET_RESOURCES <= cmd) && (cmd <= BSR_ADM_GET_PEER_DEVICES)))
                    g_genl_run_cmd = cmd;
				// DW-1998 if locked is true, unlock before call _genl_ops().
				if (locked)
					mutex_unlock(&g_genl_run_cmd_mutex);
				err = _genl_ops(pops, pinfo);

				// DW-1998
				if (locked)
					mutex_unlock(&g_genl_mutex);
				else
					mutex_unlock(&g_genl_run_cmd_mutex);

				if (err) {
					bsr_err(19, BSR_LC_NETLINK, NO_OBJECT, "command failed while operating. cmd(%u), error(%d)", cmd, err);
					errcnt++;
				}
				// BSR-1192
				log_for_netlink_cli_done(cmd);
			} else {
                mutex_unlock(&g_genl_run_cmd_mutex);
				bsr_info(21, BSR_LC_NETLINK, NO_OBJECT, "Cannot execute command %s:%u because mutex is not returned and cannot be acquired. status(0x%x)", pops->str, cmd, status);
			}

        } else {
			bsr_info(22, BSR_LC_NETLINK, NO_OBJECT, "Command %d is a non-existent command.", cmd);
        }
    }

cleanup:
	if (pSock) {
		pop_msocket_entry(pSock);
		Disconnect(pSock);
		CloseSocket(pSock);
	}

    netlink_work_thread_cnt--;
    
	//ObDereferenceObject(pNetlinkCtx->NetlinkEThread);

	ExFreeToNPagedLookasideList(&bsr_workitem_mempool, context);

    genl_info_free(pinfo);
	
    if (psock_buf)
        ExFreeToNPagedLookasideList(&genl_msg_mempool, psock_buf);

	if(pSock)
		kfree(pSock);
	
    if (errcnt) {
		bsr_err(23, BSR_LC_NETLINK, NO_OBJECT, "Netlink thread terminate due to error occurrence thread:%p, count(%d)", KeGetCurrentThread(), errcnt);
    } else {
		bsr_debug(34, BSR_LC_NETLINK, NO_OBJECT, "NetlinkWorkThread:%p done...", KeGetCurrentThread());
    }
}
// Listening socket callback which is invoked whenever a new connection arrives.
NTSTATUS
WSKAPI
NetlinkAcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
PVOID *AcceptSocketContext,
CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
	UNREFERENCED_PARAMETER(AcceptSocketDispatch);
	UNREFERENCED_PARAMETER(AcceptSocketContext);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(SocketContext);

    if (AcceptSocket == NULL) {
        // If WSK provider makes a WskAcceptEvent callback with NULL 
        // AcceptSocket, this means that the listening socket is no longer
        // functional. The WSK client may handle this situation by trying
        // to create a new listening socket or by restarting the driver, etc.
        // In this sample, we will attempt to close the existing listening
        // socket and create a new one. Note that the AcceptEvent
        // callback is guaranteed to be invoked with a NULL AcceptSocket
        // by the WSK subsystem only *once*. So, we can safely use the same
        // operation context that was originally used for enqueueing the first
        // WskSampleStartListen operation on the listening socket. The
        // WskSampleStartListen operation will close the existing listening
        // socket and create a new one.
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    SOCKADDR_IN * pRemote = (SOCKADDR_IN *)RemoteAddress;
    SOCKADDR_IN * pLocal = (SOCKADDR_IN *)LocalAddress;

	bsr_debug(35, BSR_LC_NETLINK, NO_OBJECT, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u connected",
					        pRemote->sin_addr.S_un.S_un_b.s_b1,
					        pRemote->sin_addr.S_un.S_un_b.s_b2,
					        pRemote->sin_addr.S_un.S_un_b.s_b3,
					        pRemote->sin_addr.S_un.S_un_b.s_b4,
					        HTON_SHORT(pRemote->sin_port),
					        pLocal->sin_addr.S_un.S_un_b.s_b1,
					        pLocal->sin_addr.S_un.S_un_b.s_b2,
					        pLocal->sin_addr.S_un.S_un_b.s_b3,
					        pLocal->sin_addr.S_un.S_un_b.s_b4,
					        HTON_SHORT(pLocal->sin_port));

	// DW-1701 Only allow to local loopback netlink command
	if(pRemote->sin_addr.S_un.S_un_b.s_b1 != 0x7f) {
		bsr_debug(36, BSR_LC_NETLINK, NO_OBJECT, "External connection attempt was made and blocked.");
		return STATUS_REQUEST_NOT_ACCEPTED;
	}

	
    PNETLINK_WORK_ITEM netlinkWorkItem = ExAllocateFromNPagedLookasideList(&bsr_workitem_mempool);

    if (!netlinkWorkItem) {
		bsr_err(69, BSR_LC_MEMORY, NO_OBJECT, "Failed to netlink accept due to failure to allocate %d size memory for work item", sizeof(NETLINK_WORK_ITEM));
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    netlinkWorkItem->Socket = AcceptSocket;
    netlinkWorkItem->RemotePort = pRemote->sin_port;
	
	ExInitializeWorkItem(&netlinkWorkItem->Item,
		NetlinkWorkThread,
		netlinkWorkItem);

// DW-1587 
// Code Analysis indicates this is obsolete, but it is ok.
// If the work item is not associated with a device object or device stack, 
// there is no problem in use, and it is still in use within the Windows file system driver.
#pragma warning (disable: 28159)
	ExQueueWorkItem(&netlinkWorkItem->Item, DelayedWorkQueue);
#pragma warning (default: 28159)
    return STATUS_SUCCESS;
}

