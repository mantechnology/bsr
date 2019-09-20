#include "./bsr_wingenl.h"
#include "../../../bsr/bsr_int.h"

__inline int nla_put_string(struct sk_buff *msg, int attrtype, const char *str)
{
#ifdef _WIN64
	BUG_ON_INT32_OVER(strlen(str)); 
#endif
    return nla_put(msg, attrtype, (int)(strlen(str) + 1), str);
}

__inline int nla_nest_end(struct sk_buff *msg, struct nlattr *start)
{
	BUG_ON_UINT16_OVER(skb_tail_pointer(msg) - (unsigned char *)start);
	start->nla_len = (u16)(skb_tail_pointer(msg) - (unsigned char *)start);
	return msg->len;
}

__inline int nlmsg_end(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	BUG_ON_UINT32_OVER(skb_tail_pointer(skb) - (unsigned char *)nlh);

	nlh->nlmsg_len = (u32)(skb_tail_pointer(skb) - (unsigned char *)nlh);
	return skb->len;
}