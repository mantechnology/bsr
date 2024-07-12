#include <linux/skbuff.h>
#include <linux/netlink.h>

struct nlmsghdr * f(void)
{
	struct sk_buff *skb = NULL;
	return nlmsg_hdr(skb);
}
