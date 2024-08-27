#include <linux/netlink.h>

int main(void)
{
	struct sk_buff *skb = NULL;

	return NETLINK_CB(skb).portid;
}
