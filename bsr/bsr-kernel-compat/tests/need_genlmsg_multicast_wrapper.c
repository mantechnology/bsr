#include <net/genetlink.h>

int f(void)
{
	struct sk_buff *skb = NULL;
	return genlmsg_multicast(skb, 0, 0);
}
