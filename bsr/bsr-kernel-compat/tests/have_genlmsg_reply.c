#include <net/genetlink.h>

int f(void)
{
	struct sk_buff *skb = NULL;
	struct genl_info *info = NULL;
	return genlmsg_reply(skb, info);
}
