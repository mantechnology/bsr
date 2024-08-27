#include <net/genetlink.h>

void *f(void)
{
	struct sk_buff *skb = NULL;
	struct genl_info *info = NULL;
	struct genl_family *family = NULL;
	
	return genlmsg_put_reply(skb, info, family, 0, 0);
}
