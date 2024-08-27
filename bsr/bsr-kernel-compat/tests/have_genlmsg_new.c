#include <net/genetlink.h>

struct sk_buff * f(void)
{
	return genlmsg_new(123, GFP_KERNEL);
}
