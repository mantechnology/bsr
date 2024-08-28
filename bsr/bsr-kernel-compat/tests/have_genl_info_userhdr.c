#include <net/genetlink.h>

void *foo(const struct genl_info *info) 
{
	return genl_info_userhdr(info);
}