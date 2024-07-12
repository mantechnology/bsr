#include <crypto/hash.h>

int foo(void)
{
	SHASH_DESC_ON_STACK(desc, NULL);
	
	if(desc)
		return 1;
	return 0;
}
