#include <crypto/hash.h>

void foo(void)
{
	struct ahash_request areq;
	struct shash_desc sdesc;
	
	void (*p1)(struct ahash_request *);
	void (*p2)(struct shash_desc *);
 
	p1 = ahash_request_zero;
	p2 = shash_desc_zero;
	
	memset(&areq, 0, sizeof(areq));
	memset(&sdesc, 0, sizeof(sdesc));
	
	p1(&areq);
	p2(&sdesc);
}
