#include <linux/blk_types.h>

// BSR-1113 fix incorrect compat test results
int dummy = REQ_OP_WRITE_ZEROES;