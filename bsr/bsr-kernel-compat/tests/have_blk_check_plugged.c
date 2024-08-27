#include <linux/blkdev.h>

struct my_plug_cb {
	struct blk_plug_cb cb;
	int bar;
};


static void unplug_fn(struct blk_plug_cb *cb, bool from_schedule)
{
}

struct blk_plug_cb * foo(void)
{
	return blk_check_plugged(unplug_fn, NULL, sizeof(struct my_plug_cb));
}
