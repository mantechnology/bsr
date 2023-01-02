// BSR-1006 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
#include <linux/genhd.h>

void foo(struct gendisk *disk)
{
	revalidate_disk(disk, false);
}
