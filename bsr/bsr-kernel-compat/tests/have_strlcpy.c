#include <linux/string.h>

ssize_t foo(char *dest, char *src, size_t count)
{
	return strlcpy(dest, src, count);
}
