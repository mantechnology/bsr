#include "seq_file.h"

int seq_putc(struct seq_file *m, char c)
{
	int ret;
	ret = _snprintf(m->buf + seq_file_idx, sizeof(m->buf) - seq_file_idx - 1, "%c", c);
	seq_file_idx += ret;
	ASSERT(seq_file_idx < MAX_SEQ_BUF);
	return ret;
}

int seq_puts(struct seq_file *m, const char *s)
{
	int ret;
	ret = _snprintf(m->buf + seq_file_idx, sizeof(m->buf) - seq_file_idx - 1, s);
	seq_file_idx += ret;
	ASSERT(seq_file_idx < MAX_SEQ_BUF);
	return ret;
}


int seq_printf(struct seq_file *m, const char *f, ...)
{
    int ret;
    va_list args;

    va_start(args, f);
	ret = _vsnprintf(m->buf + seq_file_idx, sizeof(m->buf) - seq_file_idx - 1, f, args);
    va_end(args);
    seq_file_idx += ret;
	ASSERT(seq_file_idx < MAX_SEQ_BUF);
    return ret;
}