#ifndef __SEQ_FILE_H__
#define __SEQ_FILE_H__
#include "bsr_windows.h"
struct seq_file
{
	char *buf;
	int size;
	int count;
    void * private;
};

extern int seq_printf(struct seq_file *m, const char *f, ...);

extern int seq_putc(struct seq_file *m, char c);
extern int seq_puts(struct seq_file *m, const char *s);

extern void seq_alloc(struct seq_file *m, int size);
extern void seq_free(struct seq_file *m);
extern bool seq_has_overflowed(struct seq_file *m);

#endif