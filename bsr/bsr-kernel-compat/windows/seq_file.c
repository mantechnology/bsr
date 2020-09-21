#include "bsr_int.h"
#include "seq_file.h"

static void seq_set_overflow(struct seq_file *m)
{
	m->count = m->size;
}

int seq_putc(struct seq_file *m, char c)
{
	int len = 0;
	
	if (m->count < m->size) {
		len = _snprintf(m->buf + m->count, m->size - m->count, "%c", c);
		if (len > 0 && (m->count + len < m->size)) {
			m->count += len;
			return len;
		}
	}
	seq_set_overflow(m);
	return len;
}

int seq_puts(struct seq_file *m, const char *s)
{
	int len = 0;

	if (m->count < m->size) {
		len = _snprintf(m->buf + m->count, m->size - m->count, s);
		if (len > 0 && (m->count + len < m->size)) {
			m->count += len;
			return len;
		}
	}

	seq_set_overflow(m);
	return len;
}


int seq_printf(struct seq_file *m, const char *f, ...)
{
    int len = 0;
    va_list args;

	if (m->count < m->size) {
		va_start(args, f);
		len = _vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		va_end(args);
		if (len > 0 && (m->count + len < m->size)) {
			m->count += len;
			return len;
		}
	}
	
	seq_set_overflow(m);
	return len;
}

void seq_alloc(struct seq_file *m, int size)
{
	m->buf = kmalloc(size, 0, '55SB');
	m->size = size;
	m->count = 0;
}

void seq_free(struct seq_file *m)
{
	if (m->buf) {
		kfree(m->buf);
		m->buf = NULL;
	}
}

bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}