/*
   bsr_proc.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <dev3@mantech.co.kr>.

   bsr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   bsr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with bsr; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */
#ifdef _WIN
#include "./bsr-kernel-compat/windows/seq_file.h"
#else // _LIN
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif
#include "bsr_int.h"
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/bsr_transport.h"

// windows replaced with MVF ioctl
#ifdef _LIN
static int bsr_proc_open(struct inode *inode, struct file *file);
static int bsr_proc_release(struct inode *inode, struct file *file);

struct proc_dir_entry *bsr_proc;
const struct file_operations bsr_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= bsr_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= bsr_proc_release,
};
#endif

// DW-826
int bsr_seq_show(struct seq_file *seq, void *v)
{
	UNREFERENCED_PARAMETER(v);

	seq_printf(seq, "BSR: " REL_VERSION " (api:%d/proto:%d-%d)\n%s\n",
		GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX, bsr_buildtag());
	print_kref_debug_info(seq);
	bsr_print_transports_loaded(seq);

	return 0;
}

#ifdef _LIN
static int bsr_proc_open(struct inode *inode, struct file *file)
{
	int err;

	if (try_module_get(THIS_MODULE)) {
		err = single_open(file, bsr_seq_show, NULL);
		if (err)
			module_put(THIS_MODULE);
		return err;
	}
	return -ENODEV;
}

static int bsr_proc_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return single_release(inode, file);
}
#endif
