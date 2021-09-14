/*
   bsr_proc.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

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
#include "bsr_int.h"
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
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/bsr_transport.h"

// windows replaced with MVF ioctl
#ifdef _LIN
struct proc_dir_entry *bsr_proc;
#endif

// DW-826
int bsr_seq_show(struct seq_file *seq, void *v)
{
	UNREFERENCED_PARAMETER(v);

	seq_printf(seq, "BSR:%s\n(api:%d/proto:%d-%d)\n",
		bsr_buildtag(), GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX);

	print_kref_debug_info(seq);
	bsr_print_transports_loaded(seq);

	return 0;
}
