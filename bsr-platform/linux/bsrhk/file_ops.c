#include <linux/namei.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include "bsr_int.h"
#include "../bsr-headers/linux/bsr_ioctl.h"


// BSR-577
static int bsr_set_minlog_lv(LOGGING_MIN_LV __user * args)
{
	LOGGING_MIN_LV loggingMinLv;
	int previous_lv_min = 0;
	int err;

	err = copy_from_user(&loggingMinLv, args, sizeof (LOGGING_MIN_LV));
	
	if (err) {
		bsr_err(NO_OBJECT, "LOGGING_MIN_LV copy from user failed.\n");
		return -1;
	}

	if (loggingMinLv.nType == LOGGING_TYPE_SYSLOG) {
		previous_lv_min = atomic_read(&g_eventlog_lv_min);
		atomic_set(&g_eventlog_lv_min, loggingMinLv.nErrLvMin);
	}
	else if (loggingMinLv.nType == LOGGING_TYPE_DBGLOG) {
		previous_lv_min = atomic_read(&g_dbglog_lv_min);
		atomic_set(&g_dbglog_lv_min, loggingMinLv.nErrLvMin);
	}
	else if (loggingMinLv.nType == LOGGING_TYPE_FEATURELOG) {
		previous_lv_min = atomic_read(&g_featurelog_flag);
		atomic_set(&g_featurelog_flag, loggingMinLv.nErrLvMin);
	}
	else {
		bsr_warn(NO_OBJECT,"invalidate logging type(%d)\n", loggingMinLv.nType);
	}
	
	// DW-2008
	bsr_info(NO_OBJECT,"set minimum log level, type : %s(%d), minumum level : %s(%d) => %s(%d)\n", 
				g_log_type_str[loggingMinLv.nType], loggingMinLv.nType, 
				// DW-2041
				((loggingMinLv.nType == LOGGING_TYPE_FEATURELOG) ? "" : g_default_lv_str[previous_lv_min]), previous_lv_min, 
				((loggingMinLv.nType == LOGGING_TYPE_FEATURELOG) ? "" : g_default_lv_str[loggingMinLv.nErrLvMin]), loggingMinLv.nErrLvMin
				);
	return Get_log_lv();
}

static int bsr_get_log(BSR_LOG __user *bsr_log) 
{
	int err;
	
	err = copy_to_user(&bsr_log->totalcnt, &gLogBuf.h.total_count, (unsigned long) sizeof(gLogBuf.h.total_count));

	if (err) {
		bsr_warn(NO_OBJECT, "gTotalLogCnt copy to user failed.\n");
		return err;
	}
	err = copy_to_user(&bsr_log->LogBuf, &gLogBuf.b, MAX_BSRLOG_BUF*LOGBUF_MAXCNT);
	if (err) {
		bsr_warn(NO_OBJECT, "gLogBuf copy to user failed.\n");
	}

	return err;
}

// BSR-597
static int bsr_set_log_max_count(unsigned int __user * args)
{
	unsigned int log_file_max_count = LOG_FILE_COUNT_DEFAULT;
	int err;

	err = copy_from_user(&log_file_max_count, args, sizeof(unsigned int));

	if (err) {
		bsr_err(NO_OBJECT, "LOGGING_MIN_LV copy from user failed.\n");
		return err;
	}

	bsr_info(NO_OBJECT, "set log file max count %lu => %lu\n", atomic_read(&g_log_file_max_count), log_file_max_count);
	atomic_set(&g_log_file_max_count, log_file_max_count);

	return 0;
}

// BSR-626
static int bsr_set_handler_use(HANDLER_INFO __user *args)
{
	HANDLER_INFO h_info;
	int err;

	err = copy_from_user(&h_info, args, sizeof(HANDLER_INFO));
	if (err) {
		bsr_err(NO_OBJECT, "HANDLER_INFO copy from user failed.\n");
		return -1;
	}
	
	bsr_info(NO_OBJECT, "set handler_use %d => %d\n", g_handler_use, h_info.use);
	g_handler_use = h_info.use;

	return 0;
}

long bsr_control_ioctl(struct file *filp, unsigned int cmd, unsigned long param)
{
	int err = 0;
	
	if ( _IOC_TYPE( cmd ) != BSR_IOCTL_MAGIC ) 
		return -EINVAL;

	switch (cmd) {
	case IOCTL_MVOL_SET_LOGLV_MIN:
	{
		err = bsr_set_minlog_lv((LOGGING_MIN_LV __user *)param);
		break;
	}
	case IOCTL_MVOL_GET_BSR_LOG:
	{
		err = bsr_get_log((BSR_LOG __user *)param);
		break;
	}
	case IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT:
	{
		err = bsr_set_log_max_count((unsigned int __user *)param);
		break;
	}
	case IOCTL_MVOL_SET_HANDLER_USE:
	{
		err = bsr_set_handler_use((HANDLER_INFO __user *)param);
		break;
	}
	default :
		break;
	}
	return err;
}

// BSR-597
// based on linux/fs/namei.c - do_renameat2()
int bsr_file_rename(const char *oldname, const char *newname)
{
	struct dentry *old_dir, *new_dir;
	struct dentry *old_dentry, *new_dentry;
	struct dentry *trap;
	struct path old_path, new_path;
	int err = 0;

	// get parent path
	err = kern_path(BSR_LOG_FILE_PATH, 0, &old_path);
	if (err)
		goto exit;

	err = kern_path(BSR_LOG_FILE_PATH, 0, &new_path);
	if (err)
		goto exit1;

	err = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto exit2;

	err = mnt_want_write(old_path.mnt);

	if (err)
		goto exit2;

	old_dir = old_path.dentry;
	new_dir = new_path.dentry;

	// parent inode lock
	trap = lock_rename(new_dir, old_dir);

	// get old file dentry
	old_dentry = lookup_one_len(oldname, old_path.dentry, strlen(oldname));

	if (IS_ERR(old_dentry)) {
		err = PTR_ERR(old_dentry);
		goto exit3;
	}

	// get new file dentry
	new_dentry = lookup_one_len(newname, new_path.dentry, strlen(newname));
	if (IS_ERR(new_dentry)) {
		err = PTR_ERR(new_dentry);
		goto exit4;
	}

	/* source should not be ancestor of target */
	err = -EINVAL;
	if (old_dentry == trap)
		goto exit5;
	
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!S_ISDIR(old_dentry->d_inode->i_mode)) {
		err = -ENOTDIR;
		if (old_dentry->d_name.name[old_dentry->d_name.len])
			goto exit5;
		if (new_dentry->d_name.name[new_dentry->d_name.len])
			goto exit5;
	}
	
	/* target should not be an ancestor of source */
	err = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	/* source must exist */
	err = -ENOENT;
	if (!old_dentry->d_inode)
		goto exit5;

	// rename
	err = bsr_rename(old_dir->d_inode, old_dentry,
	    new_dir->d_inode, new_dentry);

exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_dir, old_dir);
	mnt_drop_write(old_path.mnt);
exit2:
	path_put(&new_path);
exit1:
	path_put(&old_path);
exit:
	return err;
}

// BSR-597
// based on linux/fs/namei.c - do_unlinkat()
int bsr_file_remove(const char *filename)
{
	struct dentry *dentry;
	struct path parent;
	struct inode *inode = NULL;
	int err = 0;

	// get parent path
	err = kern_path(BSR_LOG_FILE_PATH, 0, &parent);
	if (err)
		return err;

	err = mnt_want_write(parent.mnt);
	if (err)
		goto exit1;

	// parent inode lock
	bsr_inode_lock_nested(parent.dentry->d_inode, I_MUTEX_PARENT);

	// get file dentry
	dentry = lookup_one_len(filename, parent.dentry, strlen(filename));
	err = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		if (parent.dentry->d_name.name[parent.dentry->d_name.len])
			goto slashes;

		inode = dentry->d_inode;

		if (inode)
			ihold(inode);
		else
			goto slashes;

		// unlink
		err = bsr_unlink(parent.dentry->d_inode, dentry);
exit2:
		dput(dentry);
	}

	bsr_inode_unlock(parent.dentry->d_inode);
	if (inode)
		iput(inode);    /* truncate the inode here */
	inode = NULL;
	mnt_drop_write(parent.mnt);
exit1:
	path_put(&parent);
	return err;

slashes:
	if (S_ISDIR(dentry->d_inode->i_mode))
		err = -EISDIR;
	else
	 	err = -ENOTDIR;
	goto exit2;
}

#ifdef COMPAT_HAVE_DIR_CONTEXT_PARAMS
int printdir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
#else
int printdir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type)
#endif
{
	struct log_rolling_file_list *rlist =
#ifdef COMPAT_HAVE_DIR_CONTEXT_PARAMS
		container_of(ctx, struct log_rolling_file_list, ctx);
#else
		(struct log_rolling_file_list *)buf;
#endif
		
	int err = 0;
	struct log_rolling_file_list *r;
	if (strncmp(name, BSR_LOG_FILE_NAME, namelen) == 0)
		return 0;
	if (strstr(name, BSR_LOG_ROLLING_FILE_NAME)) {
		r = kmalloc(sizeof(struct log_rolling_file_list), GFP_ATOMIC, '');
		if (!r) {
			bsr_err(NO_OBJECT, "failed to allocation file list size(%d)\n", sizeof(struct log_rolling_file_list));
			err = -1;
			goto out;
		}
		r->fileName = kmalloc(namelen + 1, GFP_ATOMIC, '');
		if (!r) {
			bsr_err(NO_OBJECT, "failed to allocation file list size(%d)\n", namelen);
			err = -1;
			goto out;
		}
		memset(r->fileName, 0, namelen + 1);
		snprintf(r->fileName, namelen + 1, "%s", name);
		list_add_tail(&r->list, &rlist->list);

	}
out:
	return err;
}


// BSR-597 read dir file list
int bsr_readdir(char * dir_path, struct log_rolling_file_list * rlist)
{
	int err = 0;
	struct file *fdir;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	
	fdir = filp_open(dir_path, O_RDONLY, 0);
	if (fdir) {
#ifdef COMPAT_HAVE_ITERATE_DIR
		err = iterate_dir(fdir, &rlist->ctx);
#else
		err = vfs_readdir(fdir, printdir, rlist);
#endif
		filp_close(fdir, NULL);
	} else {
		bsr_err(NO_OBJECT, "failed to open log directory\n");
	}
	set_fs(oldfs);

	return err;
}


// BSR-610
// based on linux/fs/namei.c - do_mkdirat()
long bsr_mkdir(const char *pathname, umode_t mode)
{
	struct dentry *dentry;
	int err;
#ifdef COMPAT_HAVE_KERN_PATH_CREATE
	struct path path;
	dentry = kern_path_create(AT_FDCWD, pathname, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) 
		return PTR_ERR(dentry);
	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
	done_path_create(&path, dentry);
#else
	struct nameidata nd;
	err = path_lookup(pathname, LOOKUP_PARENT, &nd);
	if (err)
		return err;

	dentry = lookup_create(&nd, 1);
	if (!IS_ERR(dentry)) {
		err = vfs_mkdir(d_inode(nd.path.dentry), dentry, mode);
		dput(dentry);
	} else {
		err = PTR_ERR(dentry);
	}
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
#endif
	return err;
}
