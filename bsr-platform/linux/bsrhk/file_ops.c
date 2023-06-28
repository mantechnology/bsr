#include <linux/namei.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include "bsr_int.h"
#include "../bsr-headers/bsr_ioctl.h"


// BSR-577
static int bsr_set_minlog_lv(LOGGING_MIN_LV __user * args)
{
	LOGGING_MIN_LV loggingMinLv;
	int previous_lv_min = 0;
	int err;

	err = copy_from_user(&loggingMinLv, args, sizeof (LOGGING_MIN_LV));
	
	if (err) {
		bsr_err(124, BSR_LC_DRIVER, NO_OBJECT, "Failed to set minimum log level due to failure to copy from user");
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
	else {
		bsr_warn(92, BSR_LC_DRIVER, NO_OBJECT,"Invalidate logging type(%d)", loggingMinLv.nType);
	}
	
	// DW-2008
	bsr_info(125, BSR_LC_DRIVER, NO_OBJECT, "set minimum log level, type : %s(%d), minumum level : %s(%d) => %s(%d)",
				g_log_type_str[loggingMinLv.nType], loggingMinLv.nType, 
				g_default_lv_str[previous_lv_min], previous_lv_min, 
				g_default_lv_str[loggingMinLv.nErrLvMin], loggingMinLv.nErrLvMin);

	return Get_log_lv();
}

// BSR-1052
// BSR-1048 
static int bsr_get_log(BSR_LOG __user *bsr_log) 
{
	int err;
	
	err = copy_to_user(&bsr_log->totalcnt, &gLogBuf.h.total_count, (unsigned long) sizeof(gLogBuf.h.total_count));

	if (err) {
		bsr_warn(93, BSR_LC_DRIVER, NO_OBJECT, "Failed to copy total log count to user");
		return err;
	}
	err = copy_to_user(&bsr_log->LogBuf, &gLogBuf.b, LOGBUF_MAXCNT * (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH));
	if (err) {
		bsr_warn(94, BSR_LC_DRIVER, NO_OBJECT, "Failed to copy log buffer to user");
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
		bsr_err(126, BSR_LC_DRIVER, NO_OBJECT, "Failed to set log max count due to failure to copy from user");
		return err;
	}

	bsr_info(127, BSR_LC_DRIVER, NO_OBJECT, "set log file max count %lu => %lu", atomic_read(&g_log_file_max_count), log_file_max_count);
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
		bsr_err(128, BSR_LC_DRIVER, NO_OBJECT, "Failed to set handler use due to copy from user");
		return -1;
	}

	bsr_info(129, BSR_LC_DRIVER, NO_OBJECT, "set handler_use %d => %d", g_handler_use, h_info.use);
	g_handler_use = h_info.use;

	return 0;
}

// BSR-740
static int bsr_set_bsrmon_run(unsigned int __user * args)
{
	unsigned int run = 1;
	int err;

	err = copy_from_user(&run, args, sizeof(unsigned int));

	if (err) {
		bsr_err(143, BSR_LC_DRIVER, NO_OBJECT, "Failed to set bsrmon run due to failure to copy from user");
		return err;
	}

	bsr_debug(144, BSR_LC_DRIVER, NO_OBJECT, "set bsrmon_run %u => %u", atomic_read(&g_bsrmon_run), run);
	atomic_set(&g_bsrmon_run, run);

	return 0;
}

 // BSR-740
 static int bsr_get_bsrmon_run(unsigned int __user * args)
{
	int err;
	unsigned int run = atomic_read(&g_bsrmon_run);

	err = copy_to_user(args, &run, sizeof(unsigned int));

	if (err) {
		bsr_err(146, BSR_LC_DRIVER, NO_OBJECT, "Failed to copy bsrmon_run due to failure to copy from user");
		return err;
	}
	return 0;
}



// BSR-654
static int bsr_set_debug_log_out_put_category(DEBUG_LOG_CATEGORY __user *bsr_dbg_log_ctgr)
{
	unsigned int previous = 0;
	unsigned int categories = 0;
	int err;
	DEBUG_LOG_CATEGORY dbg_log_ctgr;

	previous = atomic_read(&g_debug_output_category);

	err = copy_from_user(&dbg_log_ctgr, bsr_dbg_log_ctgr, sizeof(DEBUG_LOG_CATEGORY));
	if (err) {
		bsr_err(135, BSR_LC_DRIVER, NO_OBJECT, "Failed to set debug log out put category due to copy from user");
		return -1;
	}

	categories = dbg_log_ctgr.nCategory;

	if (dbg_log_ctgr.nType == 0) {
		//enable
		categories = (previous | categories);
	}
	else {
		//disable
		categories = previous - (previous & categories);
	}

	atomic_set(&g_debug_output_category, categories);
	bsr_info(136, BSR_LC_DRIVER, NO_OBJECT, "The debug log output has been updated, %u => %u", previous, atomic_read(&g_debug_output_category));

	err = copy_to_user(&bsr_dbg_log_ctgr->nCategory, &categories, sizeof(categories));

	if (err) {
		bsr_warn(137, BSR_LC_DRIVER, NO_OBJECT, "Failed to copy debug log category to user");
	}

	return err;
}

// BSR-764
static int bsr_set_simul_perf_degrade(SIMULATION_PERF_DEGR __user * args)
{
	SIMULATION_PERF_DEGR simul_perf;
	int err;

	err = copy_from_user(&simul_perf, args, sizeof(SIMULATION_PERF_DEGR));
	if (err) {
		bsr_err(147, BSR_LC_DRIVER, NO_OBJECT, "Failed to IOCTL_MVOL_SET_SIMUL_PERF_DEGR due to copy from user");
		return -1;
	}

	g_simul_perf = simul_perf;

	bsr_info(148, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MVOL_SET_SIMUL_PERF_DEGR Flag:%d Type:%d", 
					g_simul_perf.flag, g_simul_perf.type);

	return 0;
}

// BSR-1048 wrtie the received message in the bsr kernel log.
LONG_PTR g_klog_last_time = 0;
int g_skip_klog = 0;
long bsr_write_log(WRITE_KERNEL_LOG __user * args) 
{
	int err;
	WRITE_KERNEL_LOG writeLog;
	char *lv = NULL;
	LONG_PTR klog_current_time = jiffies;

	err = copy_from_user(&writeLog, args, sizeof(WRITE_KERNEL_LOG));
	
	if(err) {
		bsr_err(152, BSR_LC_DRIVER, NO_OBJECT, "Failed to IOCTL_WRITE_LOG due to copy from user");
		return -1;
	}
	
	if ((writeLog.length <= 0) || (writeLog.length >= MAX_BSRLOG_BUF)) {
		bsr_err(153, BSR_LC_DRIVER, NO_OBJECT, "Failed to wrtie kernel log due to invalid log length(%d)", writeLog.length);
		return -1;
	}
	
	if (writeLog.level < KERN_EMERG_NUM || writeLog.level >= KERN_NUM_END) {
		bsr_err(154, BSR_LC_DRIVER, NO_OBJECT, "Failed to wrtie kernel log due to unknown log level(%d)", writeLog.level);
		return -1;
	}
	
	if (g_klog_last_time != 0) {
		if ((g_klog_last_time + HZ) > klog_current_time) {
			g_skip_klog++;
			return 0;
		}
	}

	g_klog_last_time = klog_current_time;

	switch (writeLog.level) {
	case KERN_EMERG_NUM:
		lv = KERN_EMERG;
		break;
	case KERN_ALERT_NUM:
		lv = KERN_ALERT;
		break;
	case KERN_CRIT_NUM:
		lv = KERN_CRIT;
		break;
	case KERN_ERR_NUM:
		lv = KERN_ERR;
		break;
	case KERN_WARNING_NUM:
		lv = KERN_WARNING;
		break;
	case KERN_NOTICE_NUM:
		lv = KERN_NOTICE;
		break;
	case KERN_INFO_NUM:
		lv = KERN_INFO;
		break;
	case KERN_DEBUG_NUM:
		lv = KERN_DEBUG;
		break;
	}

	if (g_skip_klog)
		__bsr_printk(BSR_LC_ETC, -1, lv, "%s, skipped logs(%d)", writeLog.message, g_skip_klog);
	else
		__bsr_printk(BSR_LC_ETC, -1, lv, "%s", writeLog.message);

	g_skip_klog = 0;
	
	return 0;
}


// BSR-1072
extern atomic_t g_forced_kernel_panic;
extern atomic_t g_panic_occurrence_time;

long bsr_panic(KERNEL_PANIC_INFO __user * args) 
{
	int err;
	KERNEL_PANIC_INFO in;

	err = copy_from_user(&in, args, sizeof(KERNEL_PANIC_INFO));
	
	if(err) {
		bsr_err(157, BSR_LC_DRIVER, NO_OBJECT, "Failed to IOCTL_MVOL_BSR_PANIC due to copy from user");
		return -1;
	}
	
	if(in.force) {
		// BSR-1073
		size_t len = strlen(in.cert);
		if (len > 1 && len < MAX_PANIC_CERT_BUF) {
			if(0 == strcmp(in.cert, "forcedkernelpanic"))
				panic("User forced kernel panic.");
		}
	} else {	
		bsr_info(155, BSR_LC_DRIVER, NO_OBJECT, "Sets the bsr kernel panic, %s => %s ", atomic_read(&g_forced_kernel_panic) ? "enable" : "disable", in.enable ? "enable" : "disable");
		atomic_set(&g_forced_kernel_panic, in.enable);

		bsr_info(156, BSR_LC_DRIVER, NO_OBJECT, "Sets the time at which bsr kernel panic occurs, %d => %d(sec)", atomic_read(&g_panic_occurrence_time), in.occurrence_time);
		atomic_set(&g_panic_occurrence_time, in.occurrence_time);
	}
	return 0;
}
// BSR-1039
extern atomic_t g_hold_state_type;
extern atomic_t g_hold_state;

long bsr_hold_state(HOLD_STATE __user * args) 
{	
	int err;
	HOLD_STATE in;

	err = copy_from_user(&in, args, sizeof(HOLD_STATE));
	
	if(err) {
		bsr_err(160, BSR_LC_DRIVER, NO_OBJECT, "Failed to IOCTL_MVOL_HOLD_STATE due to copy from user");
		return -1;
	}
	
	if ((atomic_read(&g_hold_state_type) == HOLD_STATE_TYPE_REPL && atomic_read(&g_hold_state) == L_AHEAD) &&
		(in.type != HOLD_STATE_TYPE_REPL || in.state != L_AHEAD)) {
		struct bsr_resource *resource;
		struct bsr_connection *connection;
		struct bsr_peer_device *peer_device;
		int vnr;
		
		rcu_read_lock();
		for_each_resource_rcu(resource, &bsr_resources) {
			for_each_connection_rcu(connection, resource) {
				idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
					if (peer_device->repl_state[NOW] == L_AHEAD &&
						(atomic_read64(&connection->rs_in_flight) + atomic_read64(&connection->ap_in_flight)) == 0 &&
						!test_and_set_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags)) {
						wake_up(&connection->resource->resync_reply_wait);
						peer_device->start_resync_side = L_SYNC_SOURCE;
						mod_timer(&peer_device->start_resync_timer, jiffies + HZ);
					}
				}
			}
		}
		rcu_read_unlock();
	}
	
	bsr_info(158, BSR_LC_DRIVER, NO_OBJECT, "sets the hold state type, %d => %d", atomic_read(&g_hold_state_type), in.type);
	atomic_set(&g_hold_state_type, in.type);

	bsr_info(159, BSR_LC_DRIVER, NO_OBJECT, "sets the hold state, %d => %d", atomic_read(&g_hold_state), in.state);
	atomic_set(&g_hold_state, in.state);
	
	return 0;
}

extern atomic_t g_fake_al_used;

long bsr_fake_al_used(int __user * args) 
{
	
	int err;
	int al_used_count;

	err = copy_from_user(&al_used_count, args, sizeof(int));
	
	if(err) {
		bsr_err(161, BSR_LC_DRIVER, NO_OBJECT, "Failed to IOCTL_MVOL_FAKE_AL_USED due to copy from user");
		return -1;
	}
	
	bsr_info(162, BSR_LC_DRIVER, NO_OBJECT, "sets the fake AL used, %d => %d", atomic_read(&g_fake_al_used), al_used_count);
	atomic_set(&g_fake_al_used, al_used_count);

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
// BSR-1052
// BSR-1048
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
	// BSR-654
	case IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY:
	{
		err = bsr_set_debug_log_out_put_category((DEBUG_LOG_CATEGORY __user *)param);
		break;
	}
	case IOCTL_MVOL_SET_HANDLER_USE:
	{
		err = bsr_set_handler_use((HANDLER_INFO __user *)param);
		break;
	}
	// BSR-740
	case IOCTL_MVOL_SET_BSRMON_RUN:
	{
		err = bsr_set_bsrmon_run((unsigned int __user *)param);
		break;
	}
	// BSR-741
	case IOCTL_MVOL_GET_BSRMON_RUN:
	{
		err = bsr_get_bsrmon_run((unsigned int __user *)param);
		break;
	}
	// BSR-764
	case IOCTL_MVOL_SET_SIMUL_PERF_DEGR:
	{
		err = bsr_set_simul_perf_degrade((SIMULATION_PERF_DEGR __user *)param);
		break;
	}
	// BSR-1048
	case IOCTL_MVOL_WRITE_LOG:
	{
		err = bsr_write_log((WRITE_KERNEL_LOG __user *)param);
		break;
	}
	// BSR-1072
	case IOCTL_MVOL_BSR_PANIC:
	{
		err = bsr_panic((KERNEL_PANIC_INFO __user *)param);
		break;
	}
	// BSR-1039
	case IOCTL_MVOL_HOLD_STATE:
	{
		err = bsr_hold_state((HOLD_STATE __user *)param);
		break;
	}
	case IOCTL_MVOL_FAKE_AL_USED:
	{
		err = bsr_fake_al_used((int __user *)param);
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
	    new_dir->d_inode, new_dentry, old_path.mnt, new_path.mnt);

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
		r = bsr_kmalloc(sizeof(struct log_rolling_file_list), GFP_ATOMIC, '');
		if (!r) {
			bsr_err(84, BSR_LC_MEMORY, NO_OBJECT, "Failed to print dir due to failure to allocation file list size(%d)", sizeof(struct log_rolling_file_list));
			err = -1;
			goto out;
		}
		r->fileName = bsr_kmalloc(namelen + 1, GFP_ATOMIC, '');
		if (!r) {
			bsr_err(85, BSR_LC_MEMORY, NO_OBJECT, "Failed to print dir due to failure to failure to allocation file name size(%d)", namelen);
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
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif
	
	fdir = filp_open(dir_path, O_RDONLY, 0);
	if (fdir) {
#ifdef COMPAT_HAVE_ITERATE_DIR
		err = iterate_dir(fdir, &rlist->ctx);
#else
		err = vfs_readdir(fdir, printdir, rlist);
#endif
		filp_close(fdir, NULL);
	} else {
		bsr_err(132, BSR_LC_DRIVER, NO_OBJECT, "Failed to read dir due to failure to open log directory");
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
#ifdef COMPAT_VFS_MKDIR_HAS_NS_PARAMS
	err = vfs_mkdir(&init_user_ns, d_inode(path.dentry), dentry, mode);

#else
	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
#endif
	done_path_create(&path, dentry);
#else // old kernel (version < 3.1)
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


// BSR-584 reading /etc/bsr.d/.XXX file
long read_reg_file(char *file_path, long default_val)
{	
	struct file *fd = NULL;
	char *buffer = NULL;
	int filesize = 0;
	long ret_val = default_val;
	int err = 0;
	mm_segment_t oldfs;

	oldfs = get_fs();
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif
	fd = filp_open(file_path, O_RDONLY, 0);

	if (fd == NULL || IS_ERR(fd))
		goto out;

	filesize = fd->f_op->llseek(fd, 0, SEEK_END);
	if (filesize <= 0)
		goto close;

	// BSR-778 fix debuglog_category file read error due to incorrect buffer size allocation
	buffer = bsr_kmalloc(filesize + 1, GFP_ATOMIC|__GFP_NOWARN, '');

	memset(buffer, 0, filesize + 1);
	
	if (fd->f_op->llseek(fd, 0, SEEK_SET) < 0)
		goto close;
	err = bsr_read(fd, buffer, filesize, &fd->f_pos);
	if (err < 0 || err != filesize)
		goto close;

	err = kstrtol(buffer, 0, &ret_val);
	if (err < 0)
		ret_val = default_val;

close:
	if (buffer != NULL)
		bsr_kfree(buffer);
	if (fd != NULL)
		filp_close(fd, NULL);
out:
	set_fs(oldfs);
	return ret_val;
}