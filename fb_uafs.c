/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2011 Your File System, Inc. All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Sun Microsystems, Inc.
 * Portions Copyright 2008 Denis Cheng
 */

#include "config.h"
#include "filebench.h"
#include "flowop.h"
#include "threadflow.h" /* For aiolist definition */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <strings.h>

#define UKERNEL 1
#include <afs/param.h>
#include <afs/sysincludes.h>
#include <afs/afs_usrops.h>
#include <afs/afs_args.h>

#include "filebench.h"
#include "fsplug.h"

#ifdef HAVE_AIO
#include <aio.h>
#endif /* HAVE_AIO */

/*
 * These routines implement local file access. They are placed into a
 * vector of functions that are called by all I/O operations in fileset.c
 * and flowop_library.c. This represents the default file system plug-in,
 * and may be replaced by vectors for other file system plug-ins.
 */

static int fb_uafs_freemem(fb_fdesc_t *fd, off64_t size);
static int fb_uafs_open(fb_fdesc_t *, char *, int, int);
static int fb_uafs_pread(fb_fdesc_t *, caddr_t, fbint_t, off64_t);
static int fb_uafs_read(fb_fdesc_t *, caddr_t, fbint_t);
static int fb_uafs_pwrite(fb_fdesc_t *, caddr_t, fbint_t, off64_t);
static int fb_uafs_write(fb_fdesc_t *, caddr_t, fbint_t);
static int fb_uafs_lseek(fb_fdesc_t *, off64_t, int);
static int fb_uafs_truncate(fb_fdesc_t *, off64_t);
static int fb_uafs_rename(const char *, const char *);
static int fb_uafs_close(fb_fdesc_t *);
static int fb_uafs_link(const char *, const char *);
static int fb_uafs_symlink(const char *, const char *);
static int fb_uafs_unlink(char *);
static ssize_t fb_uafs_readlink(const char *, char *, size_t);
static int fb_uafs_mkdir(char *, int);
static int fb_uafs_rmdir(char *);
static DIR *fb_uafs_opendir(char *);
static struct dirent *fb_uafs_readdir(DIR *);
static int fb_uafs_closedir(DIR *);
static int fb_uafs_fsync(fb_fdesc_t *);
static int fb_uafs_stat(char *, struct stat64 *);
static int fb_uafs_fstat(fb_fdesc_t *, struct stat64 *);
static int fb_uafs_access(const char *, int);
static void fb_uafs_recur_rm(char *);

static fsplug_func_t fb_uafs_funcs =
{
	"locfs",
	fb_uafs_freemem,		/* flush page cache */
	fb_uafs_open,		/* open */
	fb_uafs_pread,		/* pread */
	fb_uafs_read,		/* read */
	fb_uafs_pwrite,		/* pwrite */
	fb_uafs_write,		/* write */
	fb_uafs_lseek,		/* lseek */
	fb_uafs_truncate,	/* ftruncate */
	fb_uafs_rename,		/* rename */
	fb_uafs_close,		/* close */
	fb_uafs_link,		/* link */
	fb_uafs_symlink,		/* symlink */
	fb_uafs_unlink,		/* unlink */
	fb_uafs_readlink,	/* readlink */
	fb_uafs_mkdir,		/* mkdir */
	fb_uafs_rmdir,		/* rmdir */
	fb_uafs_opendir,		/* opendir */
	fb_uafs_readdir,		/* readdir */
	fb_uafs_closedir,	/* closedir */
	fb_uafs_fsync,		/* fsync */
	fb_uafs_stat,		/* stat */
	fb_uafs_fstat,		/* fstat */
	fb_uafs_access,		/* access */
	fb_uafs_recur_rm		/* recursive rm */
};

#ifdef HAVE_AIO
/*
 * Local file system asynchronous IO flowops are in this module, as
 * they have a number of local file system specific features.
 */
static int fb_uafsflow_aiowrite(threadflow_t *threadflow, flowop_t *flowop);
static int fb_uafsflow_aiowait(threadflow_t *threadflow, flowop_t *flowop);

static flowop_proto_t fb_uafsflow_funcs[] = {
	{FLOW_TYPE_AIO, FLOW_ATTR_WRITE, "aiowrite", flowop_init_generic,
	fb_uafsflow_aiowrite, flowop_destruct_generic},
	{FLOW_TYPE_AIO, 0, "aiowait", flowop_init_generic,
	fb_uafsflow_aiowait, flowop_destruct_generic}
};

#endif /* HAVE_AIO */

/*
 * Initialize this processes I/O functions vector to point to
 * the vector of local file system I/O functions
 */
void
fb_uafs_funcvecinit(void)
{
	char afsMountPoint[100], afsConfDir[100], afsCacheDir[100];

	int cacheBlocks = 500000;
	int cacheFiles  = 0;
	int cacheStatEntries = 8192;
	int dCacheSize  = 0;
	int vCacheSize  = 200;
	int chunkSize   = 20;
	int closeSynch  = 0;
	int debug       = 0;
	int nDaemons    = 4; 
	int cacheFlags  = AFSCALL_INIT_MEMCACHE;

	strcpy(afsMountPoint, "/afs");
	strcpy(afsConfDir,  "/usr/vice/etc");
	/* won't matter */
	strcpy(afsCacheDir, "/tmp/cache");

        (void) osi_Init();
	(void) uafs_Init("filebench", afsMountPoint, afsConfDir, afsCacheDir,
		  cacheBlocks, cacheFiles, cacheStatEntries,
		  dCacheSize, vCacheSize, chunkSize,
		  closeSynch, debug, nDaemons, cacheFlags, NULL);

	fs_functions_vec = &fb_uafs_funcs;
}

/*
 * Initialize those flowops whose implementation is file system
 * specific.
 */
void
fb_uafs_flowinit(void)
{
	int nops;

	/*
	 * re-initialize the I/O functions vector while we are at
	 * it as it may have been redefined since the process was
	 * created, at least if this is the master processes
	 */
	fb_uafs_funcvecinit();

#ifdef HAVE_AIO
	nops = sizeof (fb_uafsflow_funcs) / sizeof (flowop_proto_t);
	flowop_flow_init(fb_uafsflow_funcs, nops);
#endif /* HAVE_AIO */
}

/*
 * Frees up memory mapped file region of supplied size. The
 * file descriptor "fd" indicates which memory mapped file.
 * If successful, returns 0. Otherwise returns -1 if "size"
 * is zero, or -1 times the number of times msync() failed.
 */
static int
fb_uafs_freemem(fb_fdesc_t *fd, off64_t size)
{
	off64_t left;
	int ret = 0;

	return -1;
	for (left = size; left > 0; left -= MMAP_SIZE) {
		off64_t thismapsize;
		caddr_t addr;

		thismapsize = MIN(MMAP_SIZE, left);
		addr = mmap64(0, thismapsize, PROT_READ|PROT_WRITE,
		    MAP_SHARED, fd->fd_num, size - left);
		ret += msync(addr, thismapsize, MS_INVALIDATE);
		(void) munmap(addr, thismapsize);
	}
	return (ret);
}

/*
 * Does a posix pread. Returns what the pread() returns.
 */
static int
fb_uafs_pread(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize, off64_t fileoffset)
{
	return (uafs_pread(fd->fd_num, iobuf, iosize, (off_t)fileoffset));
}

/*
 * Does a posix read. Returns what the read() returns.
 */
static int
fb_uafs_read(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize)
{
	return (uafs_read(fd->fd_num, iobuf, iosize));
}

#ifdef HAVE_AIO

/*
 * Asynchronous write section. An Asynchronous IO element
 * (aiolist_t) is used to associate the asynchronous write request with
 * its subsequent completion. This element includes a aiocb64 struct
 * that is used by posix aio_xxx calls to track the asynchronous writes.
 * The flowops aiowrite and aiowait result in calls to these posix
 * aio_xxx system routines to do the actual asynchronous write IO
 * operations.
 */


/*
 * Allocates an asynchronous I/O list (aio, of type
 * aiolist_t) element. Adds it to the flowop thread's
 * threadflow aio list. Returns a pointer to the element.
 */
static aiolist_t *
aio_allocate(flowop_t *flowop)
{
	aiolist_t *aiolist;

	if ((aiolist = malloc(sizeof (aiolist_t))) == NULL) {
		filebench_log(LOG_ERROR, "malloc aiolist failed");
		filebench_shutdown(1);
	}

	bzero(aiolist, sizeof(*aiolist));

	/* Add to list */
	if (flowop->fo_thread->tf_aiolist == NULL) {
		flowop->fo_thread->tf_aiolist = aiolist;
		aiolist->al_next = NULL;
	} else {
		aiolist->al_next = flowop->fo_thread->tf_aiolist;
		flowop->fo_thread->tf_aiolist = aiolist;
	}
	return (aiolist);
}

/*
 * Searches for the aiolist element that has a matching
 * completion block, aiocb. If none found returns FILEBENCH_ERROR. If
 * found, removes the aiolist element from flowop thread's
 * list and returns FILEBENCH_OK.
 */
static int
aio_deallocate(flowop_t *flowop, struct aiocb64 *aiocb)
{
	aiolist_t *aiolist = flowop->fo_thread->tf_aiolist;
	aiolist_t *previous = NULL;
	aiolist_t *match = NULL;

	if (aiocb == NULL) {
		filebench_log(LOG_ERROR, "null aiocb deallocate");
		return (FILEBENCH_OK);
	}

	while (aiolist) {
		if (aiocb == &(aiolist->al_aiocb)) {
			match = aiolist;
			break;
		}
		previous = aiolist;
		aiolist = aiolist->al_next;
	}

	if (match == NULL)
		return (FILEBENCH_ERROR);

	/* Remove from the list */
	if (previous)
		previous->al_next = match->al_next;
	else
		flowop->fo_thread->tf_aiolist = match->al_next;

	return (FILEBENCH_OK);
}

/*
 * Emulate posix aiowrite(). Determines which file to use,
 * either one file of a fileset, or the file associated
 * with a fileobj, allocates and fills an aiolist_t element
 * for the write, and issues the asynchronous write. This
 * operation is only valid for random IO, and returns an
 * error if the flowop is set for sequential IO. Returns
 * FILEBENCH_OK on success, FILEBENCH_NORSC if iosetup can't
 * obtain a file to open, and FILEBENCH_ERROR on any
 * encountered error.
 */
static int
fb_uafsflow_aiowrite(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	fbint_t wss;
	fbint_t iosize;
	fb_fdesc_t *fdesc;
	int ret;

	iosize = avd_get_int(flowop->fo_iosize);

	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &fdesc, iosize)) != FILEBENCH_OK)
		return (ret);

	if (avd_get_bool(flowop->fo_random)) {
		uint64_t fileoffset;
		struct aiocb64 *aiocb;
		aiolist_t *aiolist;

		if (wss < iosize) {
			filebench_log(LOG_ERROR,
			    "file size smaller than IO size for thread %s",
			    flowop->fo_name);
			return (FILEBENCH_ERROR);
		}

		fb_urandom64(&fileoffset, wss, iosize, NULL);

		aiolist = aio_allocate(flowop);
		aiolist->al_type = AL_WRITE;
		aiocb = &aiolist->al_aiocb;

		aiocb->aio_fildes = fdesc->fd_num;
		aiocb->aio_buf = iobuf;
		aiocb->aio_nbytes = (size_t)iosize;
		aiocb->aio_offset = (off64_t)fileoffset;
		aiocb->aio_reqprio = 0;

		filebench_log(LOG_DEBUG_IMPL,
		    "aio fd=%d, bytes=%llu, offset=%llu",
		    fdesc->fd_num, (u_longlong_t)iosize,
		    (u_longlong_t)fileoffset);

		flowop_beginop(threadflow, flowop);
		if (aio_write64(aiocb) < 0) {
			filebench_log(LOG_ERROR, "aiowrite failed: %s",
			    strerror(errno));
			filebench_shutdown(1);
		}
		flowop_endop(threadflow, flowop, iosize);
	} else {
		return (FILEBENCH_ERROR);
	}

	return (FILEBENCH_OK);
}



#define	MAXREAP 4096

/*
 * Emulate posix aiowait(). Waits for the completion of half the
 * outstanding asynchronous IOs, or a single IO, which ever is
 * larger. The routine will return after a sufficient number of
 * completed calls issued by any thread in the procflow have
 * completed, or a 1 second timout elapses. All completed
 * IO operations are deleted from the thread's aiolist.
 */
static int
fb_uafsflow_aiowait(threadflow_t *threadflow, flowop_t *flowop)
{
	struct aiocb64 **worklist;
	aiolist_t *aio = flowop->fo_thread->tf_aiolist;
	int uncompleted = 0;
#ifdef HAVE_AIOWAITN
	int i;
#endif

	worklist = calloc(MAXREAP, sizeof (struct aiocb64 *));

	/* Count the list of pending aios */
	while (aio) {
		uncompleted++;
		aio = aio->al_next;
	}

	do {
		uint_t ncompleted = 0;
		uint_t todo;
		struct timespec timeout;
		int inprogress;

		/* Wait for half of the outstanding requests */
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;

		if (uncompleted > MAXREAP)
			todo = MAXREAP;
		else
			todo = uncompleted / 2;

		if (todo == 0)
			todo = 1;

		flowop_beginop(threadflow, flowop);

#ifdef HAVE_AIOWAITN
		if (((aio_waitn64((struct aiocb64 **)worklist,
		    MAXREAP, &todo, &timeout)) == -1) &&
		    errno && (errno != ETIME)) {
			filebench_log(LOG_ERROR,
			    "aiowait failed: %s, outstanding = %d, "
			    "ncompleted = %d ",
			    strerror(errno), uncompleted, todo);
		}

		ncompleted = todo;
		/* Take the  completed I/Os from the list */
		inprogress = 0;
		for (i = 0; i < ncompleted; i++) {
			if ((aio_return64(worklist[i]) == -1) &&
			    (errno == EINPROGRESS)) {
				inprogress++;
				continue;
			}
			if (aio_deallocate(flowop, worklist[i])
			    == FILEBENCH_ERROR) {
				filebench_log(LOG_ERROR, "Could not remove "
				    "aio from list ");
				flowop_endop(threadflow, flowop, 0);
				return (FILEBENCH_ERROR);
			}
		}

		uncompleted -= ncompleted;
		uncompleted += inprogress;

#else

		for (ncompleted = 0, inprogress = 0,
		    aio = flowop->fo_thread->tf_aiolist;
		    ncompleted < todo && aio != NULL; aio = aio->al_next) {
			int result = aio_error64(&aio->al_aiocb);

			if (result == EINPROGRESS) {
				inprogress++;
				continue;
			}

			if ((aio_return64(&aio->al_aiocb) == -1) || result) {
				filebench_log(LOG_ERROR, "aio failed: %s",
				    strerror(result));
				continue;
			}

			ncompleted++;

			if (aio_deallocate(flowop, &aio->al_aiocb) < 0) {
				filebench_log(LOG_ERROR, "Could not remove "
				    "aio from list ");
				flowop_endop(threadflow, flowop, 0);
				return (FILEBENCH_ERROR);
			}
		}

		uncompleted -= ncompleted;

#endif
		filebench_log(LOG_DEBUG_SCRIPT,
		    "aio2 completed %d ios, uncompleted = %d, inprogress = %d",
		    ncompleted, uncompleted, inprogress);

	} while (uncompleted > MAXREAP);

	flowop_endop(threadflow, flowop, 0);

	free(worklist);

	return (FILEBENCH_OK);
}

#endif /* HAVE_AIO */

/*
 * Does an open64 of a file. Inserts the file descriptor number returned
 * by open() into the supplied filebench fd. Returns FILEBENCH_OK on
 * successs, and FILEBENCH_ERROR on failure.
 */

static int
fb_uafs_open(fb_fdesc_t *fd, char *path, int flags, int perms)
{
	if ((fd->fd_num = uafs_open(path, flags, perms)) < 0)
		return (FILEBENCH_ERROR);
	else
		return (FILEBENCH_OK);
}

/*
 * Does an unlink (delete) of a file.
 */
static int
fb_uafs_unlink(char *path)
{
	return (uafs_unlink(path));
}

/*
 * Does a readlink of a symbolic link.
 */
static ssize_t
fb_uafs_readlink(const char *path, char *buf, size_t buf_size)
{
	return (uafs_readlink(path, buf, buf_size));
}

/*
 * Does fsync of a file. Returns with fsync return info.
 */
static int
fb_uafs_fsync(fb_fdesc_t *fd)
{
	return (uafs_fsync(fd->fd_num));
}

/*
 * Do a posix lseek of a file. Return what lseek() returns.
 */
static int
fb_uafs_lseek(fb_fdesc_t *fd, off64_t offset, int whence)
{
	return (uafs_lseek(fd->fd_num, (off_t)offset, whence));
}

/*
 * Do a posix rename of a file. Return what rename() returns.
 */
static int
fb_uafs_rename(const char *old, const char *new)
{
	return (uafs_rename(old, new));
}


/*
 * Do a posix close of a file. Return what close() returns.
 */
static int
fb_uafs_close(fb_fdesc_t *fd)
{
	return (uafs_close(fd->fd_num));
}

/*
 * Use mkdir to create a directory.
 */
static int
fb_uafs_mkdir(char *path, int perm)
{
	return (uafs_mkdir(path, perm));
}

/*
 * Use rmdir to delete a directory. Returns what rmdir() returns.
 */
static int
fb_uafs_rmdir(char *path)
{
	return (uafs_rmdir(path));
}

/*
 * does a recursive rm to remove an entire directory tree (i.e. a fileset).
 * Supplied with the path to the root of the tree.
 */
static void
fb_uafs_recur_rm(char *path)
{
	usr_DIR* dirp;
	struct usr_dirent* dp;
	char cmd[2*MAXPATHLEN];

	dirp = uafs_opendir(path);
	while ((dp = uafs_readdir(dirp)) != NULL){
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		snprintf(cmd, sizeof(cmd), "%s/%s", path, dp->d_name);
		if (dp->d_ino % 2) {
			fb_uafs_recur_rm(cmd);
		} else {
			uafs_unlink(cmd);
		}
	}
	(void)uafs_closedir(dirp);
	return;
}

/*
 * Does a posix opendir(), Returns a directory handle on success,
 * NULL on failure.
 */
static DIR *
fb_uafs_opendir(char *path)
{
	return (uafs_opendir(path));
}

/*
 * Does a readdir() call. Returns a pointer to a table of directory
 * information on success, NULL on failure.
 */
static struct dirent *
fb_uafs_readdir(DIR *dirp)
{
	return (uafs_readdir(dirp));
}

/*
 * Does a closedir() call.
 */
static int
fb_uafs_closedir(DIR *dirp)
{
	return (uafs_closedir(dirp));
}

/*
 * Does an fstat of a file.
 */
static int
fb_uafs_fstat(fb_fdesc_t *fd, struct stat64 *statbufp)
{
	struct stat statbuf;
	int error = uafs_fstat(fd->fd_num, &statbuf);
	if (!error) {
		statbufp->st_dev = statbuf.st_dev;
		statbufp->st_rdev = statbuf.st_rdev;
		statbufp->st_size = statbuf.st_size;
		statbufp->st_blksize = statbuf.st_blksize;
		statbufp->st_blocks = statbuf.st_blocks;
		statbufp->st_ino = statbuf.st_ino;
		statbufp->st_mode = statbuf.st_mode;
		statbufp->st_nlink = statbuf.st_nlink;
		statbufp->st_uid = statbuf.st_uid;
		statbufp->st_gid = statbuf.st_gid;
		statbufp->st_atime = statbuf.st_atime;
		statbufp->st_ctime = statbuf.st_ctime;
		statbufp->st_mtime = statbuf.st_mtime;
		statbufp->st_ino = statbuf.st_ino;
	}
	return error;
}

/*
 * Does a stat of a file.
 */
static int
fb_uafs_stat(char *path, struct stat64 *statbufp)
{
	struct stat statbuf;
	int error = uafs_stat(path, &statbuf);
	if (!error) {
		statbufp->st_dev = statbuf.st_dev;
		statbufp->st_rdev = statbuf.st_rdev;
		statbufp->st_size = statbuf.st_size;
		statbufp->st_blksize = statbuf.st_blksize;
		statbufp->st_blocks = statbuf.st_blocks;
		statbufp->st_ino = statbuf.st_ino;
		statbufp->st_mode = statbuf.st_mode;
		statbufp->st_nlink = statbuf.st_nlink;
		statbufp->st_uid = statbuf.st_uid;
		statbufp->st_gid = statbuf.st_gid;
		statbufp->st_atime = statbuf.st_atime;
		statbufp->st_ctime = statbuf.st_ctime;
		statbufp->st_mtime = statbuf.st_mtime;
		statbufp->st_ino = statbuf.st_ino;
	}
	return error;
}

/*
 * Do a pwrite64 to a file.
 */
static int
fb_uafs_pwrite(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize, off64_t offset)
{
	return (uafs_pwrite(fd->fd_num, iobuf, iosize, (off_t)offset));
}

/*
 * Do a write to a file.
 */
static int
fb_uafs_write(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize)
{
	return (uafs_write(fd->fd_num, iobuf, iosize));
}

/*
 * Does a truncate operation and returns the result
 */
static int
fb_uafs_truncate(fb_fdesc_t *fd, off64_t fse_size)
{
	return (uafs_ftruncate(fd->fd_num, (off_t)fse_size));
}

/*
 * Does a link operation and returns the result
 */
static int
fb_uafs_link(const char *existing, const char *new)
{
	return (uafs_link(existing, new));
}

/*
 * Does a symlink operation and returns the result
 */
static int
fb_uafs_symlink(const char *existing, const char *new)
{
	return (uafs_symlink(existing, new));
}

/*
 * Does an access() check on a file.
 */
static int
fb_uafs_access(const char *path, int amode)
{
	return (uafs_access(path, amode));
}
