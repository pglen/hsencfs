
/* =====[ hsencfs.sess ]========================================================

   File Name:       hsencop.c

   Description:     Functions for hsencop.c

   Revisions:

      REV   DATE                BY              DESCRIPTION
      ----  -----------         ----------      --------------------------
      0.00  Tue 10.May.2022     Peter Glen      Initial version.
      0.00  Tue 10.May.2022     Peter Glen      File locking disabled

   ======================================================================= */

// The actual file operations

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>

#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <pwd.h>
#include <signal.h>
#include <getopt.h>

#include "hsencfs.h"
#include "hsutils.h"
#include "base64.h"
#include "xmalloc.h"
#include "hspass.h"
#include "hsencsb.h"
#include "bluepoint2.h"
#include "hsencop.h"

#include "hs_crypt.h"
#include "hsencop.h"

#pragma GCC diagnostic ignored "-Wformat-truncation"

void *xmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

off_t xmp_lseek(const char *path,  off_t off, int whence, struct fuse_file_info *fi)
{
    hslog(2, "xmp_lseek='%s' off=%ld whence=%d\n", path, off, whence);
    return lseek(fi->fh, off, whence);
}

int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    int ret = 0;

    char  *path2 = malloc(PATH_MAX) ;
    if(path2 == NULL)
        {
        hslog(1, "xmp_getattr() cannot alloc for'%s'", path);
        return -errno;
        }
    memset(path2, '\0', PATH_MAX);
    strcpy(path2, mountsecret); strcat(path2, path);
	int res = lstat(path2, stbuf);
	if (res < 0)
        {
        ret = -errno;
        goto cleanup;
        }
    hslog(9, "xmp_getattr.org='%s' st_size=%d\n", path, stbuf->st_size);

    // Do not process '/'
    #ifndef BYPASS
    if(strlen(path) > 1)
        stbuf->st_size = get_sidelen(path);
    #endif
   cleanup:
    if(path2) free(path2);
    return ret;
}

int xmp_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    char  *path2 = malloc(PATH_MAX) ;
    if(path2 == NULL)
        {
        hslog(1, "xmp_fgetattr() cannot alloc for'%s'", path);
        return -errno;
        }
    memset(path2, '\0', PATH_MAX);
    strcpy(path2, mountsecret); strcat(path2, path);
	int res = fstat(fi->fh, stbuf);
	if (res < 0)
		return -errno;

    // This is untested, could be OK .. mimiking getattr
    #ifndef BYPASS
    //if(strlen(path) > 1)
    //    stbuf->st_size = get_sidelen(path);
    #endif

    hslog(2, "xmp_fgetattr() path='%s' st_size=%d\n", path, stbuf->st_size);

   cleanup:
    if(path2) free(path2);

    return 0;
}

int xmp_access(const char *path, int mask)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    //    hslog(1, "Get access, file: %s uid: %d\n", path, getuid());

	res = access(path2, mask);

	if (res < 0)
        {
            hslog(1, "Cannot access file: %s uid: %d\n", path, getuid());
		//return -errno;
        }

	return 0;
}

int xmp_readlink(const char *path, char *buf, size_t size)
{
    return -ENOSYS;

	int res;
	char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    res = readlink(path2, buf, size - 1);
	if (res < 0)
		return -errno;

	buf[res] = '\0';
	return 0;
}

struct xmp_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

int xmp_opendir(const char *path, struct fuse_file_info *fi)

{
	int res = 0;

    //  hslog(LOG_DEBUG, "xmp_opendir='%s'\n", path);

	struct xmp_dirp *dd = malloc(sizeof(struct xmp_dirp));
	if (dd == NULL)
		return -ENOMEM;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	dd->dp = opendir(path2);
	if (dd->dp == NULL) {
		res = -errno;
		free(dd);
		return res;
	}
	dd->offset = 0;
	dd->entry = NULL;

	fi->fh = (unsigned long) dd;
	return 0;
}

int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags ff)
{
	struct xmp_dirp *d = get_dirp(fi);

    if (loglevel > 9)
        {
        syslog(LOG_DEBUG, "xmp_readdir='%s'\n", path);
        }
	(void) path;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		struct stat st;
		off_t nextoff;

		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry)
				break;
		}

        memset(&st, 0, sizeof(st));
    	st.st_ino = d->entry->d_ino;
    	st.st_mode = d->entry->d_type << 12;
    	nextoff = telldir(d->dp);
        if(d->entry)
            {
            //syslog(LOG_DEBUG, "gotdirent '%s'\n", d->entry->d_name);
            // Hide our files from main list
            if(is_our_file(d->entry->d_name, TRUE))
                {
                //syslog(LOG_DEBUG, "List skipping: '%s'\n", d->entry->d_name);
            	d->entry = NULL;
            	d->offset = nextoff;
                continue;
                }
            }

    	if (filler(buf, d->entry->d_name, &st, nextoff, FUSE_FILL_DIR_PLUS))
            {
            break;
            }
    	d->entry = NULL;
    	d->offset = nextoff;
	}
	return 0;
}

int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct xmp_dirp *d = get_dirp(fi);
	(void) path;

	closedir(d->dp);
	free(d);
	return 0;
}

int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	if (S_ISFIFO(mode))
		res = mkfifo(path2, mode);
	else
		res = mknod(path2, mode, rdev);
	if (res < 0)
		return -errno;

	return 0;
}

int xmp_mkdir(const char *path, mode_t mode)

{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    hslog(1, "Mkdir dir: %s mode: %o\n", path, mode);

	res = mkdir(path2, mode | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP);

	if (res < 0)
		return -errno;

	return 0;
}

int xmp_unlink(const char *path)
{
	int res = 0;

    if(is_our_file(path, FALSE))
        {
            hslog(1, "No deletion of myfiles allowed: '%s'\n", path);

        errno = EACCES;
        return -EACCES;
        }

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    //    hslog(1, "Unlinking file '%s' uid: %d\n", path, getuid());

	res = unlink(path2);
	if (res < 0)
        {
        hslog(1, "Error on Unlinking: '%s' errno: %d\n", path, errno);
		return -errno;
        }

    // Also unlink the .sideblock
    // Reassemble with dot path

    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
            hslog(1, "RM sb file: %s\n", ptmp2);

        int ret2 = unlink(ptmp2);
        if(ret2 < 0)
                hslog(1,
                    "Cannot unlink sideblock file: %s errno %d\n", ptmp2, errno);

        free(ptmp2);
        }
	return 0;
}

int xmp_rmdir(const char *path)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

        hslog(1, "Removing dir: %s uid: %d\n", path, getuid());

	res = rmdir(path2);
	if (res < 0)
        {
            hslog(1, "Cannot remove dir: '%s' errno=%d\n", path2, errno);

		return -errno;
        }

    // ?? Also remove all side items
    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
            hslog(1, "RM sb file: %s\n", ptmp2);

        int ret2 = unlink(ptmp2);
        if(ret2 < 0)
                hslog(1,
                    "Cannot unlink sideblock file: %s errno %d\n", ptmp2, errno);

        free(ptmp2);
        }

        hslog(1, "Removed dir: %s uid: %d\n", path, getuid());

	return 0;
}

//# Symlink is not implemented in the encrypted file system
// We disabled symlink, as it confused the dataroot. Remember we link
// to dataroot as an intercept.
// Re-enabled symlink ... wtf

int xmp_symlink(const char *from, const char *to)
{
	int res;

    return -ENOSYS;

        hslog(1, "Symlink parms: %s -> %s\n", from, to);

    // TODO symlink between file systems

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

        hslog(1, "Symlink file: %s -> %s\n", path2, path3);

	//res = symlink(from, path3);
	//res = symlink(path2, path3);
	res = symlink(from, to);

	if (res < 0)
		return -errno;

	return 0;
}

//
// Here we assume that rename is on the same file system
//

int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

        hslog(1, "Renamed file: %s to %s uid: %d\n", from, to, getuid());

    char *ptmp2 = get_sidename(from);
    if(!ptmp2)
        {
            hslog(1, "Error on malloc sideblock file2\n");
        return -errno;
        }
    char *ptmp3 = get_sidename(to);
    if(!ptmp3)
        {
            hslog(1, "Error on malloc sideblock file3\n");

        free(ptmp2);
        return -errno;
        }

        hslog(1, "Rename sideblock file1: %s\n", ptmp2);

    rename(ptmp2, ptmp3);
    free(ptmp2), free(ptmp3);

	res = rename(path2, path3);

	//res = rename(from, to);
	if (res < 0)
		return -errno;

	return 0;
}

// We disabled link, as it confused the dataroot. Remember we link to dataroot
// as an intercept.

int xmp_link(const char *from, const char *to)
{
	int res;

    return -ENOSYS;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

	res = link(path2, path3);
	//res = link(from, to);
	if (res < 0)
		return -errno;

	return 0;
}

int xmp_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    hslog(1, "Chmod file: %s uid: %d mode: %o", path, getuid(), mode);

	res = chmod(path2, mode);

	if (res < 0)
		return -errno;

	return 0;
}

int xmp_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

        hslog(1, "Chown file: %s uid: %d touid: %d togid %d\n",
                path, getuid(), uid, gid);

	res = lchown(path2, uid, gid);
	if (res < 0)
		return -errno;

	return 0;
}

int xmp_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res;

    if(is_our_file(path, FALSE))
        {
            hslog(1, "No trancation of myfiles allowed: '%s'\n", path);
        errno = EACCES;
        return -EACCES;
        }

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

        hslog(1, "Truncated file: %s size=%ld\n", path, size);

    // Kill sideblock too
    create_sideblock(path);

	res = truncate(path2, size);
	if (res < 0)
		return -errno;

	return 0;
}

int xmp_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res = 0;

	off_t fsize = get_fsize(fi->fh);

        hslog(1, "fTruncated file: %s size %ld fsize=%ld\n",
                                                path, size, fsize);

    // Kill sideblock too
    create_sideblock(path);

	res = ftruncate(fi->fh, size);
	if (res < 0)
		return -errno;

    #if 0
    // Fill in zeros
    if (size > fsize)
        {
            hslog(1, "fTruncate fill: size=%ld fsize=%ld\n", size, fsize);

        // Create a buffer suitable for encrypting / writing
        int fill =  size - fsize;
        int beg =  (fsize / HS_BLOCK) * HS_BLOCK;
        int span = beg + fill;
        int end =  (span / HS_BLOCK) * HS_BLOCK;
        if(span %  HS_BLOCK)
            end += HS_BLOCK;
        int total = end - beg;
        char *mem = malloc(total);
        if(!mem)
            {
                hslog(1, "fTruncate fill: no memory\n");
            return -ENOMEM;
            }
        memset(mem, 0, total);

        // Encryption / decryption by block size
        hs_encrypt(mem, total, defpassx, defplen);

        int ret2 = pwrite(fi->fh, mem, fill, fsize);
        if(!ret2)
            {
                hslog(1, "fTruncate fill: cannot fill\n");
            return -errno;
            }
        //write_sideblock(path, mem + total - HS_BLOCK, HS_BLOCK);
        }
    #endif

	return res;
}

int xmp_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
	//int res;
	//struct timeval tv[2];
    //
	//tv[0].tv_sec = ts[0].tv_sec;
	//tv[0].tv_usec = ts[0].tv_nsec / 1000;
	//tv[1].tv_sec = ts[1].tv_sec;
	//tv[1].tv_usec = ts[1].tv_nsec / 1000;
    //

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    (void) fi;
    int res;
    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, path2, ts, AT_SYMLINK_NOFOLLOW);
    if (res < 0)
            return -errno;
    return 0;

	//res = utimes(path2, tv);
	//if (res < 0)
	//	return -errno;
	//return 0;
}

int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res = 0;

    hslog(1, "Create: '%s' mode: %o flags: %o\n", path, mode, fi->flags);

    if(is_our_file(path, FALSE))
        {
        hslog(1, "No operation of myfiles allowed: '%s'\n", path);

        errno = EACCES;
        return -EACCES;
        }
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hslog(1, "Cannot alloc path2 on: '%s'\n", path);
        return -errno;
        }
    hslog(2, "Shadow file: '%s'\n", path2);

    if(defpassx[0] == 0)
        {
        hslog(1, "Empty pass on create file: %s uid: %d\n", path, getuid());
        int retp = openpass(path);
        if (retp)
            {
            errno = EACCES;
            res = -EACCES;
            goto cleanup;
            }
        }
    // Patch new flag as we always read back Sun 08.May.2022
    int mode2 = mode | (S_IRUSR | S_IWUSR | S_IRGRP);
    int addy =  O_CREAT | O_TRUNC | O_RDWR;
    int suby = ~(O_EXCL | O_WRONLY | O_EXCL) ;
    int flags2 = (fi->flags | addy) & suby;
    fi->fh = open(path2, flags2, mode2);
	if (fi->fh < 0)
        {
        hslog(1, "Cannot create file '%s' mode=%o errno=%d retry ...\n",
                        path, mode2, errno);
        }
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    int res2 = fstat(fi->fh, &stbuf);
    if(res2 < 0)
        {
        hslog(1, "Cannot stat newly created file '%s'\n", path);
        goto cleanup;
        }

    hslog(3, "File size: %d\n", stbuf.st_size);

    if(flags2 & O_TRUNC)
        {
        hslog(1, "Truncating '%s' fh=%ld\n", path, fi->fh);
        int ret2 = ftruncate(fi->fh, 0);

        }
    hslog(3, "Created: '%s' fh=%d mode=%o\n", path, fi->fh, mode);
    //hslog(9, "Inode: %lud blocksize %ld \n",
    //                                stbuf.st_ino, stbuf.st_blksize);

    create_sideblock(path);
  cleanup:
        if(path2) free(path2);
	return res;
}

int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

    // Needed by the decrypt command line util
    //if(is_our_file(path, FALSE))
    //    {
    //    syslog(LOG_DEBUG, "No operation on myfiles allowed: '%s'\n", path);
    //    return -EACCES;
    //    }

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

    hslog(1, "Open: '%s' uid: %d flags: %o\n",  path, getuid(),fi->flags);
    hslog(1, "Shadow: '%s' '%s' plen=%d",  path2, defpassx, defplen);
    if(defpassx[0] == 0)
        {
        hslog(LOG_DEBUG, "Empty pass on open file: %s uid: %d\n", path, getuid());
        int ret = openpass(path);
        if (ret)
            {
            errno = EACCES;
            return -EACCES;
            }
        }
    int mode2 = (S_IRUSR | S_IWUSR | S_IRGRP);
    int addy =  O_RDWR;
    int suby = ~(O_EXCL | O_WRONLY | O_APPEND) ;
    int flags2 = (fi->flags | addy) & suby;
    fi->fh = open(path2, flags2, mode2);
    if (fi->fh < 0)
        {
        hslog(1, "Error on open file, trying org perm. errno=%d\n", errno);
        return -errno;
        }
    //struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    //int res2 = fstat(fi->fh, &stbuf);
    //if(res2 < 0)
    //    {
    //    hslog(1, "Cannot stat opened file '%s'\n", path);
    //    goto cleanup;
    //    }
    //hslog(3, "File size: %d\n", stbuf.st_size);

    // Create flag set?
    if(fi->flags & O_TRUNC)
        {
        hslog(3, "Truncating '%s' fh=%ld\n", path, fi->fh);
        int ret2 = ftruncate(fi->fh, 0);
        create_sideblock(path);
        }
    // Append flag set?
    if(fi->flags & O_APPEND)
        {
        hslog(3, "Appending '%s' fh=%ld\n", path, fi->fh);
        hslog(3, "Current real size: %ls\n", path, fi->fh);

        int fsize = get_sidelen(path);
        int res3 = lseek(fi->fh, fsize, SEEK_SET);
        hslog(3, "Current pos=%ld\n", res3);
        }
    hslog(3, "Opened '%s' fh=%ld\n", path, fi->fh);
    //struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    //int res = fstat(fi->fh, &stbuf);
    //    hslog(1, "Inode: %lud\n", stbuf.st_ino);
    cleanup:
        ;
	return ret;
}

int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

        hslog(1, "Stat file: %s uid: %d\n", path, getuid());

	res = statvfs(path2, stbuf);
	if (res < 0)
		return -errno;

	return 0;
}

int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	int res = 0;

    hslog(9, "Flushing file: %s fh=%d\n", path, fi->fh);

	(void) path;
	/* This is called from every close on an open file, so call the
	   close on the underlying filesystem.	But since flush may be
	   called multiple times for an open file, this must not really
	   close the file.  This is important if used on a network
	   filesystem like NFS which flush the data/metadata on close() */

    // try until error
    //for (int aa = 0; aa < 10; aa++)
    //    {
    //    res = syncfs(fi->fh);
    //    if (res < 0)
    //        break;
    //    }
    //res = 0;

    //hslog(9, "Flushing %d", fi->fh);
    res = fsync(fi->fh);
    if (res < 0)
        {
        hslog(1, "Flushing failed on %d", fi->fh);
    	return -errno;
        }

    //res = close(dup(fi->fh));
    //if (res < 0)
    //   return -errno;

    hslog(9, "Flushed file: %s fh: %ld\n", path, fi->fh);

	return 0;
}

int xmp_release(const char *path, struct fuse_file_info *fi)

{
    int res = 0;

    hslog(3, "Releasing: '%s' fh: %ld\n", path, fi->fh);
	(void) path;
	int rret =  close(fi->fh);
    hslog(9, "Released: '%s' fh: %ld rret=%d\n", path, fi->fh, rret);
	return res;
}

int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	int ret = 0;

    hslog(1, "xmp_fsync() '%s'", path);

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		ret = fdatasync(fi->fh);
	else
#endif
    ret = fsync(fi->fh);
	if (ret < 0)
        {
        hslog(1, "Fsync error '%s' fh: %ld err=%d\n",
                     path, fi->fh, ret);
		ret = -errno;
        }
	return ret;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lsetxattr(path2, name, value, size, flags);
	if (res < 0)
		return -errno;
	return 0;
}

int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lgetxattr(path2, name, value, size);
	if (res < 0)
		return -errno;
	return res;
}

int xmp_listxattr(const char *path, char *list, size_t size)
{
    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	int res = llistxattr(path3, list, size);
	if (res < 0)
		return -errno;
	return res;
}

int xmp_removexattr(const char *path, const char *name)
{
    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);

    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lremovexattr(path2, name);
	if (res < 0)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock)
{
	(void) path;
    int ret = 0;
    //ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
	//		   sizeof(fi->lock_owner));
    hslog(3, "xmp_lock='%s' cmd=%ld fh=%ld type=%d\n",
                                path, cmd, fi->fh, lock->l_type);
	return ret;
}

// EOF