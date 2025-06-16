
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
#include <libgen.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <pwd.h>
#include <signal.h>
#include <getopt.h>

#include "hsencdef.h"
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
    hsprint(TO_EL, 3, "xmp_lseek='%s' off=%ld whence=%d", path, off, whence);
    return lseek(fi->fh, off, whence);
}

int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    int ret = 0;

    //hsprint(TO_EL, 9, "xmp_getattr '%s' st_size=%d", path, stbuf->st_size);
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 2, "xmp_getattr() cannot alloc for'%s'", path);
        return -errno;
        }
    //memset(stbuf, '\0', sizeof(struct stat));
    int res = lstat(path2, stbuf);
	if (res < 0)
        {
        //hsprint(TO_EL, 8, "xmp_getattr() cannot stat '%s'", path);
        ret = -errno;
        goto cleanup;
        }
    hsprint(TO_EL, 9, "xmp_getattr() '%s' st_size=%d", path, stbuf->st_size);
    hsprint(TO_EL, 9, "shadow: '%s' ", path2);

    // Do not process '/'
    #ifdef BYPASS
        // NOOP
    #else
    if(strlen(path) > 1)
        stbuf->st_size = get_sidelen(path);
    #endif

  cleanup:
    if(path2) xsfree(path2);

    hsprint(TO_EL, 9, "xmp_getattr xmalloc_bytes %d", xmalloc_bytes);
    //xmdump(0);

    return ret;
}

int xmp_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 2, "xmp_fgetattr() cannot alloc for'%s'", path);
        return -errno;
        }
    int res = fstat(fi->fh, stbuf);
	if (res < 0)
		return -errno;

    // This is untested, could be OK .. mimiking getattr
    #ifndef BYPASS
    //if(strlen(path) > 1)
    //    stbuf->st_size = get_sidelen(path);
    #endif

    hsprint(TO_EL, 9, "xmp_fgetattr() path='%s' st_size=%d", path, stbuf->st_size);

   cleanup:
    if(path2) xsfree(path2);

    return 0;
}

int     xmp_access(const char *path, int mask)
{
	int ret = 0;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_access() cannot alloc for'%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 5, "access() file: %s uid: %d", path, getuid());
	ret = access(path2, mask);
	if (ret < 0)
        {
        hsprint(TO_EL, 2, "Cannot access file: %s uid: %d", path, getuid());
        }
  cleanup:
    if(path2) xsfree(path2);

	return ret;
}

int xmp_readlink(const char *path, char *buf, size_t size)
{
    return -ENOSYS;

	int res;
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_readlink() cannot alloc for'%s'", path);
        return -errno;
        }
    res = readlink(path2, buf, size - 1);
	if (res < 0)
		return -errno;
	buf[res] = '\0';

  cleanup:
    if(path2) xsfree(path2);

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

	struct xmp_dirp *dd = xmalloc(sizeof(struct xmp_dirp));
	if (dd == NULL)
		return -ENOMEM;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_opendir() cannot alloc for'%s'", path);
        return -errno;
        }
	dd->dp = opendir(path2);
	if (dd->dp == NULL) {
		res = -errno;
		xsfree(dd);
		return res;
	}
	dd->offset = 0;
	dd->entry = NULL;

	fi->fh = (unsigned long) dd;

  cleanup:
    if(path2) xsfree(path2);

	return 0;
}

int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags ff)
{
	struct xmp_dirp *d = get_dirp(fi);

    if(strlen(path) > 1)
        hsprint(TO_EL, 6, "xmp_readdir() '%s'", path);

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
            // Hide our files from main list
            if(is_our_file(d->entry->d_name, TRUE))
                {
                //hsprint(TO_EL, 1, "List skipping: '%s'", d->entry->d_name);
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
	xsfree(d);
	return 0;
}

int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_mknod() cannot alloc for'%s'", path);
        return -errno;
        }

	if (S_ISFIFO(mode))
		res = mkfifo(path2, mode);
	else
		res = mknod(path2, mode, rdev);
	if (res < 0)
		return -errno;

   cleanup:
    if(path2) xsfree(path2);

    return 0;
}

int xmp_mkdir(const char *path, mode_t mode)

{
	int ret = 0;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_mkdir() cannot alloc for'%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 3, "mkdir dir: %s mode: %o", path, mode);
	ret = mkdir(path2, mode | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP);
	if (ret < 0)
        {
		hsprint(TO_EL, 2, "Cannot mkdir '%s' mode: %o", path, mode);
        ret = -errno;
        }
  cleanup:
    if(path2) xsfree(path2);

	return ret;
}

int xmp_unlink(const char *path)
{
	int res = 0;

    if(is_our_file(path, FALSE))
        {
        hsprint(TO_EL, 2, "No deletion of myfiles allowed: '%s'", path);
        errno = EACCES;
        return -EACCES;
        }
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_unlink() cannot alloc for'%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 4, "unlink() '%s' uid: %d", path, getuid());
	res = unlink(path2);
	if (res < 0)
        {
        hsprint(TO_EL, 2, "Error on Unlinking: '%s' errno: %d", path, errno);
		//return -errno;
        }

    // Also unlink the sideblock
    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
        hsprint(TO_EL, 9, "Removing sideblock file: %s", ptmp2);
        int ret2 = unlink(ptmp2);
        if(ret2 < 0)
                hsprint(TO_EL, 1, "Cannot unlink sideblock file: %s errno %d",
                             ptmp2, errno);
        xsfree(ptmp2);
        }
  cleanup:
    if(path2) xsfree(path2);

	return res;
}

int xmp_rmdir(const char *path)
{
	int res = 0;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_rmdir() cannot alloc for'%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 3, "removing dir: %s uid: %d", path, getuid());
	res = rmdir(path2);
	if (res < 0)
        {
        hsprint(TO_EL, 2, "Cannot remove dir: '%s' errno=%d", path2, errno);
		//return -errno;
        }
    // ?? Also remove all side items
    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
        hsprint(TO_EL, 9, "Remove sideblock file: %s", ptmp2);
        int ret2 = unlink(ptmp2);
        if(ret2 < 0)
                hsprint(TO_EL, 2, "Cannot unlink sideblock file: %s",
                            ptmp2, errno);
        xsfree(ptmp2);
        }
    hsprint(TO_EL, 7, "removed dir: %s uid: %d", path, getuid());

  cleanup:
    if(path2) xsfree(path2);

	return res;
}

//# Symlink is not implemented in the encrypted file system
// We disabled symlink, as it confused the dataroot.
// Remember, we link to dataroot as an intercept.

int xmp_symlink(const char *from, const char *to)
{
	int res;
    hsprint(TO_EL, 2, "symlink disabled: %s -> %s", from, to);
    return -ENOSYS;

    // TODO symlink between file systems

    char  path2[PATH_MAX] ;
    memset(path2, '\0', PATH_MAX);
    strcpy(path2, mountsecret); strcat(path2, from);
    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);
    hsprint(TO_EL, 9, "symlink file: %s -> %s", path2, path3);
	//res = symlink(from, path3);
	//res = symlink(path2, path3);
	res = symlink(from, to);
	if (res < 0)
		return -errno;

	return res;
}

//
// Here we assume that rename is on the same file system
//

int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

    char  *path2 = alloc_path2(from);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_rename() cannot alloc for '%s'", from);
        return -errno;
        }
    char  *path3 = alloc_path2(to);
    if(path2 == NULL)
        {
        xsfree(path2);
        hsprint(TO_EL, 1, "xmp_rename() cannot alloc for '%s'", to);
        return -errno;
        }
    hsprint(TO_EL, 2, "rename file from: %s to %s", from, to);
    char *ptmp2 = NULL, *ptmp3 = NULL;
    ptmp2 = get_sidename(from);
    if(!ptmp2)
        {
        hsprint(TO_EL, 1, "Error on malloc sideblock");
        res = -errno;
        goto cleanup;
        }
    ptmp3 = get_sidename(to);
    if(!ptmp3)
        {
        hsprint(TO_EL, 1, "Error on malloc sideblock");
        res = -errno;
        goto cleanup;
        }
    res = rename(path2, path3);
	if (res < 0)
        {
        res = -errno;
        }
    hsprint(TO_EL, 9, "Rename sideblock file1: %s %s", ptmp2, ptmp3);
    rename(ptmp2, ptmp3);

  cleanup:
    if(ptmp2) xsfree(ptmp2);
    if(ptmp3) xsfree(ptmp3);
    if(path2) xsfree(path2);
    if(path3) xsfree(path3);

	return res;
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
  cleanup:
    if(path2) xsfree(path2);

	return 0;
}

int xmp_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res = 0;
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_chmod() cannot alloc for '%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 3, "chmod file: %s uid: %d mode: %o", path, getuid(), mode);
	res = chmod(path2, mode);
	if (res < 0)
		res = -errno;
  cleanup:
    if(path2) xsfree(path2);
	return res;
}

int xmp_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	int res = 0;
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_chown() cannot alloc for '%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 4, "chown file: '%s' touid: %d togid %d",
                                    path, uid, gid);
	res = lchown(path2, uid, gid);
	if (res < 0)
		res =  -errno;
 cleanup:
    if(path2) xsfree(path2);
    return res;
}

int xmp_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res = 0;
    if(is_our_file(path, FALSE))
        {
        hsprint(TO_EL, 1, "No trancation of myfiles allowed: '%s'", path);
        errno = EACCES;
        return -EACCES;
        }
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_truncate() cannot alloc for '%s'", path);
        return -errno;
        }
    hsprint(TO_EL, 3, "truncate() '%s' size=%ld", path, size);
    // Kill sideblock too
    create_sideblock(path);
	res = truncate(path2, size);
	if (res < 0)
		res = -errno;
	return res;
}

int xmp_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res = 0;

	off_t fsize = get_fsize(fi->fh);

    hsprint(TO_EL, 5, "ftruncate() '%s' size %ld fsize=%ld",
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
        hsprint(TO_EL, 6, "ftruncate fill: size=%ld fsize=%ld", size, fsize);

        // Create a buffer suitable for encrypting / writing
        int fill =  size - fsize;
        int beg =  (fsize / HS_BLOCK) * HS_BLOCK;
        int span = beg + fill;
        int end =  (span / HS_BLOCK) * HS_BLOCK;
        if(span %  HS_BLOCK)
            end += HS_BLOCK;
        int total = end - beg;
        char *mem = xmalloc(total);
        if(!mem)
            {
            hsprint(TO_EL, 1, "fTruncate fill: no memory");
            return -ENOMEM;
            }
        memset(mem, 0, total);

        // Encryption / decryption by block size
        hs_encrypt(mem, total, defpassx, sizeof(defpassx));

        int ret2 = pwrite(fi->fh, mem, fill, fsize);
        if(!ret2)
            {
            hsprint(TO_EL, 1, "ftruncate fill: cannot fill");
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

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_utimens() cannot alloc for'%s'", path);
        return -errno;
        }
    (void) fi;
    int res = 0;
    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, path2, ts, AT_SYMLINK_NOFOLLOW);
    if (res < 0)
            res = -errno;
  cleanup:
    if(path2) xsfree(path2);

    return res;

	//res = utimes(path2, tv);
	//if (res < 0)
	//	return -errno;
	//return 0;
}

int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res = 0;

    hsprint(TO_EL, 2, "create(): '%s' mode: %o", path, mode);
    hsprint(TO_EL, 5, "create(): '%s' flags: %o", path, fi->flags);

    if(is_our_file(path, FALSE))
        {
        hsprint(TO_EL, 1, "No operation of myfiles allowed: '%s'", path);

        errno = EACCES;
        return -EACCES;
        }
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "Cannot alloc path2 on: '%s'", path);
        return -errno;
        }
    //hsprint(TO_EL, 9, "shadow file: '%s'", path2);
    if(gotdefpass == 0)
        {
        hsprint(TO_EL, 9, "Empty pass on create file: %s uid: %d", path, getuid());
        int retp = openpass(path);
        if (retp)
            {
            //errno = EACCES;
            //res = -EACCES;
            errno = EKEYREJECTED;
            res = -EKEYREJECTED;
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
        hsprint(TO_EL, 2, "Cannot create file '%s' mode=%o errno=%d retry ...",
                        path, mode2, errno);
        }
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    int res2 = fstat(fi->fh, &stbuf);
    if(res2 < 0)
        {
        hsprint(TO_EL, 1, "Cannot stat newly created file '%s'", path);
        goto cleanup;
        }
    hsprint(TO_EL, 9, "file size: %d", stbuf.st_size);
    if(flags2 & O_TRUNC)
        {
        hsprint(TO_EL, 3, "truncating '%s' fh=%ld", path, fi->fh);
        int ret2 = ftruncate(fi->fh, 0);
        }
    hsprint(TO_EL, 9, "created: '%s' fh=%d mode=%o", path, fi->fh, mode);
    //hsprint(TO_EL, 9, "Inode: %lud blocksize %ld ",
    //                                stbuf.st_ino, stbuf.st_blksize);
    create_sideblock(path);
  cleanup:
    if(path2) xsfree(path2);
	return res;
}

int     xmp_open(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_open() cannot alloc for'%s'", path);
        return -errno;
        }
    //hsprint(TO_EL, 2, "open() '%s' flags: %o",  path, fi->flags);
    hsprint(TO_EL, 2, "open() '%s' flags: %o",  path, fi->flags);

    hsprint(TO_EL, 9, "shadow: '%s'",  path2);
    if(defpassx[0] == 0)
        {
        hsprint(TO_EL, 9, "Empty pass on open file: %s uid: %d", path, getuid());
        int ret = openpass(path);
        //hsprint(TO_EL, 1, "Open pass got %d", ret);
        if (ret)
            {
            //errno = EACCES;
            //return -EACCES;
            errno = EKEYREJECTED;
            return -EKEYREJECTED;
            }
        }
    int mode2 = (S_IRUSR | S_IWUSR | S_IRGRP);
    int addy =  O_RDWR;
    int suby = ~(O_EXCL | O_WRONLY | O_APPEND) ;
    int flags2 = (fi->flags | addy) & suby;
    fi->fh = open(path2, flags2, mode2);
    if (fi->fh < 0)
        {
        hsprint(TO_EL, 1, "Error on open file, trying org perm. errno=%d", errno);
        ret = -errno;
        goto cleanup;
        }
    //struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    //int res2 = fstat(fi->fh, &stbuf);
    //if(res2 < 0)
    //    {
    //    hsprint(TO_EL, 1, "Cannot stat opened file '%s'", path);
    //    goto cleanup;
    //    }
    //hsprint(TO_EL, 3, "File size: %d", stbuf.st_size);

    // Create flag set?
    if(fi->flags & O_TRUNC)
        {
        hsprint(TO_EL, 8, "truncating '%s' fh=%ld", path, fi->fh);
        int ret2 = ftruncate(fi->fh, 0);
        create_sideblock(path);
        }
    // Append flag set?
    if(fi->flags & O_APPEND)
        {
        hsprint(TO_EL, 8, "appending '%s' fh=%ld", path, fi->fh);
        hsprint(TO_EL, 9, "Current real size: %ls", path, fi->fh);

        int fsize = get_sidelen(path);
        int res3 = lseek(fi->fh, fsize, SEEK_SET);
        hsprint(TO_EL, 9, "Current pos=%ld", res3);
        }
    hsprint(TO_EL, 8, "opened '%s' fh=%ld", path, fi->fh);
  cleanup:
    if(path2) xsfree(path2);
        ;
	return ret;
}

int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res = 0;
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_statfs() cannot alloc for'%s'", path);
        return -errno;
        }

    if(strlen(path) > 1)
        hsprint(TO_EL, 3, "statfs(): %s uid: %d", path, getuid());
	res = statvfs(path2, stbuf);

    if (res < 0)
		res = -errno;
cleanup:
    if(path2) xsfree(path2);
  	return res;
}

int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	int res = 0;

    hsprint(TO_EL, 9, "Flushing file: %s fh=%d", path, fi->fh);

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

    //hsprint(TO_EL, 9, "Flushing %d", fi->fh);
    res = fsync(fi->fh);
    if (res < 0)
        {
        hsprint(TO_EL, 1, "Flushing failed on %d", fi->fh);
    	return -errno;
        }
    //hsprint(TO_EL, 9, "Flushed file: %s fh: %ld", path, fi->fh);
	return 0;
}

int xmp_release(const char *path, struct fuse_file_info *fi)

{
    int res = 0;

    hsprint(TO_EL, 5, "release() '%s' fh: %ld", path, fi->fh);
	(void) path;
	int rret =  close(fi->fh);
    hsprint(TO_EL, 9, "Released: '%s' fh: %ld rret=%d", path, fi->fh, rret);

    // Show if this file leaked memory
    //hsprint(TO_EL, 3, "xmalloc_bytes %d", xmalloc_bytes);
    //xmdump(0);

    return res;
}

int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	int ret = 0;

    hsprint(TO_EL, 9, "xmp_fsync() '%s'", path);

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
        hsprint(TO_EL, 3, "Fsync error '%s' fh: %ld err=%d",
                     path, fi->fh, ret);
		ret = -errno;
        }
	return ret;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    int res = 0;
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_setxattr() cannot alloc for'%s'", path);
        return -errno;
        }
	res = lsetxattr(path2, name, value, size, flags);
	if (res < 0)
		 res = -errno;
  cleanup:
    if(path2) xsfree(path2);
	return res;
}

int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_getxattr() cannot alloc for'%s'", path);
        return -errno;
        }
	int res = lgetxattr(path2, name, value, size);
	if (res < 0)
		res = -errno;
  cleanup:
    if(path2) xsfree(path2);

	return res;
}

int xmp_listxattr(const char *path, char *list, size_t size)
{
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_listxattr() cannot alloc for'%s'", path);
        return -errno;
        }
	int res = llistxattr(path3, list, size);
	if (res < 0)
		res = -errno;
  cleanup:
    if(path2) xsfree(path2);
	return res;
}

int xmp_removexattr(const char *path, const char *name)
{
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_removexattr() cannot alloc for'%s'", path);
        return -errno;
        }
	int res = lremovexattr(path2, name);
	if (res < 0)
		res = -errno;
  cleanup:
    if(path2) xsfree(path2);
	return res;
}
#endif /* HAVE_SETXATTR */

int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock)
{
    // TODO
    char  *path2 = alloc_path2(path);
    if(path2 == NULL)
        {
        hsprint(TO_EL, 1, "xmp_lock() cannot alloc for'%s'", path);
        return -errno;
        }
    int ret = 0;
    //ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
	//		   sizeof(fi->lock_owner));
    //hsprint(TO_EL, 3, "xmp_lock='%s' cmd=%ld fh=%ld type=%d",
    //                            path, cmd, fi->fh, lock->l_type);

  cleanup:
    if(path2) xsfree(path2);

  return ret;
}

// EOF