// The actual file operations

#pragma GCC diagnostic ignored "-Wformat-truncation"

static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
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

static inline struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static off_t xmp_lseek(const char *path,  off_t off, int whence, struct fuse_file_info *fi)
{
    hslog(2, "xmp_lseek='%s' off=%ld whence=%d\n", path, off, whence);
    return lseek(fi->fh, off, whence);
}

static int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);
	res = lstat(path2, stbuf);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_fgetattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	int res;
	(void) path;
	res = fstat(fi->fh, stbuf);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Get access, file: %s uid: %d\n", path, getuid());

	res = access(path2, mask);

	if (res == -1)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "Cannot access file: %s uid: %d\n", path, getuid());
		//return -errno;
        }

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    res = readlink(path2, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

struct xmp_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;

    //if (loglevel > 3)
    //    {
    //    syslog(LOG_DEBUG, "xmp_opendir='%s'\n", path);
    //    }

	struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
	if (d == NULL)
		return -ENOMEM;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);


	d->dp = opendir(path2);
	if (d->dp == NULL) {
		res = -errno;
		free(d);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long) d;
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags ff)
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
    if (loglevel > 3)
        {

        }
	return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct xmp_dirp *d = get_dirp(fi);
	(void) path;

	closedir(d->dp);
	free(d);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	if (S_ISFIFO(mode))
		res = mkfifo(path2, mode);
	else
		res = mknod(path2, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Mkdir dir: %s uid: %d\n", path, getuid());

	res = mkdir(path2, mode | S_IRUSR | S_IWUSR |  S_IRGRP);

	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

    if(is_our_file(path, FALSE))
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "No deletion of myfiles allowed: '%s'\n", path);

        errno = EACCES;
        return -EACCES;
        }

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Unlinking file: %s uid: %d\n", path, getuid());

	res = unlink(path2);
	if (res == -1)
		return -errno;

    // Also unlink the .sideblock
    // Reassemble with dot path

    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "Unlinking sideblock file: %s\n", ptmp2);

        int ret2 = unlink(ptmp2);
        if(ret2 < 0)
            if (loglevel > 3)
                syslog(LOG_DEBUG,
                    "Cannot unlink sideblock file: %s errno %d\n", ptmp2, errno);

        free(ptmp2);
        }
	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Removing dir: %s uid: %d\n", path, getuid());

    // ?? Also remove all secret tiles

	res = rmdir(path2);
	if (res == -1)
		return -errno;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Removed dir: %s uid: %d\n", path, getuid());

	return 0;
}

//# Symlink is not implemented in the encrypted file system
// We disabled symlink, as it confused the dataroot. Remember we link
// to dataroot as an intercept.
// Re-enabled symlink ... wtf

static int xmp_symlink(const char *from, const char *to)
{
	int res;

    //return -ENOSYS;

    if (loglevel > 1)
        syslog(LOG_DEBUG, "Symlink parms: %s -> %s\n", from, to);

    // TODO symlink between file systems

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

    if (loglevel > 1)
        syslog(LOG_DEBUG, "Symlink file: %s -> %s\n", path2, path3);

	res = symlink(from, path3);
	//res = symlink(path2, path3);
	//res = symlink(from, to);

	if (res == -1)
		return -errno;

	return 0;
}

//
// Here we assume that rename is on the same file system
//

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Renamed file: %s to %s uid: %d\n", from, to, getuid());

    char *ptmp2 = get_sidename(from);
    if(!ptmp2)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Error on malloc sideblock file2\n");
        return -errno;
        }
    char *ptmp3 = get_sidename(to);
    if(!ptmp3)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Error on malloc sideblock file3\n");

        free(ptmp2);
        return -errno;
        }

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Rename sideblock file1: %s\n", ptmp2);

    rename(ptmp2, ptmp3);
    free(ptmp2), free(ptmp3);

	res = rename(path2, path3);

	//res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

// We disabled link, as it confused the dataroot. Remember we link to dataroot
// as an intercept.

static int xmp_link(const char *from, const char *to)
{
	int res;

    return -ENOSYS;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, from);

    char  path3[PATH_MAX] ;
    strcpy(path3, mountsecret); strcat(path3, to);

	//res = link(path2, path3);
	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Chmod file: %s uid: %d mode: %d\n", path, getuid(), mode);

	res = chmod(path2, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Chown file: %s uid: %d touid: %d togid %d\n",
                path, getuid(), uid, gid);

	res = lchown(path2, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res;

    if(is_our_file(path, FALSE))
        {
        if(loglevel > 0)
            syslog(LOG_DEBUG, "No trancation of myfiles allowed: '%s'\n", path);
        errno = EACCES;
        return -EACCES;
        }

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Truncated file: %s size=%ld\n", path, size);


    // Kill sideblock too
    create_sideblock(path);

	res = truncate(path2, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	int res = 0;

	off_t fsize = get_fsize(fi->fh);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "fTruncated file: %s size %ld fsize=%ld\n",
                                                path, size, fsize);

    // Kill sideblock too
    create_sideblock(path);

	res = ftruncate(fi->fh, size);
	if (res == -1)
		return -errno;

    // Fill in zeros
    if (size > fsize)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "fTruncate fill: size=%ld fsize=%ld\n", size, fsize);

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
            if (loglevel > 3)
                syslog(LOG_DEBUG, "fTruncate fill: no memory\n");
            return -ENOMEM;
            }
        memset(mem, 0, total);

        // Encryption / decryption by block size
        hs_encrypt(mem, total, passx, plen);

        int ret2 = pwrite(fi->fh, mem, fill, fsize);
        if(!ret2)
            {
            if (loglevel > 3)
                syslog(LOG_DEBUG, "fTruncate fill: cannot fill\n");
            return -errno;
            }
        //write_sideblock(path, mem + total - HS_BLOCK, HS_BLOCK);
        }
	return res;
}

static int xmp_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	res = utimes(path2, tv);
	if (res == -1)
		return -errno;

	return 0;
}


static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd, res = 0;

    if(is_our_file(path, FALSE))
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "No operation of myfiles allowed: '%s'\n", path);

        errno = EACCES;
        return -EACCES;
        }

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret);
    if(path[0] == '/')
        strcat(path2, path + 1);
    else
        strcat(path2, path);

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Create: '%s' uid: %d mode: %x\n", path, getuid(), mode);

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Shadow file: '%s'\n", path2);

    if(passx[0] == 0)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "Empty pass on create file: %s uid: %d\n", path, getuid());
        int ret = openpass(path);
        if (ret)
            {
            errno = EACCES;
            return -EACCES;
            }
        }

    // Patch new create mode
    int mode2 = (mode | S_IRUSR | S_IWUSR | S_IRGRP); // && ~(S_IXOTH | S_IROTH | S_IWOTH);
	fd = open(path2, fi->flags, mode2);

	if (fd == -1)
        {
		if (loglevel > 2)
            syslog(LOG_DEBUG, "Cannot create file '%s' mode=%d(0x%x) errno=%d retry ...\n",
                        path, mode2, mode2, errno);

        fd = open(path2, fi->flags, mode);
        if (fd == -1)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot create file '%s' mode=%d(0x%x) errno=%d\n",
                            path, mode2, mode2, errno);
            return -1;
            }
        }

	fi->fh = fd;

    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    int res2 = fstat(fi->fh, &stbuf);
    if(res2 < 0)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Cannot stat newly created file '%s'\n", path);

        goto endd;
        }

    hslog(3, " - - - - - \n");
    hslog(3, "Created: '%s' fh=%d\n", path, fi->fh);

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Inode: %lud blocksize %ld \n",
    //                                stbuf.st_ino, stbuf.st_blksize);

    create_sideblock(path);

    endd:
        ;
	return res;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;

    // Needed by the decrypt command line util
    //if(is_our_file(path, FALSE))
    //    {
    //    syslog(LOG_DEBUG, "No operation on myfiles allowed: '%s'\n", path);
    //    return -EACCES;
    //    }

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 1)
        syslog(LOG_DEBUG, "Open: %s uid: %d mode: %x\n",
                                                path, getuid(),fi->flags);
    if(passx[0] == 0)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "Empty pass on open file: %s uid: %d\n", path, getuid());
        int ret = openpass(path);
        if (ret)
            {
            errno = EACCES;
            return -EACCES;
            }
        }

    int mode2 = S_IRUSR | S_IWUSR |  S_IRGRP | O_RDWR;
	//fd = open(path2, fi->flags | O_RDWR);
    //fd = open(path2, S_IRUSR | S_IWUSR |  S_IRGRP | O_RDWR);
    fd = open(path2, fi->flags, mode2);

    if (fd < 0)
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "Error on open file, trying org perm. errno=%d\n", errno);

        // try with original permissions
        fd = open(path2, fi->flags);

        if (fd < 0)
            {
            if (loglevel > 3)
                syslog(LOG_DEBUG, "Error on open file, '%s' perm=%d (0x%x)\n",
                                        path, fi->flags, fi->flags);

    		return -errno;
            }
        }
	fi->fh = fd;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Open '%s' fh=%ld\n", path2, fi->fh);

    //struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    //int res = fstat(fi->fh, &stbuf);
    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Inode: %lud\n", stbuf.st_ino);
	return 0;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Stat file: %s uid: %d\n", path, getuid());

	res = statvfs(path2, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	int res;

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Flushing file: %s uid: %d\n", path, getuid());

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
    //
    //res = 0;

    res = close(dup(fi->fh));
	if (res == -1)
		return -errno;

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Flushed file: %s fh: %ld\n", path, fi->fh);

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)

{
    int res;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Releasing: '%s' fh: %ld\n", path, fi->fh);

    // try until error
    for (int aa = 0; aa < 3; aa++)
        {
        res = syncfs(fi->fh);
        if (res < 0)
            break;
        }

    //usleep(10000);

	(void) path;
	close(fi->fh);

    //usleep(10000);

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Released: '%s' fh: %ld\n", path, fi->fh);

	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	int res;
	(void) path;

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif

    res = fsync(fi->fh);

	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lsetxattr(path2, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lgetxattr(path2, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	int res = llistxattr(path3, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    char  path2[PATH_MAX] ;
    strcpy(path2, mountsecret); strcat(path2, path);

	int res = lremovexattr(path2, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd,
		    struct flock *lock)
{
	(void) path;

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			   sizeof(fi->lock_owner));
}

// EOF