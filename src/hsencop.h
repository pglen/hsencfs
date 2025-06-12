
/* =====[ hsencop ]========================================================

   File Name:       hsencop.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Thu 12.Jun.2025      Peter Glen      Initial version.

   ======================================================================= */

void *xmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg);
off_t xmp_lseek(const char *path,  off_t off, int whence, struct fuse_file_info *fi);
int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int xmp_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int xmp_access(const char *path, int mask);
int xmp_readlink(const char *path, char *buf, size_t size);
int xmp_opendir(const char *path, struct fuse_file_info *fi);
int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags ff);
int xmp_releasedir(const char *path, struct fuse_file_info *fi);
int xmp_mknod(const char *path, mode_t mode, dev_t rdev);
int xmp_mkdir(const char *path, mode_t mode);
int xmp_unlink(const char *path);
int xmp_rmdir(const char *path);
int xmp_symlink(const char *from, const char *to);
int xmp_rename(const char *from, const char *to, unsigned int flags);
int xmp_link(const char *from, const char *to);
int xmp_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);
int xmp_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi);
int xmp_truncate(const char *path, off_t size, struct fuse_file_info *fi);
int xmp_ftruncate(const char *path, off_t size, struct fuse_file_info *fi);
int xmp_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi);
int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int xmp_open(const char *path, struct fuse_file_info *fi);
int xmp_statfs(const char *path, struct statvfs *stbuf);
int xmp_flush(const char *path, struct fuse_file_info *fi);
int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi);
int xmp_release(const char *path, struct fuse_file_info *fi);
int xmp_listxattr(const char *path, char *list, size_t size);
int xmp_removexattr(const char *path, const char *name);
int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock);

// EOF

