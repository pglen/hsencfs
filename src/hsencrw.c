// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Read write 'C' include. Extracted for eazy editing
//

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption /decryption
// is symmetric.
//

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;

    void *mem =  malloc(size);
    if (mem == NULL)
        {
     	res = -ENOMEM;
        return res;
        }
    memset(mem, 0, size);        // Zero it

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Reading file: %s size %ld offs %ld\n",
                                                    path, size, offset);

	res = pread(fi->fh, mem, size, offset);
	if (res == -1)
		res = -errno;

    // Encryption / decryption by block size. Currently: 1024
    hs_decrypt(mem, res, pass, plen);
    memcpy(buf, mem, res);

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Read file: %s size %d\n", path, res);

    // Do not leave data behind
    if (mem)
        {
        // Encrypt it: This is a fake encryption od the dangling memory.
        // Just to confuse the debugger
        hs_decrypt(mem, size, "pass", 4);
        memset(mem, 0, size);        // Zero it
        free(mem);
        }
	return res;
}

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption /decryption
// is symmetric.
//

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res, loop;

    void *mem =  malloc(size);
    if (mem == NULL)
        {
     	res = -ENOMEM;
        return res;
        }
    memset(mem, 0, size);        // Zero it

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Writing file: %s size %ld offs %ld\n",
                                                        path, size, offset);

    memcpy(mem, buf, size);
    // Encryption / decryption by block size. Currently: 1024
    hs_encrypt(mem, size, pass, plen);

	res = pwrite(fi->fh, mem, size, offset);

	if (res == -1)
		res = -errno;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Written out file: %s size %d\n", path, res);

    // Do not leave data behind
    if (mem)
        {
        // Encrypt it: This is a fake encryption of the dangling memory.
        // Just to confuse the debugger
        hs_decrypt(mem, size, "passpass", 8);
        memset(mem, 0, size);        // Zero it
        free(mem);
        }
	return res;
}





