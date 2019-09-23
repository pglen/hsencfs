// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Read write 'C' include. Extracted for eazy editing
//

char *get_tmpname(const char *path)

{
    char *ptmp2 = malloc(PATH_MAX);
    if(ptmp2)
        {
        // Reassemble with dot path
        strcpy(ptmp2, mountdata);
        char *endd = strrchr(path, '/');
        if(endd)
            {
            strncat(ptmp2, path, endd - path);
            strcat(ptmp2, ".");
            strcat(ptmp2, endd + 1);
            }
        else
            {
            strcat(ptmp2, ".");
            }
        strcat(ptmp2, ".secret");
        }
    return ptmp2;
}

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption / decryption
// is symmetric.
//
//        new_offset (buf % n)                total buf % n + n
// ===----|---------------------|--------------=======
//    |   ^ offs                ^offs + size  |
//
// Exception is taken when dealing with the last block. The Inode file contains a copy
// of the last block, one that overflows the real file length.
// This is to complete the last buffer.
//

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;

    size_t new_offset = (offset / HS_BLOCK) * HS_BLOCK;
    size_t skip = offset - new_offset;
    size_t new_size = size + skip;

    size_t total = (new_size / HS_BLOCK) * HS_BLOCK;
    if((size % HS_BLOCK) != 0)
        {
        total += HS_BLOCK;
        }
    void *mem =  malloc(total);
    if (mem == NULL)
        {
     	res = -ENOMEM;
        return res;
        }
    memset(mem, 0, total);        // Zero it

    if (loglevel > 2)
        {
        syslog(LOG_DEBUG, "Before reading file: %s size=%ld offs=%ld\n",
                                                    path, size, offset);
        syslog(LOG_DEBUG, "Size expanded: new_offs=%ld total=%ld skip=%ld\n",
                                                               new_offset, total, skip);
        }

    // Remember old place
    off_t oldoff = lseek(fi->fh, 0, SEEK_SET);

    // Estabilish file size
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    res = fstat(fi->fh, &stbuf);
    off_t fsize = stbuf.st_size;

    // Read full block instead
    size_t getall = new_offset + total;
    if(getall >= fsize)
        {
        // Read in last block from lastblock file
        getall = fsize - new_offset;
        //res = pread(fi->fh, mem, getall, new_offset);

        char *ptmp2 =  get_tmpname(path);
        if(ptmp2)
            {
            int old_errno = errno;
            int fdi = open(ptmp2, O_RDWR, S_IRUSR | S_IWUSR);
            if(fdi < 0)
                {
                if (loglevel > 2)
                    syslog(LOG_DEBUG, "Error on opening '%s', errno: %d\n", ptmp2, errno);
                }
            else
                {
                int rrr = read(fdi, mem, HS_BLOCK);
                if(rrr < HS_BLOCK)
                    {
                    if (loglevel > 2)
                        syslog(LOG_DEBUG, "Error on reading inode file, errno: %d\n", errno);
                    }
                close(fdi);
                }
            errno = old_errno;
            free(ptmp2);
            }
        }
    else
        {
        getall = total;
        res = pread(fi->fh, mem, getall, new_offset);
        lseek(fi->fh, oldoff + size, SEEK_SET);
        }

    if (res == -1)
        res = -errno;

    // Encryption / decryption by block size. Currently: 1024
    hs_decrypt(mem, HS_BLOCK, passx, plen);

    // Return result as requested
    memcpy(buf, mem + skip, size);

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Read in data: %s size %d\n", path, res);

    // Do not leave data behind
    if (mem)
        {
        // Encrypt (double decrypt) it: This is a fake encryption of the dangling memory.
        // Just to confuse the would be decoder
        hs_decrypt(mem, total, "pass", 4);
        memset(mem, 0, total);        // Zero it
        free(mem);
        }
	return res;
}

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption / decryption
// is symmetric.
//
//    new_offset (buf % n)                    total (buf % n) * n
// ===----|---------------------|--------------=======
//    |   ^ offs                ^offs + size  |


static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res, loop;

    size_t new_offset = (offset / HS_BLOCK) * HS_BLOCK;
    size_t skip = offset - new_offset;
    size_t new_size = size + skip;

    size_t total = (new_size / HS_BLOCK) * HS_BLOCK;

     if (loglevel > 4)
            syslog(LOG_DEBUG,
                "total: '%s' total=%ld mult=%ld \n",
                                       path, total, new_size / HS_BLOCK);
    if((size % HS_BLOCK) > 0)
        {
        total += HS_BLOCK;
        }
    if (loglevel > 3)
        syslog(LOG_DEBUG,
                "About to write: '%s' offset=%ld new_offs=%ld size=%ld total=%ld\n",
                                                   path, offset, new_offset, size, total);
    void *mem =  malloc(total);
    if (mem == NULL)
        {
     	if (loglevel > 2)
            {
            syslog(LOG_DEBUG, "Cannot allocate memory %ld", total);
            }
        res = -ENOMEM;
        return res;
        }
    memset(mem, 0, total);        // Zero it

    // read / encrypt / patch / write

    off_t oldoff = lseek(fi->fh, 0, SEEK_SET);

    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    res = fstat(fi->fh, &stbuf);
    off_t fsize = stbuf.st_size;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "File size from stat %ld\n", fsize);

    int get_patch = 0;
    size_t get = new_offset + size;
    if(get >= fsize)
        {
        get_patch = total - (get - fsize);
        }

    if (loglevel > 3)
            syslog(LOG_DEBUG,
            "About to pre read: '%s' "
                "get=%ld new_offs=%ld fsize=%ld patch=%d total=%ld\n",
                       path, get, new_offset, fsize, get_patch, total);
    if(get > 0)
        {
        res = pread(fi->fh, mem, get, new_offset);
        if(get_patch)
            {
            res = pread(fi->fh, mem + res, get_patch, new_offset + res);
            }

    	if (res == -1)
            {
            // We throw this away, as the buffer is zeroed out
            if (loglevel > 3)
                syslog(LOG_DEBUG,
                    "Cannot pre read for encryption %s size=%ld total=%ld offs=%ld\n",
                                   path, size, total, offset);
            errno = 0;
            res = 0;
            }
        else
            {
            hs_decrypt(mem, res, passx, plen);
            }
        // patch
        }

    if (loglevel > 2)
        syslog(LOG_DEBUG,
            "Writing file: %s size=%ld offs=%ld skip=%ld total=%ld\n",
                                              path, size, offset, skip, total);

    memcpy(mem + skip, buf, size);

    // Encryption / decryption by block size. Currently: 1024
    hs_encrypt(mem, total, passx, plen);

	//lseek(fi->fh, oldoff, SEEK_SET);

    res = pwrite(fi->fh, mem + skip, size, offset);
	if (res == -1)
        {
        syslog(LOG_DEBUG, "Error on writing file: %s res %d errno %d\n", path, res, errno);
		res = -errno;
        }

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Written out file: %s res %d\n", path, res);

    // Do not leave data behind
    if (mem)
        {
        // Encrypt it: This is a fake encryption of the dangling memory.
        // Just to confuse the debugger
        hs_decrypt(mem, get > 0, "passpass", 8);
        memset(mem, 0, total);        // Zero it
        free(mem);
        }
	return res;
}









