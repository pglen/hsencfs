// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Extracted for eazy editing. This code took forever.
//

//
// Read / Write the
//      If last block, gather data from sideblock, patch it in.
//

static  int    read_sideblock(const char *path, char **pbuff, int len)

{
    int ret = 0;
    // Read in last block from lastblock file
    *pbuff = malloc(len);
    if(!*pbuff)
        {
        syslog(LOG_DEBUG, "Cannot allocate memory for final block '%s'\n", path);
        ret = -ENOMEM;
        goto endd;
        }
    memset(*pbuff, '\0', HS_BLOCK);
    //hs_encrypt(mem, HS_BLOCK, passx, plen);

    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        if(*pbuff)
            {
            ret = -ENOMEM;
            free(*pbuff);
            *pbuff = NULL;
            }
        syslog(LOG_DEBUG, "Cannot allocate memory for file name '%s'\n", path);
        goto endd;
        }

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Opening block file '%s'\n", ptmp2);

    int old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Error on opening block file '%s', errno: %d\n", ptmp2, errno);

        ret = -ENOENT;
        errno = old_errno;
        goto endd;
        }
    else
        {
        ret = read(fdi, *pbuff, len);
        if(ret < len)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Error on reading block file, errno: %d\n", errno);

            ret = -EFAULT;
            }
        close(fdi);
        }
    errno = old_errno;

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Read block file, '%s'\n",
    //                             bluepoint2_dumphex(bbuff, 100));

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Reading block file, %.*s\n", 8, *pbuff);

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Block file, '%s'\n", bluepoint2_dumphex(*pbuff, 8));

  endd:
    return ret;
}

//
// Read / Write the
//      If last block, gather data from sideblock, patch it in.
//

static  int     write_sideblock(const char *path, char *bbuff, int len)

{
    int ret = 0;

    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        syslog(LOG_DEBUG, "Cannot allocate memory for file name '%s'\n", path);
        goto endd;
        }

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Writing block file '%s'\n", ptmp2);

    int rrr = 0, old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Error on creating block file '%s', errno: %d\n", ptmp2, errno);

        ret = -errno;
        errno = old_errno;
        goto endd;
        }
    else
        {
        int rrr = write(fdi, bbuff, len);
        if(rrr < len)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Error on writing block file, errno: %d\n", errno);

            ret = -errno;
            }
        close(fdi);
        }
    errno = old_errno;

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Read block file, '%s'\n",
    //                             bluepoint2_dumphex(bbuff, 100));

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Block file, '%s'\n", bluepoint2_dumphex(bbuff, 11));

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Written block file, %.*s\n", 8, bbuff);

  endd:
    return ret;
}

// EOF
