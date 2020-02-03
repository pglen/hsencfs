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

char    *get_sidename(const char *path)

{
    char *ptmp2 = malloc(PATH_MAX);
    if(!ptmp2)
        {
        syslog(LOG_DEBUG, "Cannot allocate memory for sideblock filename '%s'\n", path);
        goto endd;
        }

    syslog(LOG_DEBUG, "Generate sidename '%s'\n", path);

    int cnt = 0, cnt2 = 0; char *pch, *temp;
    char *ddd = strdup(path);
    pch = strtok(ddd, "/");
    while ( (temp = strtok (NULL, "/") ) != NULL)
        cnt++;
    free(ddd);

    char *eee = strdup(path);
    strcpy(ptmp2, mountsecret);
    pch = strtok(eee, "/");
    if(cnt2 == cnt)
        strcat(ptmp2, ".");
    strcat(ptmp2, pch);
    syslog(LOG_DEBUG, "sb tokenx '%s'\n", pch);

    while ( (temp = strtok(NULL, "/") ) != NULL)
        {
        cnt2++;
        syslog(LOG_DEBUG, "sb token %d  '%s'\n", cnt2, temp);
        if(strcmp(temp, "."))
            {
            strcat(ptmp2, "/");
            if(cnt2 == cnt)
                strcat(ptmp2, ".");
            strcat(ptmp2, temp);
            }
        }
    free(eee);
    strcat(ptmp2, ".dat");

    if (loglevel > 3)
         syslog(LOG_DEBUG, "Got sidename '%s'\n", ptmp2);

   endd:
    return ptmp2;
}

static  int    read_sideblock(const char *path, char **pbuff, int len)

{
    int ret = 0;
    // Read in last block from lastblock file
    *pbuff = malloc(len);
    if(!*pbuff)
        {
        syslog(LOG_DEBUG, "Cannot allocate memory for sideblock '%s'\n", path);
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
        syslog(LOG_DEBUG, "Cannot allocate memory for sideblock file name '%s'\n", path);
        goto endd;
        }

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Opening sideblock file '%s'\n", ptmp2);

    int old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Error on opening sideblock file '%s', errno: %d\n", ptmp2, errno);

        //ret = -ENOENT;
        //errno = old_errno;
        //goto endd2;
        }
    else
        {
        ret = read(fdi, *pbuff, len);
        if(ret && ret < len)        // We ignore empty file
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Error on reading sideblock file, errno: %d\n", errno);

            //ret = -EFAULT;
            }
        close(fdi);
        }
    errno = old_errno;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Got sideblock:, '%s'\n", bluepoint2_dumphex(*pbuff, 8));

  endd2:
    free(ptmp2);

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
        syslog(LOG_DEBUG, "Writing sideblock file '%s'\n", ptmp2);

    int rrr = 0, old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Error on creating sideblock file '%s', errno: %d\n", ptmp2, errno);

        ret = -errno;
        errno = old_errno;
        goto endd2;
        }
    else
        {
        int rrr = write(fdi, bbuff, len);
        if(rrr < len)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Error on writing sideblock file, errno: %d\n", errno);

            ret = -errno;
            }
        close(fdi);
        }
    errno = old_errno;

    if (loglevel > 4)
        syslog(LOG_DEBUG, "Written sideblock file, '%s'\n", bluepoint2_dumphex(bbuff, 16));

   endd2:
    free(ptmp2);

  endd:
    return ret;
}

static  int    create_sideblock(const char *path)

{
    char *ptmp2 = get_sidename(path);
    if(ptmp2)
        {
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Creating new sideblock '%s'\n", ptmp2);

        int old_errno = errno;
        int fdi = open(ptmp2, O_RDWR | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
        if(fdi < 0)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Error on creating '%s' errno: %d\n", ptmp2, errno);
            }
        else
            {
            int blksize = HS_BLOCK;
            //int blksize = stbuf.st_blksize;

            char *ptmp3 = malloc(blksize);
            if(ptmp3)
                {
                memset(ptmp3, '\0', blksize);
                int ww = write(fdi, ptmp3, blksize);
                if(ww < blksize)
                    {
                    if (loglevel > 2)
                        syslog(LOG_DEBUG, "Error on writing to sideblock errno: %d\n", errno);
                    }
                free(ptmp3);
                }
            close(fdi);
            }
        errno = old_errno;
        free(ptmp2);
        }
    return 0;
}

// Estabilish file size

static  off_t get_fsize(int fh)

{
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    fstat(fh, &stbuf);
    return stbuf.st_size;
}

// EOF

