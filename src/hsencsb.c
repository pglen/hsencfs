// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Extracted for eazy editing. This code took forever.
//

// -----------------------------------------------------------------------
// Shorthand for log to syslog

void    hslog(int lev, char *fmt, ...)
{
    if (loglevel > lev)
        {
        va_list ap;
        va_start(ap, fmt);
        vsyslog(LOG_DEBUG, fmt, ap);
        va_end(ap);
        }
}

// -----------------------------------------------------------------------
// Scratch pad for the whole lot

void    *hsalloc(int total)
{
    void *mem =  malloc(total);
    if (mem == NULL)
        {
        hslog(0, "Cannot get main block memory.\n");
        goto endd;
        }
     memset(mem, 0, total);                  // Zero it

 endd:
    return mem;
}

// -----------------------------------------------------------------------

sideblock *alloc_sideblock()

{
    sideblock *psb = malloc(sizeof(sideblock));
    if(psb == NULL)
        {
        if (loglevel > 0)
           syslog(LOG_DEBUG, "Cannot allocate memory for sideblock\n");
        goto endd;
        }
    INIT_SIDEBLOCK(*psb);
   endd:
    return psb;
}

// -----------------------------------------------------------------------

char    *get_sidename(const char *path)

{
    char *ptmp2 = malloc(PATH_MAX);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for sideblock filename '%s'\n", path);
        goto endd;
        }

     if (loglevel > 9)
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
    //syslog(LOG_DEBUG, "sb tokenx '%s'\n", pch);

    while ( (temp = strtok(NULL, "/") ) != NULL)
        {
        cnt2++;
        //syslog(LOG_DEBUG, "sb token %d  '%s'\n", cnt2, temp);
        if(strcmp(temp, "."))
            {
            strcat(ptmp2, "/");
            if(cnt2 == cnt)
                strcat(ptmp2, ".");
            strcat(ptmp2, temp);
            }
        }
    free(eee);
    strcat(ptmp2, myext);

    if (loglevel > 9)
         syslog(LOG_DEBUG, "Got sidename '%s'\n", ptmp2);

   endd:
    return ptmp2;
}

// ----------------------------------------------------------------------
// Always read full blocks from sideblock

static  int    read_sideblock(const char *path, sideblock *psb)

{
    int ret = 0;

    if(psb->magic !=  HSENCFS_MAGIC)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Bad magic on sizeblock read '%s'\n", path);
        ret = -1;
        goto endd;
        }
    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for sideblock file name '%s'\n", path);

        ret = -ENOMEM;
        goto endd;
        }

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Opening sideblock file '%s'\n", ptmp2);

    int old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on opening sideblock file '%s', errno: %d\n", ptmp2, errno);

        ret = -ENOENT;
        //errno = old_errno;
        goto endd2;
        }
    else
        {
        ret = read(fdi, psb, sizeof(sideblock));
        if(ret && ret < sizeof(sideblock))        // We ignore empty file
            {
            if (loglevel > 0)
                syslog(LOG_DEBUG, "Error on reading sideblock file, errno: %d\n", errno);
            //ret = -EFAULT;
            }
        close(fdi);
        }
    errno = old_errno;
    if(psb->magic !=  HSENCFS_MAGIC)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on sideblock MAGIC\n");
        }

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Got sideblock:, '%s'\n", bluepoint2_dumphex(*pbuff, 8));

  endd2:
    free(ptmp2);

  endd:
    return ret;
}

//////////////////////////////////////////////////////////////////////////
//
// Read / Write the
//      If last block, gather data from sideblock, patch it in.
//

static  int     write_sideblock(const char *path, sideblock *psb)

{
    int ret = 0;

    if(psb->magic !=  HSENCFS_MAGIC)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Bad magic on sizeblock write '%s'\n", path);
        ret = -1;
        goto endd;
        }

    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for file name '%s'\n", path);
        goto endd;
        }

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Writing sideblock file '%s'\n", ptmp2);

    int rrr = 0, old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on creating sideblock file '%s', errno: %d\n", ptmp2, errno);

        ret = -errno;
        errno = old_errno;
        goto endd2;
        }
    rrr = write(fdi, psb, sizeof(sideblock));
    if(rrr < sizeof(sideblock))
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on writing sideblock file, errno: %d\n", errno);

        //ret = -errno;
        }
    close(fdi);

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Writing sideblock file2 '%s'\n", ptmp2);

    errno = old_errno;

    //if (loglevel > 4)
    //    syslog(LOG_DEBUG, "Written sideblock file, '%s'\n", bluepoint2_dumphex(bbuff, 16));

   endd2:
    if (loglevel > 9)
        syslog(LOG_DEBUG, "Writing sideblock file3 '%s'\n", ptmp2);

    free(ptmp2);

  endd:
    return ret;
}

static  int    create_sideblock(const char *path)

{
    int ret = 0;

    char *ptmp2 = get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Canot allocate sideblock memory.");
        ret = -ENOMEM;
        goto endd;
        }

    sideblock *psb = alloc_sideblock();
    if(!psb)
        goto endd3;

    int old_errno = errno;
    int fdi = open(ptmp2, O_RDWR | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    if(fdi < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on creating sideblock '%s' errno: %d\n", ptmp2, errno);

        // Not sure what to do ... error?
        ret = -errno;
        goto endd3;
        }
    int ww = write(fdi, psb, sizeof(sideblock));
    if(ww < sizeof(sideblock))
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on writing to sideblock errno: %d\n", errno);
        }
    close(fdi);
    errno = old_errno;

  endd3:
    free(psb);

  endd2:
    free(ptmp2);

   endd:
    return ret;
}

// -----------------------------------------------------------------------
// Check if it is our internal file

static  int     is_our_file(const char *path, int fname_only)

{
    int ret = FALSE;
    char *eee = "/.";
    if(fname_only == FALSE)
        {
        eee = strrchr(path, '/');
        }
    char *nnn = strrchr(path, '.');

    // Determine if it is our data file, deny access
    if(eee && nnn)
        {
        if(eee[1] == '.' && strncmp(nnn, myext, sizeof(myext) - 1) == 0 )
            {
            ret = TRUE;
            }

        //if (loglevel > 4)
        //    syslog(LOG_DEBUG, "is_our_file: eee '%s' nnn '%s' ret=%d\n", eee, nnn, ret);
        }
    return ret;
}

// Estabilish file size

static off_t    get_fsize(int fh)

{
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    fstat(fh, &stbuf);
    return stbuf.st_size;
}

// -----------------------------------------------------------------------
// Encrypt (double decrypt) it: This is a fake encryption of the
// dangling memory, Just to confuse the would be decoder

static  void  kill_buff(void *bbuff, int xlen)

{
    // Do not leave data behind
    if (bbuff)
        {
        #if 1
        // Just to confuse the would be debugger
        if(rand() % 2 == 0)
            hs_decrypt(bbuff, xlen, "passpass", 8);
        else
            hs_decrypt(bbuff, xlen, "pass", 4);

        // No data left behind
        memset(bbuff, 0, xlen);        // Zero it
        #endif

        free(bbuff);
        }
}

void    kill_sideblock(sideblock *psb)

{
    if(psb)
        kill_buff(psb, sizeof(psb));
}

// -----------------------------------------------------------------------
// Go through pass ritual on demand

static  int     openpass(const char *path)

{
    char tmp[MAXPASSLEN];
    int ret = 0;

    if(passprog[0] == 0)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "No pass program specified: %s uid: %d\n", path, getuid());
        return 1;
        }
    char *res = hs_askpass(passprog, tmp, MAXPASSLEN);
    if (res == NULL || strlen(res) == 0)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Cannot get pass for %s uid: %d\n", path, getuid());
        return 1;
        }

    strncpy(passx, res, sizeof(passx));

    int ret2 = pass_ritual(mountpoint, mountsecret, passx, &plen);
    if(ret2)
        {
        // Force new pass prompt
        memset(passx, 0, sizeof(passx));
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Invalid pass for %s uid: %d\n", path, getuid());
        return ret2;
        }
    return ret;
}

// EOF