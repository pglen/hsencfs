// Included in the HSENC project

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>

#include <sys/time.h>
#include <sys/stat.h>

#include "bp2com.h"
#include "bluepoint2.h"

char    progname[] = "HSENCFS";
static char     tmp[256];

int     bpgetpass(const char *fname, char *pass, int *plenx)

{
    char    *xpass = NULL; int     xlen;

    snprintf(tmp, sizeof(tmp),  "\n"
            "Enter pass for file: '%s'\n"
            "Entering wrong pass will decrypt it incorrectly.\n"
            "Entering empty pass (Return) will Abort.\n"
            "\n"
            "Please enter pass: ", fname);

    xpass = getpass(tmp);  //printf("password: '%s'\n", pass);
    xlen = strlen(xpass);
    if(xlen == 0)
        {
        fprintf(stderr, "Aborted.\n");
        exit(1);
        }

    // Dup the results right away, clear it too
    strcpy(pass, xpass);
    memset(xpass, 0, xlen);

    // Always padd it
    if(xlen % 2)
        strncat(pass, "x", sizeof(pass)-1);

    // Encrypt the results right away
    bluepoint2_encrypt(pass, xlen, progname, strlen(progname));
    *plenx = xlen;
}

// Make backup path name. Caller must free result.
// Same process as hsenc uses.

char    *mk_backup_path(const char *path)

{
    char *ptmp2 = malloc(PATH_MAX);
    if(ptmp2)
        {
        // Reassemble with dot path
        //strcpy(ptmp2, mountdata);
        char *endd = strrchr(path, '/');
        if(endd)
            {
            strncpy(ptmp2, path, endd - path);
            strcat(ptmp2, "/.");
            strcat(ptmp2, endd + 1);
            }
        else
            {
            strcpy(ptmp2, ".");
            strcat(ptmp2, path);
            }
        strcat(ptmp2, ".datx");
        }
    return ptmp2;
}

//////////////////////////////////////////////////////////////////////////
// Create block backup file. Calle must close it.

int     mk_block_file(const char *path)

{
    int fdi = 0;  char *ptmp2 = NULL, *ptmp3 = NULL;
    int old_errno = errno;

    ///printf("Block file for '%s'\n", path);

    //struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    //int res = stat(path, &stbuf);
    //if(res < 0)
    //    {
    //    printf("Cannot stat newly created file '%s'\n", path);
    //    goto endd;
    //    }
    //printf("Stat block size: %ld\n", stbuf.st_blksize);

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Creating '%s'\n", ptmp2);
    printf("Creating '%s'\n", ptmp2);

    fdi = open(ptmp2, O_TRUNC | O_RDWR , S_IRUSR | S_IWUSR);
    if(fdi < 0)
        {
        printf("Error on creating '%s' errno: %d\n", ptmp2, errno);
        goto endd;
        }
    else
        {
        char *ptmp3 = malloc(BLOCKSIZE);
        if(ptmp3)
            {
            memset(ptmp3, '\0', BLOCKSIZE);
            int ww = write(fdi, ptmp3, BLOCKSIZE);
            if(ww < BLOCKSIZE)
                {
                //if (loglevel > 2)
                //    syslog(LOG_DEBUG, "Error on writing to inode file errno: %d\n", errno);
                printf("Error on writing to inode file errno: %d\n", errno);
                goto endd;
                }
            //lseek(fd, 0, SEEK_SET);
            }
        close(fdi);
        }
 endd: ;
    errno = old_errno;
    if(ptmp2) free(ptmp2);
    if(ptmp3) free(ptmp3);
    return(fdi);
}






