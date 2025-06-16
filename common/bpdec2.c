///////////////////////////////////////////////////////////////////////////
// Bluepoint2 test decrypter. Outputs to stdout.
//

// It blindly decrypts, so make sure if you expect the HSENCFS
// subsystem to accept the file, use the same pass.
//

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
#include <fuse.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "hsencdef.h"
#include "hsencfs.h"
#include "hspass.h"
#include "hsutils.h"
#include "hs_crypt.h"
#include "bp2com.h"
#include "hsencsb.h"
#include "bluepoint2.h"

static char buff[4096];
static char pass[256];
static char tmp[256];

// Log
static FILE *logfp = NULL;

// Flags
int     verbose = 0;
int     quiet = 0;
int     force = 0;
int     ondemand = 0;

// Maintain internal count
static  char    version[] = "1.18";

char    passx[MAXPASSLEN];
int     plen = sizeof(passx);

//static  char    decoy[MAXPASSLEN];
static  int     plen2 = sizeof(decoy);
static char     pass[256];

static struct option long_options[] =
    {
        {"loglevel",    1,  0,  'l'},
        {"help",        0,  0,  'h'},
        {"pass",        0,  0,  'p'},
        {"quiet",       0,  0,  'g'},
        {"force",       0,  0,  'f'},
        {"verbose",     0,  0,  'v'},
        {"version",     0,  0,  'V'},
        {"askpass",     0,  0,  'a'},
        {"ondemand",    0,  0,  'o'},
        {0,             0,  0,   0}
    };

void help()

{
    //printf("Help here\n");

    printf("\n");
    printf("Usage: bpdec2 [options] infile outfile\n");
    printf("\n");
    printf("Options:        -l num      -- Use log level  (--loglevel)\n");
    printf("                -p pass     -- Use pass (!!Warning!! cleartext pass) (--pass)\n");
    printf("                -f          -- Force overwrite target (--force)\n");
    printf("                -q          -- Quiet (--quiet)\n");
    printf("                -v          -- Verbose (--verbose)\n");
    printf("                -V          -- Print version (--version)\n");
    printf("\n");

}

sideblock_t sb;

// -----------------------------------------------------------------------

int main(int argc, char *argv[])

{
    memset(pass, 0, sizeof(pass));

    int cc, digit_optind = 0, loop, loop2;
    struct stat ss; struct timespec ts;

    memset(&sb, '\0', sizeof(sb));
    sb.magic =  HSENCFS_MAGIC;

    //bluepoint2_set_verbose(1);
    //bluepoint2_set_functrace(1);

    // Parse command line
   	while (1)
        {
        int this_option_optind = optind ? optind : 1;
        int option_index = -1;

    	cc = getopt_long(argc, argv, "a:fhl:p:oqvV",
                         long_options, &option_index);
        if (cc == -1)
            break;

        //printf("cc %d cc %c arg %x\n", cc, cc, optarg);
        //if(option_index >= 0)
        //    {
        //    printf ("long option '%s' idx: %d val %d ",
        //              long_options[option_index].name,
        //              option_index,
        //                long_options[option_index].val);
        //    if (optarg)
        //           printf (" with arg %s", optarg);
        //    printf("\n");
        //    }

        int ret = 0, loop = 0;

        switch (cc)
           {
           case 'a':
                if(verbose)
                    printf("Getting pass from program: '%s'\n", optarg);
                //strncpy(passprog, optarg, MAXPASSLEN);
                break;

            case 'f':
                force = 1;
                break;

           case 'l':
               loglevel = atoi(optarg);
                if(verbose)
                    printf("Log Level: %d\n", loglevel);
               break;

           case 'p':
                if (passx[0] != 0)
                    {
                    fprintf(stderr, "%s Error: multiple passes on command line.\n", argv[0]);
                    exit(1);
                    }
                plen = strlen(optarg);
                if(plen > sizeof(passx))
                    {
                    printf("Pass too long\n");
                    exit(1);
                    }
                strncpy(passx, optarg, sizeof(passx));

                // Randomize optarg
                for(loop = 0; loop < plen; loop++)
                    {
                    ((char*)optarg)[loop] = rand() % 0x80;
                    }

                bluepoint2_encrypt(passx, plen, progname, strlen(progname));

                if(verbose)
                    printf("Pass provided on command line.\n");
                break;

           case 'q':
               quiet = 1;
               break;

           case 'o':
               ondemand = 1;
               break;

            case 'v':
               verbose = 1;
               break;

           case 'V':
               printf("%s Version: %s\n", argv[0], version);
               exit(0);
               break;

           case 'h': case '?':
                if(verbose)
                    printf("Showing help.\n");
               help(); exit(0);
               break;

           default:
               printf ("?? getopt returned character code 0%o (%c) ??\n", cc, cc);
        }
    }
    FILE *fp2 = NULL;
    if (optind >= argc - 1)
        {
        printf("Not enough arguments, use -h option for more info\n");
        //help();
        exit(1);
        fp2 = stdout;
        }
   if(verbose)
        printf("Infile: '%s' Outfile: '%s'\n", argv[optind], argv[optind+1]);

    if(access(argv[optind], F_OK) < 0)
        {
        fprintf(stderr, "File '%s' must exist and must be readable.\n", argv[optind]);
        exit(1);
        }
    if(access(argv[optind+1], F_OK) >= 0 && !force)
        {
        fprintf(stderr, "Output file '%s' must not exist.\n", argv[optind+1]);
        exit(1);
        }
    if(passx[0] != 0)
        {
        strncpy(pass, passx, sizeof(pass));
        }
    else
        {
        bpgetpass(argv[optind], pass, &plen);
        }

    FILE *fp = fopen(argv[optind], "rb");
    if (!fp)
        {
        fprintf(stderr, "File %s must exist.\n", argv[optind]);
        exit(1);
        }

    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    int res = fstat(fileno(fp), &stbuf);
    if(res < 0)
        {
        fprintf(stderr, "Cannot stat '%s'.\n", argv[optind]);
        exit(1);
        }

    off_t fsize = stbuf.st_size;

    if(!fp2)
        {
        fp2 = fopen(argv[optind+1], "wb+");
        if (!fp2)
            {
            fprintf(stderr, "File '%s' must be writable.\n", argv[optind+1]);
            exit(1);
            }
        }

    char *ptmp2 = mk_backup_path(argv[optind]);
    if(!ptmp2)
        {
        printf("No mem for file name '%s'\n", argv[optind]);
        exit(1);
        }

    FILE *fp3 = fopen(ptmp2, "rb");
    if (!fp3)
        {
        fprintf(stderr, "Support file for '%s' is not found.\n", argv[optind]);
        exit(1);
        }

    int prog = 0;
    while(1)
        {
        memset(buff, 0, sizeof(buff));
        int loop, len, len2, len3, curr;

        //printf("3\n");
        // Is it the last buffer to read?
        if(prog + 4096 > fsize)
            {
            //printf("33\n");
            curr = fsize - prog;

            sideblock_t sb;

            //len3 = fread(buff, 1, sizeof(buff), fp3);
            len3 = fread(&sb, 1, sizeof(sideblock_t), fp3);
            //memcpy(buff, sb.buff, sizeof(buff));

            if(len3 == 0)
                {
                break;
                }
            if(len3 < 0)
                {
                printf("Cannot read support file\n");
                break;
                }
            }
        else
            {
            //printf("34\n");

            curr = 4096;
            len = fread(buff, 1, sizeof(buff), fp);
            if(len <= 0)
                {
                printf("Cannot read file\n");
                break;
                }
            }

        //hs_decrypt(buff, len, pass, plen);
        hs_decrypt(buff, sizeof(buff), pass, plen);

        //printf("2\n");
        len2 = fwrite(buff, 1, curr, fp2);
        if(len2 < curr)
            {
            printf("Error on write\n");
            break;
            }
        prog += len;
        }

    //printf("1\n");
    fclose(fp); fclose(fp2);

    exit(0);
}

// EOF