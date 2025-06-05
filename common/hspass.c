/*
 *   High security encryption file system. Password routines.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#include <signal.h>
#include <termios.h>
#include <getopt.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "hsutils.h"
#include "../src/hsencfs.h"
#include "../bluepoint/bluepoint2.h"

char  *passfname = ".passdata.datx";

static char  *getlinex(int fd, char *buf, size_t bufsiz)

{
    size_t left = bufsiz;
    ssize_t nr = -1;
    char *cp = buf; char c = '\0';

    if (left == 0) {
    	errno = EINVAL;
    	return(NULL);			/* sanity */
    }

    while (--left) {
	   nr = read(fd, &c, 1);
    	if (nr != 1 || c == '\n' || c == '\r')
    	    break;
	   *cp++ = c;
    }
    *cp = '\0';

    return(nr == 1 ? buf : NULL);
}

// -----------------------------------------------------------------------
// Just for checking, do not use in production code.

#if 0
static  void printpass(char *pp, int ll)
{
    char *ttt = malloc(ll);
    if(ttt)
        {
        memcpy(ttt, pp, ll); ttt[ll] = 0;
        bluepoint2_decrypt(ttt, ll, progname, strlen(progname));
        //printf("got pass '%s'\n", ttt);
        // Erase it by encrypt / clear
        bluepoint2_encrypt(ttt, ll, progname, strlen(progname));
        memset(ttt, 0, ll);
        free(ttt);
        }
}
#endif


// -----------------------------------------------------------------------
// Create asyn encryption

//define MIN(aa, bb) aa > bb ? bb : aa
typedef unsigned char uchar;

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static int pad = RSA_PKCS1_PADDING;
static const char *propq = NULL;

static void hexdump(char *ptr, int len)
{
    int llen = 24;
    for (int aa = 0; aa < len; aa++)
        {
        uchar chh = ptr[aa] & 0xff;
        if(chh > 127 || chh < 32)
            printf("%.2x ", chh);
        else
            printf(" %c ", chh);

        if (aa % llen == llen-1)
            printf("\n");
        }
}

static void printLastError(char *msg)
{
    ERR_load_crypto_strings();
    char *err = malloc(130);;
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

static char* publicKeyToString(EVP_PKEY* pubKey, char *out, int maxlen)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubKey);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    len = MIN(len, maxlen);
    memcpy(out, pem_str, len);
    out[len] = '\0';
    BIO_free(bio);
    return out;
}

static char* privateKeyToString(EVP_PKEY* Key, char *out, int maxlen)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, Key, NULL, NULL, 0, NULL, NULL);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    len = MIN(len, maxlen);
    memcpy(out, pem_str, len);
    out[len] = '\0';
    BIO_free(bio);
    return out;
}

/*
 * Generates an RSA public-private key pair and returns it.
 * The number of bits is specified by the bits argument.
 *
 * This uses the long way of generating an RSA key.
 */

static EVP_PKEY *generate_rsa_key(unsigned int bits)
{
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int primes = 2;
    OSSL_LIB_CTX *libctx = NULL;

    /* Create context using RSA algorithm. "RSA-PSS" could also be used here. */
    genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq);
    if (genctx == NULL) {
        printLastError("EVP_PKEY_CTX_new_from_name() failed");
        goto cleanup;
    }

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        printLastError("EVP_PKEY_keygen_init() failed");
        goto cleanup;
    }

    /*
     * Here we set the number of bits to use in the RSA key.
     * See comment at top of file for information on appropriate values.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) <= 0) {
        printLastError("EVP_PKEY_CTX_set_rsa_keygen_bits() failed");
        goto cleanup;
    }

    /*
     * It is possible to create an RSA key using more than two primes.
     * Do not do this unless you know why you need this.
     * You ordinarily do not need to specify this, as the default is two.
     *
     * Both of these parameters can also be set via EVP_PKEY_CTX_set_params, but
     * these functions provide a more concise way to do so.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) <= 0) {
        printLastError("EVP_PKEY_CTX_set_rsa_keygen_primes() failed");
        goto cleanup;
    }

    /*
     * Generating an RSA key with a number of bits large enough to be secure for
     * modern applications can take a fairly substantial amount of time (e.g.
     * one second). If you require fast key generation, consider using an EC key
     * instead.
     *
     * If you require progress information during the key generation process,
     * you can set a progress callback using EVP_PKEY_set_cb; see the example in
     * EVP_PKEY_generate(3).
     */
    if (EVP_PKEY_generate(genctx, &pkey) <= 0) {
        printLastError("EVP_PKEY_generate() failed");
        goto cleanup;
    }
cleanup:
    EVP_PKEY_CTX_free(genctx);
    /* pkey object is the generated key pair. */
    return pkey;
}

static  RSA *createRSA(uchar *key, int public)
{
    BIO *keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
        {
        printLastError("failed create BIO");
        return NULL;
        }
    RSA *rsa = RSA_new();
    if(public)
        {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
        }
    else
        {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
        }
    if(rsa == NULL)
        {
        printLastError("failed ot create RSA");
        }
    return rsa;
}

int     public_encrypt(uchar *data, int data_len, uchar *key, uchar *ebuf)
{
    RSA *rsa = createRSA(key, 1);
    if (!rsa)
        return -1;

    int maxlen = RSA_size(rsa);
    //printf("maxlen: %d\n", maxlen);
    if (data_len > maxlen)
        {
        RSA_free(rsa);
        printf("Cannot encrypt. (too long) %d\n", data_len);
        return -1;
        }
    int result = RSA_public_encrypt(data_len, data, ebuf, rsa, pad);
    RSA_free(rsa);
    return result;
}

int     private_decrypt(uchar * enc_data, int data_len, uchar *key, uchar *dbuf)
{
    RSA *rsa = createRSA(key, 0);
    if (!rsa)
        return -1;
    int  result = RSA_private_decrypt(data_len, enc_data,
                                        dbuf, rsa, pad);
    RSA_free(rsa);
    return result;
}


//////////////////////////////////////////////////////////////////////////
// Create mark file. Random block, one half is encrypted with the
// password and saved to the other half. Checking is done by
// decrypting the second half, comparing it to the first.
// Long enough to have more numbers than the starts in the universe
//

int     create_markfile(char *name, char *pass, int *plen)

{
    int loop, ret = 0;
    char *ttt = malloc(MARK_SIZE);
    if(!ttt)
        return -errno;

    //printf("use pass '%s'\n", pass);

    char *ttt2 = malloc(MARK_SIZE / 2);
    if(!ttt2)
        { free(ttt); return -errno; }

    srand(time(NULL));

    // Generate crap
    for(loop = 0; loop < MARK_SIZE; loop++)
        { ttt[loop] = rand() % 0xff; }

    // Verify:
    //for(loop = 0; loop < 30; loop++)
    //    printf("%x ", ttt[loop] & 0xff);

    memcpy(ttt2, ttt, MARK_SIZE / 2);
    bluepoint2_encrypt(ttt2, MARK_SIZE / 2, pass, *plen);
    memcpy(ttt + MARK_SIZE / 2, ttt2, MARK_SIZE / 2);
    if (ttt2) free(ttt2);

    //int fh = open(name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    int fh = open(name, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(fh < 1)
        { if(ttt) free(ttt); return -errno;}

    if (write(fh, ttt, MARK_SIZE) != MARK_SIZE)
        { if(ttt) free(ttt); close(fh); return -errno; }

    close(fh);

    if (ttt) free(ttt);

    return ret;
}

// See notes on create_markfile

int     check_markfile(char *name, char *pass, int *plen)

{
    int ret = 0;

    //printf("use pass '%s'\n", pass);

    // Checking
    char *ttt = malloc(MARK_SIZE);
    if(!ttt)
        return -errno;

    int fh = open(name, O_RDONLY);
    if(fh < 1)
        { if(ttt) free(ttt); return -errno; }

    if (read(fh, ttt, MARK_SIZE) != MARK_SIZE)
        {
        if(ttt) free(ttt); close(fh); return -errno;
        }

    close(fh);

    bluepoint2_decrypt(ttt + MARK_SIZE / 2, MARK_SIZE / 2, pass, *plen);
    ret = memcmp(ttt, ttt + MARK_SIZE / 2, MARK_SIZE / 2);

    if(ttt) free(ttt);

    return ret;
}

// -----------------------------------------------------------------------
// Read a line from the forked program

// Really dumb parse command line to array

void    parse_comstr(char *argx[], int limx, const char *program)

{
    //printf("parse: '%s'\n", program);

    // Parse command line
    char aa = 0, bb = 0, cc = 0;
    argx[cc] = NULL;
    char curr[128];
    while(1)
        {
        char chh = program[aa];
        //printf("%c", chh);
        if(cc >= limx-1)
            {
            //printf("Warn: argx limit %d\n", cc);
            argx[cc] = NULL;
            break;
            }
        if (chh == '\0')
            {
            //printf("estr: '%s'\n", curr);
            if (curr[0] != '\0')
                {
                argx[cc] = strdup(curr);
                cc++;
                }
            argx[cc] = NULL;
            break;
            }
        else if (chh == ' ')
            {
            //printf("str: '%s'\n", curr);
            if (curr[0] == '\0')
                {
                aa++;
                continue;
                }
            argx[cc] = strdup(curr);
            cc++; bb = 0;
            curr[bb] = '\0';
            }
        else
            {
            curr[bb] = chh;
            bb++;
            curr[bb] = '\0';
            }
        aa++;
        }
}

struct termios oldt;

void    sigint_local(int sig)

{
    tcsetattr(0, TCSANOW, &oldt);
    printf("\n");
    //printf("Local sig\n");
    exit(127);
}

char    *getpassx(char *prompt)

{
    static char ppp[128];
    char tmp[MAXPASSLEN];

    ppp[0] = '\0';

    sighandler_t oldsig = signal(SIGINT, sigint_local);
    printf("%s", prompt); fflush(stdout);
    struct termios newt;

    tcgetattr(STDIN_FILENO, &oldt); /* store old settings */
    tcgetattr(STDIN_FILENO, &newt); /* store old settings */

    /* make changes to in new settings */
    //newt.c_lflag &= ~(ICANON | ECHO | ECHONL | ISIG );
    newt.c_lflag &= ~(ICANON | ECHO | ECHONL );
    newt.c_oflag &= ~(OPOST);
    newt.c_iflag &= ~(IXON | ICRNL);

    int ret = tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int prog = 0;
    while(1==1)
        {
        if (prog >= sizeof(ppp)-1)
            {
            ppp[prog] = '\0';
            break;
            }
        int ddd = getchar();
        if(ddd == '\r' || ddd == '\n' || ddd == '\0')
            {
            ppp[prog] = '\0';
            break;
            }
        ppp[prog] = (char)ddd;
        prog++;
        }
    tcsetattr(0, TCSANOW, &oldt);
    signal(SIGINT, oldsig);
    printf("\n");
    return ppp;
}

/*
 * Fork a child and exec progran to get the password from the user.
 */

char    *hs_askpass(const char *program, char *buf, int buflen)

{
    struct sigaction  sa, saved_sa_pipe;
    int pfd[2];  pid_t pid;

    char *argx[12];
    parse_comstr(argx, 12, program);
    //int xx = 0; while(1)
    //    {
    //    hslog(0, "ptr: '%s'\n", argx[xx]);
    //    if(!argx[xx]) break;
    //    xx++;
    //    }
    if (access(argx[0], X_OK) < 0)
        {
        hslog(0, "Askpass is not an executable: '%s'", program);
        return "";
        }

    //char cwd[PATH_MAX];
    hslog(0, "Asking pass with program: '%s'", program);

    if (pipe(pfd) == -1)
	   {
        hslog(0, "Unable to create pipe.");
        //printf("Unable to create pipe.");
        //perror("Unable to create pipe");
        //return("");
        }
    if ((pid = fork()) == -1)
        {
        hslog(0, "Unable to fork");
        //printf("Unable to dup2");
        // perror("Unable to fork");
        return("");
        }
    if (pid == 0) {

        /* child, point stdout to output side of the pipe and exec askpass */
    	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
                hslog(0, "Unable to dup2");
                //printf("Unable to dup2");
                //_exit(255);
                return("");
    	       }
        //(void) dup2(pfd[1], STDOUT_FILENO);
        // Redirect error messages:
        int fh = open("/dev/null", O_RDWR );
    	(void) dup2(fh, STDERR_FILENO);

    	//set_perms(PERM_FULL_USER); //TODO
    	closefrom(STDERR_FILENO + 1);
        int ret = execvp(argx[0], argx) ;

        hslog(0, "Unable to run askpass: '%s' ret=%d", program, ret);
        // Clear error number so the FS can work
        errno = 0;

        // Free array
        int xx = 0; while(1)
            {
            if(!argx[xx]) break;
            free(argx[xx]);
            xx++;
            }

        //printf("Unable to run %s", program);
        // Try fallback:
        //char *fallback = "xfce4-terminal -e hsaskpass.sh";
        //execl(fallback, fallback, NULL);
    	//hslog(LOG_DEBUG, "Unable to run2 askpass: '%s'", fallback);
        //printf("Unable to run2 %s", fallback);
        //_exit(255);
        return("");
        }

    /* Ignore SIGPIPE in case child exits prematurely */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, &saved_sa_pipe);

    /* Get response from child and restore SIGPIPE handler */
    (void) close(pfd[1]);

    char *xpass = getlinex(pfd[0], buf, buflen);
    (void) close(pfd[0]);
    (void) sigaction(SIGPIPE, &saved_sa_pipe, NULL);

    int xx = 0; while(1)
        {
        if(!argx[xx]) break;
        free(argx[xx]);
        xx++;
        }
    //hslog(0, "Askpass got: '%s'", xpass);
    return(xpass);
}

// Get the password for the current mount and / or create a new one.
// Return 0 if all OK.

int     pass_ritual(char *mroot, char *mdata, char *pass, int *plen, char *passprog)

{
    char tmp[PATH_MAX]; char *xpass2 = NULL, *xpass = NULL;
    int ret = -1, xlen2 = 0, xlen = strlen(pass);

    //hsprint(TO_ERR|TO_LOG, -1, "pass_ritual() '%s'", pass);

    int pask = (xlen == 0) ? 1 : 0;

    // Check it against saved pass, warn if creating new mount
    char tmp2[PATH_MAX];
    strncpy(tmp2, mdata, sizeof(tmp));
    strcat(tmp2, passfname);
    struct stat ss;
    int rret = stat(tmp2, &ss);

    if(pask)
        {
        if(rret < 0 )
            sprintf(tmp,
                "About to create encrypted mount in: '%s'\n"
                "Please enter HSENCFS pass: ", mroot);
        else
            sprintf(tmp,
                "Mounting: '%s'\n"
                "Please enter HSENCFS pass: ", mroot);

        if (isatty(STDOUT_FILENO))
            xpass = getpassx(tmp);  //printf("password: '%s'\n", pass);
        else
            {
            //char tmp[MAXPASSLEN];
            //xpass = hs_askpass(passprog, tmp, MAXPASSLEN);
            }

        xlen = strlen(xpass);
        if(xlen == 0)
            {
            return 2;
            }
        // Dup the results right away, clear it too
        *plen = xlen;
        strcpy(pass, xpass);
        memset(xpass, 0, xlen);
        }

    // Always padd it
    if(xlen % 2)
        strncat(pass, "x", sizeof(pass));

    // Encrypt the results right away
    //*plen = strlen(pass);

    bluepoint2_encrypt(pass, *plen, progname, strlen(progname));

    //printpass(pass, *plen);

    if(rret < 0)
        {
        if(pask)
            {
            sprintf(tmp,
                "This is a new mount with no password set previously.\n"
                "Please re-enter HSENCFS pass: ");
            xpass2 = getpassx(tmp);
            xlen2 = strlen(xpass2);
            if(xlen2 == 0)
                {
                //fprintf(stderr, "Aborted.\n");
                ret = 2;
                return ret;
                }
            // Always padd it
            if(xlen2 % 2)
                strcat(xpass2, "x");
            xlen2 = strlen(xpass2);
            bluepoint2_encrypt(xpass2, xlen2, progname, strlen(progname));

            //printpass(xpass2, xlen2);

            if (memcmp(pass, xpass2, *plen))
                {
                memset(xpass2, 0, xlen2);
                //fprintf(stderr, "Passes do not match. Aborted\n");
                //if(loglevel > 0)
                //    syslog(LOG_DEBUG, "Passes do not match by uid: %d\n", getuid());
                ret = 3;
                return ret;
                }
            memset(xpass2, 0, xlen2);
            }
        ret = create_markfile(tmp2, pass, plen);
        if (ret)
            {
            hsprint(TO_ERR|TO_LOG, -1, "Error on creating markfile.\n");
            }
        }
    else
        {
        ret = check_markfile(tmp2, pass, plen);
        //if (ret)
        //    {
        //    hsprint(TO_ERR|TO_LOG, -1, "Invalid pass entered by uid: %d\n", getuid());
        //    }
        //printf("Checking '%s' got %d", tmp2, ret);
        }
    return ret;
}

// EOF
