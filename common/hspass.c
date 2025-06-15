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
#include <signal.h>
#include <termios.h>
#include <getopt.h>
#include <stdarg.h>

#include <sys/time.h>
#include <sys/wait.h>

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

#include "hsencdef.h"
//#include "hsencfs.h"
#include "hsutils.h"
#include "hspass.h"
#include "xmalloc.h"
#include "base64.h"
#include "bluepoint2.h"

// The decoy deployed occasionally to stop spyers
// from figuring out where pass is stored

char    decoy[MAXPASSLEN];
char    defpassx[MAXPASSLEN];
char    decoy2[MAXPASSLEN];
char    defpassx2[MAXPASSLEN];

char    *passfname = ".passdata.datx";
char    *myext = ".datx";

static int  getlinex(int fd, char *buf, size_t bufsiz)

{
    size_t left = bufsiz;
    ssize_t nr = -1;
    char *cp = buf; char c = '\0';

    // Terminator here
    *cp = c;

    if (left == 0) {

    	errno = EINVAL;
    	return(0);			/* sanity */
    }

    while (--left) {
	   nr = read(fd, &c, 1);
    	//if (nr != 1 || c == '\n' || c == '\r')
    	if (nr == 0)
    	    break;
	   *cp++ = c;
    }
    *cp = '\0';

    return 0; //(nr == 1 ? buf : NULL);
}

// -----------------------------------------------------------------------
// Just for checking, do not use in production code.

#if 0
static  void printpass(char *pp, int ll)
{
    char *ttt = xmalloc(ll);
    if(ttt)
        {
        memcpy(ttt, pp, ll); ttt[ll] = 0;
        bluepoint2_decrypt(ttt, ll, progname, strlen(progname));
        //printf("got pass '%s'\n", ttt);
        // Erase it by encrypt / clear
        bluepoint2_encrypt(ttt, ll, progname, strlen(progname));
        memset(ttt, 0, ll);
        xsfree(ttt);
        }
}
#endif

//// -----------------------------------------------------------------------
//// Create asyn encryption
//
////define MIN(aa, bb) aa > bb ? bb : aa
//typedef unsigned char uchar;
//

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

//static int pad = RSA_PKCS1_PADDING;
//static int pad = RSA_NO_PADDING;
static int pad = RSA_PKCS1_OAEP_PADDING;

static const char *propq = NULL;

static void printLastError(char *msg)
{
    ERR_load_crypto_strings();
    char *err = xmalloc(130);;
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    xsfree(err);
}

static char* publicKeyToString(EVP_PKEY* pubKey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubKey);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    char *out = xmalloc(len + 1);
    if(out)
        {
        memcpy(out, pem_str, len);
        out[len] = '\0';
        }
    BIO_free(bio);
    return out;
}

static char* privateKeyToString(EVP_PKEY* Key)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, Key, NULL, NULL, 0, NULL, NULL);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    char *out = xmalloc(len + 1);
    if(out)
        {
        memcpy(out, pem_str, len);
        out[len] = '\0';
        }
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
//
// Create mark file. Random block, one half is encrypted with the
// password and saved to the other half. Checking is done by
// decrypting the second half, comparing it to the first.
// Long enough to have more numbers than the number of stars in
// the universe. Password never stored.
//

int     create_markfile(const char *name, char *pass, int plen)

{
    int loop, ret = 0, fh = -1;
    char *ttt = NULL, *ttt2 = NULL;

    //printf("use pass '%s'\n", pass);

    ttt = xmalloc(MARK_SIZE);
    if(!ttt)
        {
        ret = HSPASS_MALLOC;  goto cleanup;
        }
    ttt2 = xmalloc(MARK_SIZE / 2);
    if(!ttt2)
        {
        ret = HSPASS_MALLOC;  goto cleanup;
        }
    srand(time(NULL));
    // Generate crap
    for(loop = 0; loop < MARK_SIZE; loop++)
        {
        ttt[loop] = rand() % 0xff;
        }

    // Verify:
    //for(loop = 0; loop < 30; loop++)
    //    printf("%x ", ttt[loop] & 0xff);

    memcpy(ttt2, ttt, MARK_SIZE / 2);
    bluepoint2_encrypt(ttt2, MARK_SIZE / 2, pass, plen);
    memcpy(ttt + MARK_SIZE / 2, ttt2, MARK_SIZE / 2);

    //int fh = open(name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    fh = open(name, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(fh < 0)
        {
        ret = HSPASS_ERRFILE; goto cleanup;
        }
    if (write(fh, ttt, MARK_SIZE) != MARK_SIZE)
        {
        ret = HSPASS_ERRWRITE; goto cleanup;
        }
  cleanup:
    if (ttt) xsfree(ttt);
    if (ttt2) xsfree(ttt2);
    if(fh >=0 ) close(fh);

    return ret;
}

// Updated for constant time search

static int     seccomp(const char *s1, const char *s2, int len)

{
    int ret = 0, ret2 = 0;
    for(int aa = 0; aa < len; aa++)
        {
        //printf("%d %d ", *s1, *s2);
        char cret = *s1++ - *s2++;
        //printf("%d  ", (int)cret);
        if(cret && ret == 0)
            ret = (int)cret;
        else
            ret2 = (int)cret;
        }
    return ret;
}

// See notes on create_markfile

int     check_markfile(const char *fname, char *pass, int plen)

{
    int ret = 0;

    //printf("use pass '%s'\n", pass);

    // Checking
    char *ttt = xmalloc(MARK_SIZE);
    if(!ttt)
        {
        hsprint(TO_EL, 1, "Cannot alloc markfile");
        return -errno;
        }
    int fh = open(fname, O_RDONLY);
    if(fh < 1)
        {
        ret = -errno;
        goto cleanup;
        }
    if (read(fh, ttt, MARK_SIZE) != MARK_SIZE)
        {
        close(fh);
        ret = -errno;
        goto cleanup;
        }
    close(fh);

    bluepoint2_decrypt(ttt + MARK_SIZE / 2, MARK_SIZE / 2, pass, plen);
    ret = seccomp(ttt, ttt + MARK_SIZE / 2, MARK_SIZE / 2);

  cleanup:
    if(ttt) xsfree(ttt);
    return ret;
}

static struct termios oldt;

void    sigint_local(int sig)

{
    tcsetattr(0, TCSANOW, &oldt);
    printf("\n");
    //printf("Local sig\n");
    exit(127);
}

char    *getpassx(char *prompt)

{
    char *tmp = xmalloc(MAXPASSLEN);
    if(!tmp)
        return(NULL);
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
        if (prog >= MAXPASSLEN-1)
            {
            tmp[prog] = '\0';
            break;
            }
        int ddd = getchar();
        if(ddd == '\r' || ddd == '\n' || ddd == '\0')
            {
            tmp[prog] = '\0';
            break;
            }
        tmp[prog] = (char)ddd;
        prog++;
        }
    tcsetattr(0, TCSANOW, &oldt);
    signal(SIGINT, oldsig);
    //printf("\n");
    return tmp;
}

/*
 * Fork a child and exec progran to get the password from the user.
 */

int     hs_askpass(const char *program, char *buf, int buflen)

{
    //return 1;
    struct sigaction  sa, saved_sa_pipe;
    int pfd[2];  pid_t pid;
    int mainret = 0;

    //printf("hsaskpass() progfile: '%s'\n", program);

    char *argx[12]; argx[0] = NULL;
    int idx = parse_comstr(argx, sizeof(argx)/sizeof(char*), program);
    //if (access(argx[0], X_OK) < 0)
    //    {
    //    hsprint(TO_ERR | TO_LOG, -1,
    //            "Askpass is not an executable: '%s'\n", program);
    //    mainret = -1;
    //    goto cleanup;
    //    }
    //char cwd[PATH_MAX];
    //hsprint(TO_ERR | TO_LOG, 3, "Asking pass with program: '%s'", program);

    EVP_PKEY *rsa_key = generate_rsa_key(2048);
    char* pub_ptr = publicKeyToString(rsa_key);
    //printf("%s\n", hexdump(pub_ptr, strlen(pub_ptr) ));

    //argx[idx] = strdup("--loglevel");   argx[idx+1] = NULL;  idx++;
    //argx[idx] = strdup("5");            argx[idx+1] = NULL; idx++;

    argx[idx] = strdup("--pubkey");  argx[idx+1] = NULL;  idx++;
    argx[idx] = strdup(pub_ptr);     argx[idx+1] = NULL; idx++;

    char* priv_ptr = privateKeyToString(rsa_key);
    if (pipe(pfd) == -1)
        {
        hsprint(TO_ERR | TO_LOG, 2, "Unable to create pipe.");
        mainret = -1;
        goto cleanup;
        }
    if ((pid = fork()) == -1)
        {
        hsprint(TO_ERR | TO_LOG, 2, "Unable to fork");
        mainret = HSPASS_NOEXEC;
        goto cleanup;
        }
    if (pid == 0)
        {
        /* child, point stdout to output side of the pipe and exec askpass */
    	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
                hsprint(TO_ERR | TO_LOG, 2, "Unable to dup2");
                mainret = HSPASS_NOEXEC;
                goto cleanup;
    	       }
        //(void) dup2(pfd[1], STDOUT_FILENO);
        //(void) dup2(pfd[1], STDERR_FILENO);
    	//set_perms(PERM_FULL_USER); //TODO
    	closefrom(STDERR_FILENO + 1);
        //arr2log(argx);
        int retx = execvp(argx[0], argx) ;
        hsprint(TO_ERR | TO_LOG, 2,
            "Unable to run askpass: '%s' ret=%d", program, retx);
        // Clear error number so the FS can work
        errno = 0;    // ??
        //mainret = HSPASS_NOEXEC;
        //goto cleanup;
        exit(1);   // Error exit, so parent knows
        }
    /* Ignore SIGPIPE in case child exits prematurely */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, &saved_sa_pipe);

    int status = 0;
    pid_t pidx = waitpid(pid, &status, 0);

    /* Get response from child */
    (void) close(pfd[1]);

    char *tmp6 = xmalloc(2 * MAXPASSLEN);
    getlinex(pfd[0], tmp6, 2 * MAXPASSLEN);
    hsprint(TO_ERR | TO_LOG, 2, "hspass() stdout: '%s'\n", tmp6);
    if (status)
        {
        xsfree(tmp6);
        hsprint(TO_ERR | TO_LOG, 2, "exe askpass return status: %d", status);
        mainret = -5;
        goto cleanup;
        }
    unsigned long olen = 0;
    unsigned char *res2 = base64_decode(tmp6, strlen(tmp6), &olen);
    xsfree(tmp6);
    if(!res2)
        {
        hsprint(TO_ERR | TO_LOG, 2, "hspass() cannot decode.\n");
        }
    else
        {
        //printf("hspass() decoded:\n");
        //hexdump(res2, olen); printf("\n");
        char *tmp5 = xmalloc(MAXPASSLEN * 2);
        if(tmp5)
            {
            memset(tmp5, '\0', MAXPASSLEN * 2);
            int   ret = private_decrypt(res2, olen, priv_ptr, tmp5);
            //printf("decoded: len=%d '%s'\n", ret, tmp5);
            xsfree(res2);
            if(ret >= 0)
                strcpy(buf, tmp5);
            xsfree(tmp5);
            }
        }
    (void) close(pfd[0]);
    /* and restore SIGPIPE handler */
    (void) sigaction(SIGPIPE, &saved_sa_pipe, NULL);

  cleanup:
    if( pub_ptr)  xsfree(pub_ptr);
    if( priv_ptr) xsfree(priv_ptr);

    // xsfree array
    { int xx = 0; while(1)
        {
        if(!argx[xx]) break;
        xsfree(argx[xx]);
        xx++;
        }
    }
    return(mainret);
}

// Get the password for the current mount and / or create a new one.
// Return 0 if all OK.

int     pass_ritual(PassArg *parg)

{
    int zret = 0;

    //xmdump(0);
    //printf("Bound ---\n");
    //hsprint(TO_ERR|TO_LOG, 1, "pass_ritual() '%s'", parg->title);

    char *ppp;
    if(parg->create)
        {
        ppp = "About to create encrypted mount in: '%s'\n"
               "Please enter  HSENCFS pass: ";
        }
    else
        {
        ppp = "Mounting: '%s'\n"
              "Please enter HSENCFS pass: ";
        }
    char *tmp2 = xmalloc(PATH_MAX);
    if(!tmp2)
        {
        //printf("Memory alloc error\n");
        zret = HSPASS_MALLOC;
        goto cleanup;
        }
    snprintf(tmp2, PATH_MAX, ppp, parg->mountstr);
    char *xpass = getpassx(tmp2);
    printf("\n");
    xsfree(tmp2);
    if(!xpass)
        {
        //printf("Memory alloc error\n");
        zret = HSPASS_MALLOC;
        goto cleanup;
        }
    int xlen = strlen(xpass);
    if(xlen == 0)
        {
        //xsfree(xpass);
        //printf("Empty pass.\n");
        zret = HSPASS_NOPASS;
        goto cleanup;
        }
    if(parg->create)
        {
        //printf("xpass '%s'\n", xpass);
        char *tmp3 = xmalloc(PATH_MAX);
        if(!tmp3)
            {
            xsfree(xpass);
            //printf("Memory alloc error.\n");
            zret = HSPASS_MALLOC;
            goto cleanup;
            }
        snprintf(tmp3, PATH_MAX, "Please verify HSENCFS pass: ");
        char *xpass2 = getpassx(tmp3);
        printf("\n");
        xsfree(tmp3);
        if(!xpass2)
            {
            xsfree(xpass);
            //printf("Memory alloc error.\n");
            zret = HSPASS_MALLOC;
            goto cleanup;
            }
        int xlen2 = strlen(xpass2);
        if(seccomp(xpass, xpass2, MAX(xlen, xlen2)))
            {
            xsfree(xpass); xsfree(xpass2);
            //printf("Passes do not match\n");
            zret = HSPASS_NOMATCH;
            goto cleanup;
            }
        zret = create_markfile(parg->markfname, xpass, xlen);
        if(zret == 0)
            {
            printf("created markfile, pass '%s'\n", xpass);
            //printf("created markfile: %d\n", ret);
            strcpy(parg->result, xpass);
            }
        xsfree(xpass); xsfree(xpass2);
        }
    else
        {
        //printf("xpass '%s'\n", xpass);
        zret = check_markfile(parg->markfname, xpass, xlen);
        if (zret == 0)
            {
            printf("check markfile, pass '%s'\n", xpass);
            strcpy(parg->result, xpass);
            }
        //printf("checked markfile: %d\n", ret);
        xsfree(xpass);
        }

   cleanup:
    //xmdump(0);
    return zret;
}

int     pass_gui_ritual(PassArg *parg)
{
    int yret = 0;
    //char *xpass = xmalloc(MAXPASSLEN);
    //if(!xpass)
    //    {
    //    hsprint(TO_EL, 9, "Error on alloc gui ritual.\n");
    //    yret = HSPASS_MALLOC;
    //    goto cleanup;
    //    }

    int ret = hs_askpass(parg->passprog, parg->result, MAXPASSLEN);
    //printf("hsaskpass ret: %d\n", ret);
    if(ret)
        {
        hsprint(TO_EL, 9, "Error on  getting pass %d\n", ret);
        yret = HSPASS_NOEXEC;
        goto cleanup;
        }
    //hsprint(TO_EL, 9, ("hs_askpass() %d returned pass: '%s'\n", ret, xpass);
    int xlen = strlen(parg->result);
    if(!xlen)
        {
        //printf("No gui pass, aborted.\n");
        yret = HSPASS_NOPASS;
        goto cleanup;
        }
    //hsprint(TO_EL, 9, "pass: '%s'\n", xpass);
    if(parg->create)
        {
        yret = create_markfile(parg->markfname, parg->result, xlen);
        hsprint(TO_EL, 9, "created markfile: %d\n", yret);
        }
    else
        {
        yret = check_markfile(parg->markfname, parg->result, xlen);
        }

cleanup:
     hsprint(TO_EL, 9, "created markfile: %d\n", ret);

    //if(xpass) xsfree(xpass);
    return yret;
}

// Front end for asking pass

int     getpass_front(PassArg *parg)

{
    int yret = 0;

    //xmdump(0);
    //printf("-----\n");

    if(parg->gui)
        yret = pass_gui_ritual(parg);
    else
        yret = pass_ritual(parg);

  cleanup:
    //xmdump(0);

    return yret;
}

// -----------------------------------------------------------------------
// Check if it is our internal file

int     is_our_file(const char *path, int fname_only)

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

// EOF
