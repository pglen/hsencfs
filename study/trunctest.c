///////////////////////////////////////////////////////////////////////////
// File truncation test 
//
// See if data survives after truncate / un-truncate
// On Linux data did not survive, data is destroyed
// On windows data survived, but it was unreliable.
//
///////////////////////////////////////////////////////////////////////////

#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "sys/stat.h"
#include "sys/types.h"
#include "fcntl.h"

char buff[1024];
char pass[128];
int plen;

char str[] = "Hello World";
char str2[100];

int main(int argc, char *argv[])

{
    printf("File truncation test\n");
    
    int fh = open("trunc", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    write(fh, str, strlen(str)); 
    ftruncate(fh, 5);
    lseek(fh, SEEK_SET, 25);
    close(fh);
    
    int fh2 = open("trunc", O_RDWR);
    //ftruncate(fh, 25);
    lseek(fh2, SEEK_SET, 25);
    int ret = read(fh2, str2, sizeof(str2));
    printf("%d %s\n", ret, str2);
    
    exit(0);    
}











