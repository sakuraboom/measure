#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
 
int main()
{
	int fd = open("/home/spike/workspace/project1/measure/sen2.txt",O_RDWR);
	printf("fd = %d\n",fd);

	char *readBuf;
	readBuf = (char*)malloc(sizeof(char)*1024);
    for (int i = 0; i < 1000; i++) {
        int n_read = read(fd,readBuf,20);   
	    printf("n_read = %d,context = %s\n",n_read,readBuf);
    }
	close(fd);
    char tmp[64];
    fgets(tmp, 64, stdin);;
 
	return 0;
}