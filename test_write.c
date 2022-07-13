#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
int batch = 10000;
unsigned long int total_sec = 0, total_usec = 0;
unsigned long int average_sec, average_usec;
char *buf = "spike is handsome!!!";

void write_time (int fd) {
        struct timeval tv_begin,tv_end;
        gettimeofday(&tv_begin,NULL);
        for (int i = 0; i < 1000; i++) {
                write(fd,buf,strlen(buf));
        }
        gettimeofday(&tv_end,NULL);
        close(fd);
        unsigned int sec = tv_end.tv_sec - tv_begin.tv_sec;
        unsigned int usec = tv_end.tv_usec - tv_begin.tv_usec;
        total_sec += sec;
        total_usec += usec;
}

int main()
{
        int fd;
        char *filename = "/home/spike/workspace/project1/measure/sen2.txt";
        fd = open(filename,O_RDWR);
        printf("fd = %d\n",fd);
        if(fd == -1){
                printf("open file1 fail!!\n");
                fd = open(filename,O_RDWR|O_CREAT,0600);
                if(fd > 0){
                printf("create file1 success!!!\n");
                }else if(fd == -1){
                        printf("creat file1 success!!\n");
                }
        }else{
                printf("open file1 success!!!\n");
        }
        for (int i = 0; i < batch; i++) write_time (fd);
        average_sec = total_sec / batch;
        average_usec = total_usec / batch;
        printf ("Average time cost : %ld s %ld us", average_sec, average_usec);
        char tmp[64];
        fgets(tmp, 64, stdin);
        return 0;
}