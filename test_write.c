#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
int main()
{
        int fd;
        char *filename = "/home/spike/workspace/project1/measure/sen2.txt";
        char *buf = "luyi is handsome!!";
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
        write(fd,buf,strlen(buf));
        
        char tmp[64];
        gets(tmp);
        close(fd);
 
        return 0;
}