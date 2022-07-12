#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sqlite3.h>
#include <time.h>
#define NETLINK_TEST 30
#define MAX_PAYLOAD 4096 /* maximum payload size*/
#define MAX_NL_BUFSIZ NLMSG_SPACE(MAX_PAYLOAD)

#define PAGE_SIZE 4096
#define PAGEMAP_ENTRY 8
#define GET_BIT(X, Y) (X & ((uint64_t)1 << Y)) >> Y
#define GET_PFN(X) X & 0x7FFFFFFFFFFFFF
#define print(X, Y) { printf ("* "#X" : %s\n", Y); }
#define print_fmt(X, Y, Z) { printf ("* "#X" : "#Y"\n", Z); }

const int __endian_bit = 1;
#define is_bigendian() ((*(char *)&__endian_bit) == 0)

int PORTID = 1;
int proc_pid;
char *send_buf;

unsigned long elftextstart = 0, elftextend;     // elf文件中text段的开始和结尾地址
uint64_t virstart, virend;                      //进程代码段的开始和结尾

#define DBPATH "./metric.db" //设置数据库的文件路经
sqlite3 *db;
char sql_insert[128] = {};
char sql_query[128] = {};
#define MAXROW 409600

void read_pagemap_and_measurement_process(char *target_buf, char *elfpath)
{
    int i;
    uint64_t start_offset, curr_offset, end_offset;
    unsigned char tmp;

    int nrow = 0, ncol = 0;
    char *zErrMsg = 0;
    char **texthash;    //用来储存elf文件中text段的分页hash值

    memset(sql_query, 0, sizeof(sql_query));
    sprintf(sql_query, "select hash from elftexthash where filepath like '%s';", elfpath);
    sqlite3_get_table(db, sql_query, &texthash, &nrow, &ncol, &zErrMsg);
    int index = ncol;
    if(nrow != 0){      
        strcat(target_buf,texthash[1]);
        strcat(target_buf,"\n");
    }
    sqlite3_free_table(texthash);
    printf ("* elfpath:%s\n", elfpath);
    
    //数据库中不存在代码段hash
    if (nrow == 0){
        int elf_text_page_num = 0;
        int len = 0;

        elftextstart = 0;
        elftextend = virend - virstart;     //通过虚拟地址的范围获取elf文件代码段的长度。
        loff_t pos = 0;
        size_t readsize;

        FILE *fp = NULL;
        fp = fopen(elfpath, "rb");
        if (fp == NULL){
            perror("fopen()");
            return;
        }
        char con_path[30] ={}; 
        sprintf(con_path,"/tmp/elf%dcon.txt",proc_pid);
        FILE *con = fopen(con_path, "ab+");
        unsigned char buf[PAGE_SIZE];

        while (1){
            if (pos >= elftextend)
                break;
            memset(buf, 0, PAGE_SIZE);
            fseek(fp, pos, 0);
            readsize = fread(buf, 1, PAGE_SIZE, fp);
            if (readsize != PAGE_SIZE){
                buf[readsize] = '\0';
            }
            int size=fwrite(buf,1,readsize,con);   //fwrite : (数据缓冲区，一次写入的单位，写入的次数，要写入的文件指针)
            elf_text_page_num++;
            pos += PAGE_SIZE;
        }

        fclose(fp);
        fclose(con);

        char *command=(char *)malloc(sizeof(char) * 128);
        memset(command,0,sizeof(command));
        char elfhash_path[30] ={};
        sprintf(elfhash_path,"/tmp/elf%dhash.txt",proc_pid);
        sprintf(command, "tpm2_hash -g sha256 -H e -o %s %s", elfhash_path,con_path);
        // printf ("* command : %s\n", command);
        
        FILE *log = fopen(elfhash_path, "wb+");
        if (log == NULL){
            perror("fopen()");
            return;
        }
        int status = system(command);
        unlink(con_path);

        char *hash_str = (char *)malloc(sizeof(char) * 65);     /* 为字符串分配堆空间 */
        memset(hash_str, 0, 65);
        fread(hash_str, 1, 64, log);
        fclose(log);
        strcat(target_buf,hash_str);
        strcat(target_buf,"\n");
        unlink(elfhash_path);

        memset(sql_insert, 0, sizeof(sql_insert));
        sprintf(sql_insert, "insert into elftexthash values('%s', '%s');", elfpath, hash_str);
        if (sqlite3_exec(db, sql_insert, NULL, NULL, NULL) != SQLITE_OK){
            printf("* insert error\n");
            //return;
        }
        else{
            printf("* insert success\n");
        }
    }

    printf("* virstart:%#lx\n* virend:%#lx\n", virstart, virend);
    start_offset = virstart / PAGE_SIZE * PAGEMAP_ENTRY;   //计算得到虚拟地址在pagemap中表项的开始地址
    curr_offset = start_offset;
    end_offset = virend / PAGE_SIZE * PAGEMAP_ENTRY;        //虚拟地址在pagemap表项中的结束位置

    int cnt = 0;
    char *tmp_buf = (char *)malloc(128);
    
    FILE *f;
    char pagemap_path[0x100] = {};
    sprintf(pagemap_path, "/proc/%u/pagemap", proc_pid);
    f = fopen(pagemap_path, "rb");
    if (f == NULL){
        printf("Error! Cannot open %s\n", pagemap_path);
        return;
    }
    print (pagemap_path, pagemap_path);
    
    uint64_t file_offset = virstart / PAGE_SIZE * PAGEMAP_ENTRY;
    printf("* Vaddr: 0x%lx, Page_size: %d, Entry_size: %d\n", virstart, PAGE_SIZE, PAGEMAP_ENTRY);
    printf("* Reading %s at 0x%llx\n", pagemap_path, (unsigned long long) file_offset);

    unsigned char c_buf[PAGEMAP_ENTRY];
    while (1){
        unsigned long read_val = 0;
        if (curr_offset >= end_offset)
            break;
        int status = fseek(f, curr_offset, SEEK_SET);
        if (status){                                                                                                                 
            perror("Failed to do fseek!");
            return;
        }
        
        //读取物理页帧
        int c;
        printf("* ");
        for(i = 0; i < PAGEMAP_ENTRY; i++){
            c = getc(f);
            if(c == EOF){
                printf("\nReached end of the file\n");
                return;
            }
            if(is_bigendian()) c_buf[i] = c;
            else c_buf[PAGEMAP_ENTRY - i - 1] = c;
            printf("[%d]0x%x ", i, c);
        }
        for(i = 0; i < PAGEMAP_ENTRY; i++){
            read_val = (read_val << 8) + c_buf[i];
        }
        printf("\n");
        printf("* Result: 0x%llx\n", (unsigned long long) read_val);

        if (GET_BIT(read_val, 63)){
            memset(tmp_buf, 0, sizeof(tmp_buf));
            sprintf(tmp_buf, "%lx\n%x\n", GET_PFN(read_val), cnt);
            print_fmt (read_val, %lx, read_val);
            cnt++;
            strcat(target_buf, tmp_buf);
        }
        curr_offset += PAGEMAP_ENTRY;
    }
    fclose(f);
}

char *getTarget(int process_pid)
{
    FILE *stream;
    char addr1[32];
    char addr2[32];
    char elfpath[64];
    char cmd[64];
    char cmd1[64];
    char cmd2[64];
    char cmd3[64];
    char *target_buf;
    target_buf = (char *)malloc(4096);
    // 1
    memset(addr1, 0, sizeof(addr1));
    memset(addr2, 0, sizeof(addr2));
    memset(elfpath, 0, sizeof(elfpath));
    memset(cmd, 0, sizeof(cmd));
    memset(cmd1, 0, sizeof(cmd1));
    memset(cmd2, 0, sizeof(cmd2));
    memset(cmd3, 0, sizeof(cmd3));
    memset(target_buf, 0, sizeof(target_buf));
    // 2
    int row=1;
    char inode[32];
    while(row<MAXROW){
        sprintf(cmd, "cat /proc/%d/maps | awk 'NR==%d' | awk -F ' ' '{print $5}'", process_pid,row);
        stream=popen(cmd,"r");
        memset(inode,0,sizeof(inode));
        fread(inode,sizeof(char),sizeof(inode),stream);
        if(strcmp(inode,"0\n")){
            pclose(stream);
            break; 
        }
        row++;
    }
    
    sprintf(cmd1, "cat /proc/%d/maps | awk 'NR==%d' | awk -F '-' '{print $1}'", process_pid,row);
    sprintf(cmd2, "cat /proc/%d/maps | awk 'NR==%d' | awk -F '[- ]' '{print $2}'", process_pid,row);
    sprintf(cmd3, "cat /proc/%d/maps | awk 'NR==%d' | awk -F ' ' '{print $6}'", process_pid,row);
    // 3
    stream = popen(cmd1, "r");
    fread(addr1, sizeof(char), sizeof(addr1), stream);
    stream = popen(cmd2, "r");
    fread(addr2, sizeof(char), sizeof(addr2), stream);
    stream = popen(cmd3, "r");
    fread(elfpath, sizeof(char), sizeof(elfpath), stream);
    pclose(stream);

    time_t now;
    struct tm *tm_now;
    char    datetime[128];
    time(&now);
    tm_now = localtime(&now);
    strftime(datetime, 200, "%Y-%m-%d %H:%M:%S\n", tm_now);
    printf("now datetime : %s\n", datetime);

    sprintf(target_buf, "%s%s%s", datetime, addr1, addr2);
    printf ("target buf : %s", target_buf);
    char **endp = NULL;
    virstart = strtoul(addr1, endp, 16);
    virend = strtoul(addr2, endp, 16);
    elfpath[strlen(elfpath) - 1] = '\x00';
    read_pagemap_and_measurement_process(target_buf, elfpath);
    return target_buf;
}

int create_nl_socket(uint32_t pid, uint32_t groups)
{
    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if (fd == -1){
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = pid;
    addr.nl_groups = groups;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        close(fd);
        return -1;
    }

    return fd;
}

ssize_t nl_recv(int fd)
{
    char nl_tmp_buffer[MAX_NL_BUFSIZ];
    struct nlmsghdr *nlh;
    ssize_t ret;

    // 设置 Netlink 消息缓冲区
    nlh = (struct nlmsghdr *)&nl_tmp_buffer;
    memset(nlh, 0, MAX_NL_BUFSIZ);

    ret = recvfrom(fd, nlh, MAX_NL_BUFSIZ, 0, NULL, NULL);
    if (ret < 0){
        return ret;
    }

    printf("==== LEN(%d) TYPE(%d) FLAGS(%d) SEQ(%d) PID(%d)\n", nlh->nlmsg_len, nlh->nlmsg_type,
           nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
    proc_pid = atoi(NLMSG_DATA(nlh));
    printf("Received pid: %d\n", proc_pid);
    send_buf = getTarget(proc_pid);
    return ret;
}

int nl_sendto(int fd, void *buffer, size_t size, uint32_t pid, uint32_t groups)
{
    char nl_tmp_buffer[MAX_NL_BUFSIZ];
    struct nlmsghdr *nlh;

    if (NLMSG_SPACE(size) > MAX_NL_BUFSIZ){
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = pid;       /* Send messages to the linux kernel. */
    addr.nl_groups = groups; /* unicast */

    // 设置 Netlink 消息缓冲区
    nlh = (struct nlmsghdr *)&nl_tmp_buffer;
    memset(nlh, 0, MAX_NL_BUFSIZ);
    nlh->nlmsg_len = NLMSG_LENGTH(size);
    nlh->nlmsg_pid = PORTID;
    memcpy(NLMSG_DATA(nlh), buffer, size);

    return sendto(fd, nlh, NLMSG_LENGTH(size), 0, (struct sockaddr *)&addr, sizeof(addr));
}

int main(void){
    int sockfd = create_nl_socket(PORTID, 0);
    if (sockfd == -1){
        return 1;
    }
    if (sqlite3_open(DBPATH, &db) != SQLITE_OK){
        printf("Open sqlite error.\n");
        return -1;
    }
    while (1){
        if (nl_recv(sockfd) > 0){
            printf("##########################\nsend to kernel : \n%s##########################\n", send_buf);
            nl_sendto(sockfd, send_buf, strlen(send_buf), 0, 0);
        }
    }

    sqlite3_close(db);
    return 0;
}