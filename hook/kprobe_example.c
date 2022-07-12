#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/rtc.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/kallsyms.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/ctype.h>
#include <linux/fdtable.h>
#include<linux/slab.h>
#include <linux/sched.h>
MODULE_LICENSE("GPL");

#define MAX_FILE_NAME_LEN 512

//#define PAGE_SIZE 4096	//每页大小
#define PAGEMAP_ENTRY 8											// /proc/pid/pagemap文件内的每一项的字节长度
#define GET_BIT(X, Y) (X & ((uint64_t)1 << Y)) >> Y 			//返回位数组中,指定位的值,X:位数组，Y:位置
#define GET_PFN(X) (X & 0x7FFFFFFFFFFFFF)						//从pagemap的项中获取页框号(后面要加括号)
const int __endian_bit = 1;
#define is_bigendian() ((*(char *)&__endian_bit) == 0) 			//判断是否为大端存储

int pid = -1;
int len;										//代码段长度
unsigned char *result;

unsigned long virstart, virend; 				//进程代码段的虚拟地址的开始和结尾(左闭右开区间)
static char filepath[64];						// = "/home/ubuntu/Documents/measure/hello";	//可执行文件所在目录
unsigned long elftextstart = 0, elftextend; 	// elf文件中text段的开始和结尾地址
unsigned long read_vals[1024];
unsigned int page_cnt = 0;
unsigned int page_cnts[1024];
char *elftexthash;								//用来储存elf文件中text段的hash值

//函数声明，方便调用
unsigned int close_cr(void);
void open_cr(unsigned int oldval);
void start_hook(void);
int test_unicast(void *data, size_t size, __u32 pid);
static void nl_recv_msg(struct sk_buff *skb);

mm_segment_t old_fs;

#define NETLINK_TEST 30
static struct sock *nl_sk = NULL;
static struct completion comp;				//补充原语，起到同步的作用

//对系统调用进行Hook的相关结构体
asmlinkage long (*orig_mkdir)(const struct pt_regs * regs);
asmlinkage long (*orig_read)(const struct pt_regs * regs);
asmlinkage long (*orig_write)(const struct pt_regs * regs);
asmlinkage long (*orig_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
uint64_t **g_sys_call_table = 0; // save address of sys_call_table
long g_oldcr0 = 0; 

const char *pathname;

//读取并将白名单内容存储到whitelist数组
#define LISTLEN 60
#define BUFLEN 25
char whitelist[LISTLEN][BUFLEN];
int cnt=0;

//读取并将敏感文件列表存储到senlist数组
#define SENLISTLEN 5
#define SENBUFLEN 128
char senlist[SENLISTLEN][SENBUFLEN];
int cnt1=0;

//kprobe模块相关变量
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static struct kprobe kp = {
	.symbol_name	= symbol,
};

void read_pagemap_and_measurement_process(void)
{
	loff_t start_offset, curr_offset, end_offset;
	unsigned long curr_vir_addr;
	unsigned long read_val;
	unsigned long physical_page_addr;

	printk("virstart:%#lx\nvirend:%#lx\n", virstart, virend);
	start_offset = virstart / PAGE_SIZE * PAGEMAP_ENTRY;
	curr_offset = virstart / PAGE_SIZE * PAGEMAP_ENTRY;
	end_offset = virend / PAGE_SIZE * PAGEMAP_ENTRY;
	curr_vir_addr = virstart;
	len=0;
	
	struct file *con_file = NULL; 
	char con_path[30] ={};
    sprintf(con_path,"/tmp/tmp%dcon.txt",current->tgid);
	if (con_file == NULL){
		con_file = filp_open(con_path, O_RDWR|O_CREAT|O_APPEND, 0644);
	}
	//错误判断
	if (IS_ERR(con_file)){
		printk("opening file %s error.\n", con_path);
		return -1;
	}
	// return ;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	printk ("page_cnt = %d", page_cnt);
	int i = 0;
	while (i < page_cnt)
	{
		if (curr_offset >= end_offset)
			break;

		read_val = read_vals[i];
		printk("curr_vir_addr:%013X   ", curr_vir_addr);
		printk("curr_offset:%d  ", curr_offset);

		physical_page_addr = read_val * PAGE_SIZE + curr_vir_addr % PAGE_SIZE;
		printk("pfn:%013X ", read_val);
		printk("physical_page_addr:%013X", physical_page_addr);
		int curr_num=page_cnts[i];
		struct page *pp;
		void *from;
		int page_number, page_indent;

		size_t count = 4096;
		loff_t mem_size;

		mem_size = (loff_t)get_num_physpages() << PAGE_SHIFT;
		if (physical_page_addr >= mem_size)
			return 0;

		page_number = physical_page_addr / PAGE_SIZE;
		page_indent = physical_page_addr % PAGE_SIZE;
		#if 1
			pp = pfn_to_page(page_number);
		#else
			pp = &mem_map[page_number];
		#endif
			//建立持久映射来读取物理地址
		from = kmap(pp) + page_indent;
		if (page_indent + count > PAGE_SIZE)
			count = PAGE_SIZE - page_indent;
		//printk("count:%d",count);
		int writesize = vfs_write(con_file, from, count, 0);
		printk("writesize:%d\n",writesize);

		kunmap(pp);
		curr_vir_addr += PAGE_SIZE;
		i++;
	}

	struct file *hash_file = NULL; 
	char hash_path[30] ={};
    sprintf(hash_path,"/tmp/tmp%dhash.txt",current->tgid);
	int ret=-1;
	char path[]="/usr/local/bin/tpm2_hash";
	//char *argv[]={path,"-g","sha256","--hex","-o",hash_path,con_path,NULL};
	char *argv[]={path,"-g","sha256","-H", "e", "-o", hash_path, con_path, NULL};

	char *envp[]={NULL};

	//打开文件
	if (hash_file == NULL){
		hash_file = filp_open(hash_path, O_RDWR|O_CREAT, 0644);
	}
	//错误判断
	if (IS_ERR(hash_file)){
		printk("opening file %s error.\n", hash_path);
		return -1;
	}

	printk("call_usermodehelper module isstarting..!\n");
	ret = call_usermodehelper(path,argv, envp,UMH_WAIT_PROC);
	printk("ret=%d\n", ret);

	char processtexthash[65]; //用来储存elf文件中text段的分页hash值
    memset(processtexthash, 0, 65);
	int readsize = vfs_read(hash_file, processtexthash, 64, 0);
	if (readsize == 0){
		return;
	}
	printk("processtexthash: %s",processtexthash);
	printk("____elftexthash: %s",elftexthash);

	set_fs(old_fs);
	struct inode *parent_inode = hash_file->f_path.dentry->d_parent->d_inode;
	inode_lock(parent_inode);
	vfs_unlink(parent_inode, hash_file->f_path.dentry, NULL);
	inode_unlock(parent_inode);
	filp_close(hash_file, NULL);

	parent_inode = con_file->f_path.dentry->d_parent->d_inode;
	inode_lock(parent_inode);
	vfs_unlink(parent_inode, con_file->f_path.dentry, NULL);
	inode_unlock(parent_inode);
	filp_close(con_file, NULL);

	int flag;
	char measureresult[100];
	memset(measureresult,0,100);
	if (0 == strncmp(processtexthash, elftexthash, 64)){
		printk("page hash right\n");
		flag=0;
	}
	else{
		printk("page hash ERROR!!!\n");
		flag=1;
		//kill_pid(find_get_pid(current->pid), SIGTERM, 1);
	}
	if(flag){
		sprintf(measureresult,"%s measure error\n",current->group_leader->comm);
	}
	else{
		sprintf(measureresult,"%s measure right\n",current->group_leader->comm);
	}

	
	struct file *result = NULL; 
    char result_path[] = "/home/spike/workspace/project1/measure/log.txt";
	if (result == NULL){
		result = filp_open(result_path, O_RDWR|O_CREAT|O_APPEND, 0644);
	}
	//错误判断
	if (IS_ERR(result)){
		printk("opening file %s error.\n", result_path);
		return -1;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	vfs_write(result, measureresult, strlen(measureresult), 0);
	set_fs(old_fs);

	filp_close(result,NULL);
}

unsigned int close_cr(void){
	unsigned int cr0 = 0;
	unsigned int ret;
	asm volatile("movq %%cr0,%%rax"
				 : "=a"(cr0));
	ret = cr0;
	cr0 &= 0xfffffffffffeffff;
	asm volatile("movq %%rax,%%cr0" ::"a"(cr0));
	return ret;
}

void open_cr(unsigned int oldval){
	asm volatile("movq %%rax,%%cr0" ::"a"(oldval));
}

int query_list(char *comm){
	int result=0,i=0;
	for(i=0;i<cnt;i++){
		if(!strcmp(whitelist[i],comm)){
			result=1;
			break;
		}
	}
	return result;
}

int query_senlist(char *filename){
	int result=0,i=0;
	for(i=0;i<cnt1;i++){
		//printk ("%s\n", senlist[i]);
		if(!strcmp(senlist[i],filename)){
			result=1;
			break;
		}
	}
	return result;
}

asmlinkage long my_execve_hook64(const char __user *filename,
								 const char __user *const __user *argv,
								 const char __user *const __user *envp)
{
	if(!query_list(current->group_leader->comm))
	{
		printk("my_execve!\t%s\t%s\t%d\n", __func__, current->group_leader->comm, current->tgid);
		char data[16] = {0};
		sprintf(data, "%d", current->tgid);
		if (test_unicast(data, strlen(data), 1) == 0)
		{
			wait_for_completion(&comp);
			printk("virstart:%#lx\nvirend:%#lx\nprocessname:%s\n", virstart, virend, current->group_leader->comm);
			read_pagemap_and_measurement_process();
		}
	}
	return orig_execve(filename, argv, envp); /* 执行原来的execve路径 */
}

asmlinkage long new_write(const struct pt_regs * regs)
{
	if(!query_list(current->group_leader->comm)){
		struct file * file;
		char *tmp = (char *)__get_free_page(GFP_KERNEL);
		int fd = (int)regs->di;
		file = fget(fd);
		if(file == NULL)
			return -1;  

		pathname = d_path(&file->f_path, tmp, PAGE_SIZE);
		filp_close(file,NULL);
		
		if (!strcmp (current->group_leader->comm, "test_write")) {
			printk ("Processname : %s\nPathname : %s\n", current->group_leader->comm, pathname);
		}

		if(query_senlist(pathname)){
			printk("my_write!\n%s\n",pathname);
			char data[16] = {0};
			sprintf(data, "%d", current->tgid);
			if (test_unicast(data, strlen(data), 1) == 0)
			{
				wait_for_completion(&comp);
				printk("virstart:%#lx\nvirend:%#lx\nprocessname:%s\n", virstart, virend, current->group_leader->comm);
				read_pagemap_and_measurement_process();
			}
		}
	}
	return orig_write(regs);
}

asmlinkage long new_read(const struct pt_regs * regs)
{
	if(!query_list(current->group_leader->comm)){
		struct file * file;
		char *tmp = (char *)__get_free_page(GFP_KERNEL);
		int fd = (int)regs->di;
		file = fget(fd);
		if(file == NULL)
			return -1;  

		pathname = d_path(&file->f_path, tmp, PAGE_SIZE);
		
		if(query_senlist(pathname)){
			printk("my_read!\n%s\n",pathname);
			char data[16] = {0};
			sprintf(data, "%d", current->tgid);
			if (test_unicast(data, strlen(data), 1) == 0)
			{
				wait_for_completion(&comp);
				printk("virstart:%#lx\nvirend:%#lx\nprocessname:%s\n", virstart, virend, current->group_leader->comm);
				read_pagemap_and_measurement_process();
			}
		}
		filp_close(file,NULL);
	}
	return orig_read(regs);
}

//mkdir的函数原型,这个函数的原型要和系统的一致
asmlinkage long new_mkdir(const struct pt_regs * regs)
{
		char * user_pathname = (char *) regs->di;
        char pathname[MAX_FILE_NAME_LEN] = {0};
        int ret = raw_copy_from_user(pathname, user_pathname, sizeof(pathname));
		int len = strnlen_user(pathname, MAX_FILE_NAME_LEN);
		if(unlikely(len >= MAX_FILE_NAME_LEN)){
        	pr_info("len[%d] grater than %d.\n", len, MAX_FILE_NAME_LEN);
        	len = MAX_FILE_NAME_LEN-1;
    	}
    	long copied = strncpy_from_user(pathname, user_pathname, len);
		if (!strcmp (pathname, "new")) {
			printk ("Pathname : %s\n", pathname);
		}
        printk(KERN_ALERT "mkdir do nothing!\n");
        return 0; /*everything is ok, but he new systemcall does nothing*/
}

void start_hook(void)
{ //得到系统调用表地址

	g_sys_call_table = (uint64_t **)kallsyms_lookup_name("sys_call_table");

	if (!g_sys_call_table)
	{
		printk("Get sys_call_table error!\n");
		return;
	}	
	// orig_execve = (long (*)(const char __user *, const char __user *const __user *, const char __user *const __user *))g_sys_call_table[__NR_execve];
	// orig_read = (long (*)(const struct pt_regs * regs))g_sys_call_table[__NR_read];
    orig_write = (long (*)(const struct pt_regs * regs))g_sys_call_table[__NR_write];
	//orig_mkdir = (long (*)(const struct pt_regs * regs)) ((long unsigned int ) g_sys_call_table[__NR_mkdir] | 0xffffffff00000000);
	
	g_oldcr0 = close_cr();
	// g_sys_call_table[__NR_execve] = (uint64_t *)my_execve_hook64;
	// g_sys_call_table[__NR_read] = (uint64_t *)new_read; //设置新的系统调用地址
    g_sys_call_table[__NR_write] = (uint64_t *)new_write; 
	//g_sys_call_table[__NR_mkdir] = (uint64_t *)new_mkdir;
	open_cr(g_oldcr0);
}

void read_list(void){
	struct file *list_file = NULL; //打开elf的文件指针
	char list_path[] = "/home/spike/workspace/project1/measure/whitelist.txt";
	if (list_file == NULL){
		list_file = filp_open(list_path, O_RDONLY, 0644);
	}
	if (IS_ERR(list_file)){
		printk("opening file %s error.\n",list_path);
		return -1;
	}
	loff_t pos=0;
	char tmp_list[LISTLEN*BUFLEN];
	memset(tmp_list, 0, sizeof(tmp_list));
	memset(whitelist,0,sizeof(whitelist));
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	int readsize = vfs_read(list_file, tmp_list, LISTLEN*BUFLEN, &pos);
	if (readsize == 0){
		return -1;
	}
	filp_close(list_file,NULL);

	int i=0,k=0;
	for (i = 0; i < readsize; i++){
		if (tmp_list[i] == '\n'){
			cnt++;
			k=0;
		}
		else{
			whitelist[cnt][k] = tmp_list[i];
			k++;
		}
	}

	struct file *senlist_file = NULL; //打开elf的文件指针
	char senlist_path[] = "/home/spike/workspace/project1/measure/senlist.txt";
	if (senlist_file == NULL){
		senlist_file = filp_open(senlist_path, O_RDONLY, 0644);
	}
	if (IS_ERR(senlist_file)){
		printk("opening file %s error.\n",senlist_path);
		return -1;
	}
	pos=0;
	char tmp_senlist[SENLISTLEN*SENBUFLEN];
	memset(tmp_senlist, 0, sizeof(tmp_senlist));
	memset(senlist,0,sizeof(senlist));
	readsize = vfs_read(senlist_file, tmp_senlist, SENLISTLEN*SENBUFLEN, &pos);
	if (readsize == 0){
		return -1;
	}
	set_fs(old_fs);
	filp_close(senlist_file,NULL);

	k=0;
	cnt1=0;
	for (i = 0; i < readsize; i++){
		if (tmp_senlist[i] == '\n'){
			cnt1++;
			k=0;
		}
		else{
			senlist[cnt1][k] = tmp_senlist[i];
			k++;
		}
	}
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    if(!query_list(current->group_leader->comm)){
		struct file * file;
		char *tmp = (char *)__get_free_page(GFP_KERNEL);
		int fd = (int)regs->di;
		file = fget(fd);
		if(file == NULL)
			return -1;  

		pathname = d_path(&file->f_path, tmp, PAGE_SIZE);
		filp_close(file,NULL);
		
		if (!strcmp (current->group_leader->comm, "test_write")) {
			printk ("Processname : %s\nPathname : %s\n", current->group_leader->comm, pathname);
		}

		if(query_senlist(pathname)){
            pr_info("<%s> pre_handler: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
		        p->symbol_name, p->addr, regs->ip, regs->flags);
			printk("my_write!\n%s\n",pathname);
			char data[16] = {0};
			sprintf(data, "%d", current->tgid);
			if (test_unicast(data, strlen(data), 1) == 0)
			{
				wait_for_completion(&comp);
				printk("virstart:%#lx\nvirend:%#lx\nprocessname:%s\n", virstart, virend, current->group_leader->comm);
				read_pagemap_and_measurement_process();
			}
		}
	}
	return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	pr_info("<%s> post_handler: p->addr = 0x%p, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->flags);
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	return 0;
}

int monitor_init(void)
{ 
    //启动模块
	printk("Monitor init\n");
	read_list();
	// start_hook();
	
    //kprobe挂钩
    int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);

	// netlink init
	printk("Loading the netlink module\n");
	// This is for 3.8 kernels and above.
	struct netlink_kernel_cfg cfg = {
		.input = nl_recv_msg,
	};
	nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
	if (!nl_sk)
	{
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}
	init_completion(&comp);

	return 0;
}

void monitor_exit(void)
{ 
    unregister_kprobe(&kp);
	//退出模块 恢复系统调用表sys_open函数所在项地址为原sys_open，cr0寄存器16位置1，禁止写只读文件
	// if (g_sys_call_table)// && orig_execve)
	// {
	// 	g_oldcr0 = close_cr();
	// 	// g_sys_call_table[__NR_execve] = (uint64_t *)orig_execve;
	// 	// g_sys_call_table[__NR_read] = (uint64_t *)orig_read;
   	//  	g_sys_call_table[__NR_write] = (uint64_t *)orig_write;
	// 	//g_sys_call_table[__NR_mkdir] = (uint64_t *) orig_mkdir;
	// 	open_cr(g_oldcr0);
	// }

	// netlink exit
	netlink_kernel_release(nl_sk);
	printk("Monitor exit\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

int test_unicast(void *data, size_t size, __u32 pid)
{
	struct sk_buff *skb_out;
	skb_out = nlmsg_new(size, GFP_ATOMIC);
	if (!skb_out)
	{
		printk(KERN_ERR "Failed to allocate a new sk_buff\n");
		return -1;
	}

	struct nlmsghdr *nlh;
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, size, 0);

	memcpy(nlmsg_data(nlh), data, size);

	NETLINK_CB(skb_out).portid = pid;
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

	// 单播/多播
	if (nlmsg_unicast(nl_sk, skb_out, pid) < 0)
	{
		printk(KERN_INFO "Error while sending a msg to userspace\n");
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(test_unicast);

static void nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	char *addr1, *addr2;
	char *p;
	char str[4096];
	p = (char *)nlmsg_data(nlh);
	memcpy(str, p, strlen(p));
	char *token, *cur = str;
	char **endp = NULL;
	addr1 = strsep(&cur, "\n");
	addr2 = strsep(&cur, "\n");
	elftexthash=strsep(&cur, "\n");
	char *tmp_val = strsep(&cur, "\n");
	memset(read_vals, 0, sizeof(read_vals));
	memset(page_cnts, 0, sizeof(page_cnts));
	page_cnt = 0;
	while (tmp_val != NULL && simple_strtoul(tmp_val, endp, 16) != 0)
	{
		read_vals[page_cnt] = simple_strtoul(tmp_val, endp, 16);
		tmp_val = strsep(&cur, "\n");
		page_cnts[page_cnt] = simple_strtoul(tmp_val, endp, 16);
		page_cnt++;
		tmp_val = strsep(&cur, "\n");
	}

	virstart = simple_strtoul(addr1, endp, 16);
	virend = simple_strtoul(addr2, endp, 16);
	complete(&comp);
}

