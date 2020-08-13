<h1 align=center> MiniFTP 项目 开发日志 </h1>

[TOC]

# 2020_07_26



## 一、开发环境搭建

>### 1、安装FTP服务器vsftpd
>
>```
>yum install vsftpd -y
>```
>
>### 2、启动vsftpd
>
>```
>systemctl status vsftpd
>systemctl start  vsftpd
>systemctl stop   vsftpd
>systemctl restart vsftpd
>修改配置文件
>修改 /etc/vsftpd/vsftpd.conf
>```
>
>### 3、安装FTP客户端工具
>
>Linux平台——lftp
>
>```
>yum install lftp -y
>```
>
>Windows平台——Leapftp

## 二、系统框架搭建

> ### 1、创建公共模块common
>
> ```c++
> #ifndef _COMMON_H_
> #define _COMMON_H_
> 
> #include<unistd.h>
> #include<stdio.h>
> #include<string.h>
> #include<stdlib.h>
> #include<assert.h>
> 
> #include<sys/socket.h>
> #include<netinet/in.h>
> #include<arpa/inet.h>
> 
> #define MAX_BUFFER_SIZE 1024
> 
> #define ERR_EXIT(msg) \
> 	do\
> 	{\
> 		perror(msg);\
> 		exit(EXIT_FAILURE);\
> 	}while (0)
> 
> #endif /* __COMMON_H_ */
> ```
>
> 
>
> ### 2、创建网络模块sysutil
>
> ```c++
> #include"sysutil.h"
> 
> int tcp_server(const char* ip, unsigned short port)
> {
> 	int lst_fd;
> 	
> 	if((lst_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
> 	{
> 		ERR_EXIT("socket");
> 	}
> 
> 	struct sockaddr_in addr;
> 	addr.sin_family = AF_INET;
> 	addr.sin_port = htons(port);
> 	addr.sin_addr.s_addr = inet_addr(ip);
> 	
> 	int on = 1;
> 	if(setsockopt(lst_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
> 	{
> 		ERR_EXIT("setsockopt");
> 	}
> 
> 	if(bind(lst_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
> 	{
> 		ERR_EXIT("bind");
> 	}
> 
> 	if(listen(lst_fd, SOMAXCONN) < 0)
> 	{
> 		ERR_EXIT("listen");
> 	}
> 
> 	return lst_fd;
> }
> 
> ```
>
> 
>
> ### 3、创建会话模块session
>
> ```c++
> #include"session.h"
> #include"ftpproto.h"
> #include"privparent.h"
> 
> void session_start(session_t* sess)
> {
> 	pid_t pid = fork();
> 
> 	if(pid == - 1)
> 	{
> 		ERR_EXIT("fork");
> 	}
> 
> 	if(pid == 0)
> 	{
> 		//ftp服务进程
> 		handle_child(sess);
> 	}
> 	else
> 	{
> 		//nobody进程
> 		handle_parent(sess);
> 	}
> }
> ```
>
> 
>
> ### 4、创建FTP服务进程模块ftpproto
>
> ```c++
> #include"ftpproto.h"
> 
> void ftp_reply(session_t* sess, int num, char* msg)
> {
> 	char buf[MAX_BUFF_SIZE] = { 0 };
> 	sprintf(buf, "%d %s \n\r", num, msg);
> 
> 	send(sess->ctl_fd, buf, MAX_BUFF_SIZE, 0);
> }
> 
> void handle_child(session_t* sess)
> {
> 	while(1)
> 	{
> 		//等待客户端命令，并进行处理
> 	}
> }
> ```
>
> 
>
> 
>
> ### 5、创建nobody进程模块privparent
>
> ```c++
> #include"privparent.h"
> 
> void handle_parent(session_t* sess)
> {
> 	while(1)
> 	{
> 		//等待ftp进程消息
> 	}
> }
> ```
>
> 
>
> 
>
> ### 6、创建主进程模块MiniFTP
>
> ```c++
> #include"common.h"
> #include"session.h"
> #include"sysutil.h"
> 
> int main(int agrc, char* argv[])
> {
> 	session_t sess = { -1 };
> 
> 	int lst_sock = tcp_server("192.168.0.128", 9188); 
> 
> 	int new_sock;
> 	struct sockaddr_in addr;
> 	socklen_t addrlen;
> 	
> 	while(1)
> 	{
> 		if((new_sock = accept(lst_sock, (struct sockaddr*)&addr, &addrlen)) < 0)
> 		{
> 			ERR_EXIT("accept");
> 		}
> 
> 		pid_t pid = fork();
> 
> 		if(pid == -1)
> 		{
> 			ERR_EXIT("fork");
> 		}
> 		
> 		if(pid == 0)
> 		{
> 			//子进程
> 			close(lst_sock);
> 			//子进程创建会话
> 			sess.ctl_fd = new_sock;
> 			session_start(&sess);
> 			exit(EXIT_SUCCESS);
> 		}
> 		else
> 		{
> 			//父进程
> 			close(new_sock);
> 		}
> 	}
> 
> 	close(lst_sock);
> 	return 0;
> }
> 
> 
> ```
>
> 
>
> ### 7、创建MakeFile文件
>
> ```makefile
> CC = gcc
> CFLAGS = -g
> OBJS = sysutil.o session.o ftpproto.o privparent.o MiniFTP.o
> LIBS = 
> BIN  = MiniFTP
> 
> $(BIN):$(OBJS)
> 	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
> %.o:%.c
> 	$(CC) $(CFLAGS) -c $< -o $@
> 
> .PHONY:clean
> clean:
> 	rm -fr *.o $(BIN)
> ```
>
> 



# 2020_07_27

## 一、命令解析与映射



> ### 1、封装响应函数
>
> ```c++
> void ftp_reply(session_t* sess, int state, char* msg)
> {
> 	char buf[MAX_BUFFER_SIZE] = { 0 };
> 	sprintf(buf, "%d %s\r\n", state, msg);
> 
> 	send(sess->ctl_fd, buf, strlen(buf), 0);
> }
> ```
>
> 
>
> 
>
> ### 2、封装响应状态码ftpcodes
>
> ```c
> #define FTP_DATACONN 150
> #define FTP_NOOPOK 200
> #define FTP_TYPEOK 200
> #define FTP_PORTOK 200
> #define FTP_EPRTOK 200
> #define FTP_UMASKOK 200
> #define FTP_CHMODOK 200
> #define FTP_EPSVALLOK 200
> #define FTP_STRUOK 200
> #define FTP_MODEOK 200
> #define FTP_PBSZOK 200
> #define FTP_PROTOK 200
> #define FTP_OPTSOK 200
> #define FTP_ALLOOK 202
> #define FTP_FEAT 211
> #define FTP_STATOK 211
> #define FTP_SIZEOK 213
> #define FTP_MDTMOK 213
> #define FTP_STATFILE_OK 213
> #define FTP_SITEHELP 214
> #define FTP_HELP 214
> #define FTP_SYSTOK 215
> #define FTP_GREET 220
> #define FTP_GOODBYE 221
> #define FTP_ABOR_NOCONN 225
> #define FTP_TRANSFEROK 226
> #define FTP_ABOROK 226
> #define FTP_PASVOK 227
> #define FTP_EPSVOK 229
> #define FTP_LOGINOK 230
> #define FTP_AUTHOK 234
> #define FTP_CWDOK 250
> #define FTP_RMDIROK 250
> #define FTP_DELEOK 250
> #define FTP_RENAMEOK 250
> #define FTP_PWDOK 257
> #define FTP_MKDIROK 257
> #define FTP_GIVEPWORD 331
> #define FTP_RESTOK 350
> #define FTP_RNFROK 350
> #define FTP_IDLE_TIMEOUT 421
> #define FTP_DATA_TIMEOUT 421
> #define FTP_TOO_MANY_USERS 421
> #define FTP_IP_LIMIT 421
> #define FTP_IP_DENY 421
> #define FTP_TLS_FAIL 421
> #define FTP_BADSENDCONN 425
> #define FTP_BADSENDNET 426
> #define FTP_BADSENDFILE 451
> #define FTP_BADCMD 500
> #define FTP_BADOPTS 501
> #define FTP_COMMANDNOTIMPL 502
> #define FTP_NEEDUSER 503
> #define FTP_NEEDRNFR 503
> #define FTP_BADPBSZ 503
> #define FTP_BADPROT 503
> #define FTP_BADSTRU 504
> #define FTP_BADMODE 504
> #define FTP_BADAUTH 504
> #define FTP_NOSUCHPROT 504
> #define FTP_NEEDENCRYPT 522
> #define FTP_EPSVBAD 522
> #define FTP_DATATLSBAD 522
> #define FTP_LOGINERR 530
> #define FTP_NOHANDLEPROT 536
> #define FTP_FILEFAIL 550
> #define FTP_NOPERM 550
> #define FTP_UPLOADFAIL 553
> ```
>
> ## 3、新增命令解析模块str
>
> ```c++
> #include"str.h"
> 
> void str_trim_crlf(char* str)
> {
> 	assert(str);
> 
> 	char* p = str + (strlen(str) - 1);
> 	while(*p == '\n' || *p == '\r')
> 	{
> 		*(p--) = '\0';
> 	}
> }
> 
> void str_split(const char* str, char* cmd, char* arg, char split)
> {
> 	assert(str);
> 
> 	char* pos = strchr(str, split);
> 
> 	//only command
> 	if(pos == NULL)
> 	{
> 		strcpy(cmd, str);
> 	}
> 	else
> 	{
> 		strncpy(cmd, str, pos - str);
> 		strcpy(arg, pos + 1);
> 	}
> }
> ```
>
> ## 4、新增命令映射部分
>
> /////////////////////////////////////////
>
> ​		session_t中增加新成员
>
> ```c++
> typedef struct session
> {
> 	uid_t uid;						//新增进程ID
> 	int ctl_fd;						
> 	char cmdline[MAX_COMMAND_LINE];	//命令行
> 	char cmd[MAX_COMMAND];			//命令
> 	char arg[MAX_ARG];				//参数
> }session_t;
> ```
>
> /////////////////////////////////////////
>
> ftpproto模块中增加命令映射表
>
> ```c++
> static void do_user(session_t *sess); 
> static void do_pass(session_t *sess); 
> static void do_cwd(session_t *sess); 
> static void do_cdup(session_t *sess); 
> static void do_quit(session_t *sess); 
> static void do_port(session_t *sess); 
> static void do_pasv(session_t *sess); 
> static void do_type(session_t *sess); 
> //static void do_stru(session_t *sess); 
> //static void do_mode(session_t *sess); 
> static void do_retr(session_t *sess); 
> static void do_stor(session_t *sess); 
> static void do_appe(session_t *sess); 
> static void do_list(session_t *sess); 
> static void do_nlst(session_t *sess); 
> static void do_rest(session_t *sess); 
> static void do_abor(session_t *sess); 
> static void do_pwd(session_t *sess); 
> static void do_mkd(session_t *sess); 
> static void do_rmd(session_t *sess); 
> static void do_dele(session_t *sess); 
> static void do_rnfr(session_t *sess); 
> static void do_rnto(session_t *sess); 
> static void do_site(session_t *sess); 
> static void do_syst(session_t *sess); 
> static void do_feat(session_t *sess); 
> static void do_size(session_t *sess); 
> static void do_stat(session_t *sess); 
> static void do_noop(session_t *sess); 
> static void do_help(session_t *sess);
> 
> //建立命令与函数的映射关系
> typedef struct ftpcmd
> {
> 	const char* cmd;					//命令名
> 	void(*handler)(session_t *sess);	//函数指针
> }ftpcmd_t;
> 
> //命令映射表
> static ftpcmd_t ctl_cmds[] = 
> {
> 	/* 访问控制命令 */
> 	{"USER", do_user },
> 	{"PASS", do_pass },
> 	{"CWD" , do_cwd },
> 	{"XCWD", do_cwd },
> 	{"CDUP", do_cdup },
> 	{"XCUP", do_cdup },
> 	{"QUIT", do_quit },
> 	{"ACCT", NULL },
> 	{"SMNT", NULL },
> 	{"REIN", NULL },
> 
> 	/* 传输参数命令 */
> 	{"PORT", do_port },
> 	{"PASV", do_pasv },
> 	{"TYPE", do_type },
> 	{"STRU", /*do_stru*/NULL },
> 	{"MODE", /*do_mode*/NULL },
> 
> 	/* 服务命令 */
> 	{"RETR", do_retr },
> 	{"STOR", do_stor },
> 	{"APPE", do_appe },
> 	{"LIST", do_list },
> 	{"NLST", do_nlst },
> 	{"REST", do_rest },
> 	{"ABOR", do_abor },
> 	{"\377\364\377\362ABOR", do_abor},
> 	{"PWD", do_pwd },
> 	{"XPWD", do_pwd },
> 	{"MKD", do_mkd },
> 	{"XMKD", do_mkd },
> 	{"RMD", do_rmd },
> 	{"XRMD", do_rmd },
> 	{"DELE", do_dele },
> 	{"RNFR", do_rnfr },
> 	{"RNTO", do_rnto },
> 	{"SITE", do_site },
> 	{"SYST", do_syst },
> 	{"FEAT", do_feat },
> 	{"SIZE", do_size },
> 	{"STAT", do_stat },
> 	{"NOOP", do_noop },
> 	{"HELP", do_help },
> 	{"STOU", NULL },
> 	{"ALLO", NULL }
> 
> };
> ```
>
> ftp服务进程处理部分
>
> ```c++
> void handle_child(session_t* sess)
> {
> 	ftp_reply(sess, FTP_GREET, "(MiniFtp 1.0)");
> 	int ret;
> 
> 	while(1)
> 	{
> 		memset(sess->cmdline, 0, MAX_COMMAND_LINE);
> 		memset(sess->cmd, 0, MAX_COMMAND);
> 		memset(sess->arg, 0, MAX_ARG);
> 
> 		//get command
> 		ret = recv(sess->ctl_fd, sess->cmdline, MAX_COMMAND_LINE, 0);
> 		if(ret < 0)
> 		{
> 			ERR_EXIT("recv");
> 		}
> 		else if(ret == 0)
> 		{
> 			exit(EXIT_SUCCESS);
> 		}
> 
> 		str_trim_crlf(sess->cmdline);
> 		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
> 		
> 		int i;
> 		int list_size = sizeof(ctl_cmds) / sizeof(ftpcmd_t);
> 
> 		for(i = 0; i < list_size; i++)
> 		{
> 			if(strcmp(sess->cmd, ctl_cmds[i].cmd) == 0)
> 			{
> 				if(ctl_cmds[i].handler != NULL)
> 				{
> 					ctl_cmds[i].handler(sess);
> 				}
> 				else
> 				{
> 					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Command not implemented.");
> 				}
> 				break;
> 			}
> 		}
> 
> 		if(i == list_size)
> 		{
> 			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
> 		}
> 	}
> }
> ```

## 二、用户更换、鉴权

> ### 1、用户更换
>
> session.c中nobody进程部分增加用户更换
>
> ```c++
> //nobody process
> 
> //Change the process from root to nobody
> struct passwd* pw = getpwnam("nobody");
> if(pw == NULL)
> {
> 	ERR_EXIT("getpwnam");
> }
> if(setegid(pw->pw_gid) < 0)
> {
> 	ERR_EXIT("setegid");
> }
> if(seteuid(pw->pw_uid) < 0)
> {
> 	ERR_EXIT("seteuid");
> }
> 		
> handle_parent(sess);
> ```
>
> 2、响应USER命令
>
> ```c++
> static void do_user(session_t* sess)
> {
> 	struct passwd* pwd = getpwnam(sess->arg);
> 	
> 	if(pwd != NULL)
> 	{
> 		sess->uid = pwd->pw_uid;
> 	}
> 
> 	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
> }
> ```
>
> 3、响应PASS命令，通过uid获取用户名，再通过用户名获取影子文件，通过cry将明文密码加密，与通过对比影子密码实现鉴权
>
> ```c++
> static void do_pass(session_t* sess)
> {
> 	//Authentication, confirm account and password
> 	struct passwd *pwd = getpwuid(sess->uid);
> 
> 	if(pwd == NULL)
> 	{
> 		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
> 		return;
> 	}
> 
> 	struct spwd* spd = getspnam(pwd->pw_name);
> 	if(spd == NULL)
> 	{
> 		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
> 		return;
> 	}
> 
> 	char* encry_pwd = crypt(sess->arg, spd->sp_pwdp);
> 	if(strcmp(encry_pwd, spd->sp_pwdp) != 0)
> 	{
> 		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
> 		return;
> 	}
> 
> 	setegid(pwd->pw_gid);
> 	seteuid(pwd->pw_uid);
> 	chdir(pwd->pw_dir);
> 
> 	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
> }
> ```
>
> 

-----------------------------------

# 2020_08_02

## 一、命令实现（SYST、FEAT、PWD、TYPE）

>## 1、 实现SYST命令
>
>显示远程主机的操作系统类型
>
>```c
>static void do_syst(session_t* sess)
>{
>	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
>}
>```
>
>### 2、实现FEAT命令
>
>请求FTP服务器列出它的所有的扩展命令与扩展功能
>
>```c
>static void do_feat(session_t *sess)
>{
>	send(sess->ctl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
>	send(sess->ctl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
>	send(sess->ctl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
>	send(sess->ctl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
>	send(sess->ctl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
>	send(sess->ctl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0);
>	send(sess->ctl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
>	send(sess->ctl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
>	send(sess->ctl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
>	send(sess->ctl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
>}
>```
>
>### 3、实现PWD命令
>
>显示远程主机的当前工作目录
>
>```c
>static void do_pwd(session_t *sess)
>{
>	char buf[MAX_BUFFER_SIZE] = { 0 };
>	getcwd(buf, MAX_BUFFER_SIZE); // /home/user
>	
>	char msg[MAX_BUFFER_SIZE] = { 0 };
>	sprintf(msg, "\"%s\" is the current directory", buf); // "/home/user"
>
>	ftp_reply(sess, FTP_PWDOK, msg);
>}
>```
>
>### 4、实现TYPE命令
>
>设置文件传输类型，A为ASCII传输，I为二进制传输，默认为ASCII
>
>```c
>static void do_type(session_t *sess)
>{
>	if(strcmp(sess->arg, "A") == 0)
>	{
>		sess->is_ascii = 1;
>		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
>	}
>	else if(strcmp(sess->arg, "I") == 0)
>	{
>		sess->is_ascii = 0;
>		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
>	}
>	else
>	{
>		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
>	}
>}
>```
>
>

---------------

# 2020_08_03

## 一、实现主动模式和被动模式

>### session增加新成员
>
>```c
>typedef struct session
>{
>	/* control connection*/
>	uid_t uid;
>	int ctl_fd;
>	char cmdline[MAX_COMMAND_LINE];
>	char cmd[MAX_COMMAND];
>	char arg[MAX_ARG];
>
>	/* data connection */
>	struct sockaddr_in* port_addr;
>	int data_fd;
>	int pasv_lst_fd;
>
>	/* protocol status */
>	int is_ascii;
>	
>}session_t;
>```
>
>
>
>
>
>### 实现PORT命令（主动模式）
>
>```c
>static void do_port(session_t *sess)
>{
>	//resolving ip address : PORT 192,168,1,128,5,35
>	unsigned int addr[6] = { 0 };
>	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
>
>	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
>	
>	sess->port_addr->sin_family = AF_INET;
>	//set ip address
>	unsigned char* p = (unsigned char*)&sess->port_addr->sin_addr;
>	p[0] = addr[0];
>	p[1] = addr[1];
>	p[2] = addr[2];
>	p[3] = addr[3];
>
>	//set port
>	p = (unsigned char*)&sess->port_addr->sin_port;
>	p[0] = addr[4];
>	p[1] = addr[5];
>
>	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
>}
>
>int port_action(const session_t* sess)
>{
>	if(sess->port_addr)
>	{
>		return 1;
>	}
>
>	return 0;
>}
>```
>
>### 实现PASV命令（被动模式）
>
>```c
>static void do_pasv(session_t *sess)
>{
>	char ip[16] = "192.168.0.128"; //server ip address
>	sess->pasv_lst_fd = tcp_server(ip, 0); //automatic allocation port
>
>	struct sockaddr_in address;
>	socklen_t socklen = sizeof(struct sockaddr);
>
>	if(getsockname(sess->pasv_lst_fd, (struct sockaddr*)&address, &socklen) < 0)
>	{
>		ERR_EXIT("getsockname");
>	}
>
>	unsigned short port = ntohs(address.sin_port);
>	int addr[4] = { 0 };
>	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);
>
>	char buf[MAX_BUFFER_SIZE] = { 0 };
>	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", addr[0], addr[1], addr[2], addr[3], port >> 8, port & 0x00ff);
>
>	ftp_reply(sess, FTP_PASVOK, buf);
>}
>
>int pasv_action(const session_t* sess)
>{
>	if(sess->pasv_lst_fd != -1)
>	{
>		return 1;
>	}
>
>	return 0;
>}
>```
>
>### 根据工作模式，获取数据连接描述符
>
>````c
>int get_transfer_fd(session_t *sess)
>{
>	if(!port_action(sess) && !pasv_action(sess))
>	{
>		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
>		return 0;
>	}
>	
>	int ret = 1;
>	
>	if(port_action(sess))
>	{
>		int sock = tcp_client();
>
>		if(connect(sock, (struct sockaddr*)sess->port_addr, sizeof(struct sockaddr)) < 0)
>		{
>			ret = 0;
>		}
>		else
>		{
>			sess->data_fd = sock;
>		}
>	}
>
>	if(pasv_action(sess))
>	{
>		int sock = accept(sess->pasv_lst_fd, NULL, NULL);
>		if(sock < 0)
>		{
>			ret = 0;
>		}
>		else
>		{
>			close(sess->pasv_lst_fd);
>			sess->pasv_lst_fd = -1;
>			sess->data_fd = sock;
>		}
>	}
>
>	if(sess->port_addr)
>	{
>		free(sess->port_addr);
>		sess->port_addr = NULL;
>	}
>
>	return ret;
>}
>````

## 二、实现LIST功能（显示文件列表）

>```c
>static void do_list(session_t *sess)
>{
>	//1.establish data connection
>	if(get_transfer_fd(sess) == 0)
>	{
>		return;
>	}
>
>	//2.reply code-150
>	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
>
>	//3.show file list
>	list_common(sess);
>
>	//4.close connection
>	close(sess->data_fd);
>	sess->data_fd = -1;
>
>	//5.reply code-226
>	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
>}
>
>//列表实现功能
>static void list_common(session_t *sess)
>{
>	//open working directory
>	DIR* dir = opendir(".");
>	if(dir == NULL)
>	{
>		return;
>	}
>
>	//drwxr-xr-x    2 1000     1000            6 Mar 03 09:42 Desktop
>	char buf[MAX_BUFFER_SIZE] = { 0 };
>	
>	struct stat sbuf;
>	struct dirent* dt;
>	
>	while((dt = readdir(dir)) != NULL)
>	{
>		if(stat(dt->d_name, &sbuf) < 0)
>		{
>			continue;
>		}
>		//ignore hidden files
>		if(dt->d_name[0] == '.')
>		{
>			continue;
>		}
>
>		int offset = 0;
>		memset(buf, MAX_BUFFER_SIZE, 0);
>
>		//add permission information : drwxr-xr-x
>		const char* perms = statbuf_get_perms(&sbuf);
>		offset += sprintf(buf, "%s", perms);
>		
>		//add file information : 2 1000     1000            6
>		offset += sprintf(buf + offset, "%3d %-8d %-8d %8u", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, sbuf.st_size);
>		
>		//add data information : 6 Mar 03 09:42
>		const char* date = statbuf_get_date(&sbuf);
>		offset += sprintf(buf + offset, " %s ", date);
>
>		//add dir information : Desktop
>		sprintf(buf + offset, "%s\r\n", dt->d_name);
>
>		send(sess->data_fd, buf, strlen(buf), 0);
>	}
>}
>```
>
>### sysutil模块新增文件权限信息和日期信息获取
>
>```c
>const char* statbuf_get_perms(const struct stat *sbuf)
>{
>	//- --- --- ---
>	static char perms[] = "----------";
>	mode_t mode = sbuf->st_mode;
>
>	switch(mode & S_IFMT)
>	{
>		//file properties
>		case S_IFREG:
>			perms[0] = '-';
>			break;
>		case S_IFIFO:
>			perms[0] = 'p';
>			break;
>		case S_IFDIR:
>			perms[0] = 'd';
>			break;
>		case S_IFCHR:
>			perms[0] = 'c';
>			break;
>		case S_IFBLK:
>			perms[0] = 'b';
>			break;
>		case S_IFLNK:
>			perms[0] = 'l';
>			break;
>		case S_IFSOCK:
>			perms[0] = 's';
>			break;
>	}
>    
>	//permission
>	if(mode & S_IRUSR)
>		perms[1] = 'r';
>	if(mode & S_IWUSR)
>		perms[2] = 'w';
>	if(mode & S_IXUSR)
>		perms[3] = 'x';
>		
>	if(mode & S_IRGRP)
>		perms[4] = 'r';
>	if(mode & S_IWGRP)
>		perms[5] = 'w';	
>	if(mode & S_IXGRP)
>		perms[6] = 'x';
>
>	if(mode & S_IROTH)
>		perms[7] = 'r';
>	if(mode & S_IWOTH)
>		perms[8] = 'w';
>	if(mode & S_IXOTH)
>		perms[9] = 'x';
>
>	return perms;
>}
>
>const char* statbuf_get_date(const struct stat *sbuf)
>{
>	static char dates[64] = { 0 };
>
>	time_t file_time = sbuf->st_mtime;
>	struct tm* ptm = localtime(&file_time);
>
>	strftime(dates, 64, "%b %e %H:%M", ptm);
>
>	return dates;
>}
>```

---------------------------

# 2020_08_06

## 一、实现内部通信模块privsock

> ### 创建内部通信模块privsock
>
> ```c
> #include"privsock.h"
> 
> 
> void priv_sock_init(session_t *sess)
> {
> 	int sockfds[2];
> 	if(socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
> 	{
> 		ERR_EXIT("socketpait");
> 	}
> 
> 	sess->parent_fd = sockfds[0];
> 	sess->child_fd = sockfds[1];
> }
> 
> void priv_sock_close(session_t *sess)
> {
> 	if(sess->parent_fd != -1)
> 	{
> 		close(sess->parent_fd);
> 		sess->parent_fd = -1;
> 	}
> 
> 	if(sess->child_fd != -1)
> 	{
> 		close(sess->child_fd);
> 		sess->child_fd = -1;
> 	}
> }
> 
> void priv_sock_set_parent_context(session_t *sess)
> {
> 	if(sess->child_fd != -1)
> 	{
> 		close(sess->child_fd);
> 		sess->child_fd = -1;
> 	}
> }
> 
> void priv_sock_set_child_context(session_t *sess)
> {
> 	if(sess->parent_fd != -1)
> 	{
> 		close(sess->parent_fd);
> 		sess->parent_fd = -1;
> 	}
> }
> 
> void priv_sock_send_cmd(int fd, char cmd)
> {
> 	int ret = send(fd, &cmd, sizeof(cmd), 0);
> 
> 	if(ret != sizeof(cmd))
> 	{
> 		ERR_EXIT("priv_sock_send_cmd error.");
> 	}
> }
> 
> char priv_sock_get_cmd(int fd)
> {
> 	char cmd;
> 	int ret = recv(fd, &cmd, sizeof(cmd), 0);
> 
> 	if(ret == 0)
> 	{
> 		printf("ftp process eixt.\n");
> 		exit(EXIT_SUCCESS);
> 	}
> 	else if(ret != sizeof(cmd))
> 	{
> 		ERR_EXIT("priv_sock_get_cmd error.");
> 	}
> 
> 	return cmd;
> }
> 
> void priv_sock_send_result(int fd, char res)
> {
> 	int ret = send(fd, &res, sizeof(res), 0);
> 
> 	if(ret != sizeof(res))
> 	{
> 		ERR_EXIT("priv_sock_send_result error.");
> 	}
> }
> 
> char priv_sock_get_result(int fd)
> {
> 	char res;
> 	int ret = recv(fd, &res, sizeof(res), 0);
> 
> 	if(ret == 0)
> 	{
> 		printf("ftp process eixt.\n");
> 		exit(EXIT_SUCCESS);
> 	}
> 	else if(ret != sizeof(res))
> 	{
> 		ERR_EXIT("priv_sock_get_result error.");
> 	}
> 
> 	return res;
> }
> 
> 
> void priv_sock_send_int(int fd, int the_int)
> {
> 	int ret = send(fd, &the_int, sizeof(the_int), 0);
> 
> 	if(ret != sizeof(the_int))
> 	{
> 		ERR_EXIT("priv_sock_send_int error.");
> 	}
> }
> 
> int priv_sock_get_int(int fd)
> {
> 	int the_int;
> 	int ret = recv(fd, &the_int, sizeof(the_int), 0);
> 
> 	if(ret == 0)
> 	{
> 		printf("ftp process eixt.\n");
> 		exit(EXIT_SUCCESS);
> 	}
> 	else if(ret != sizeof(the_int))
> 	{
> 		ERR_EXIT("priv_sock_get_int error.");
> 	}
> 
> 	return the_int;
> }
> 
> void priv_sock_send_buf(int fd, const char *buf, unsigned int len)
> {
> 	priv_sock_send_int(fd, len);
> 
> 	int ret = send(fd, buf, len, 0);
> 	if(ret != len)
> 	{
> 		ERR_EXIT("priv_sock_send_buf error.");
> 	}
> }
> 
> void priv_sock_recv_buf(int fd, char *buf, unsigned int len)
> {
> 	int recv_len = priv_sock_get_int(fd);
> 	if(recv_len != len)
> 	{
> 		ERR_EXIT("priv_sock_recv_buf error.");
> 	}
> 
> 	int ret = recv(fd, buf, recv_len, 0);
> 	if(ret != recv_len)
> 	{
> 		ERR_EXIT("priv_sock_recv_buf error.");
> 	}
> }
> 
> void priv_sock_send_fd(int sock_fd, int fd)
> {
> 	send_fd(sock_fd, fd);
> }
> 
> int priv_sock_recv_fd(int sock_fd)
> {
> 	return recv_fd(sock_fd);
> }
> ```
>



-------------------

# 2020_08_10

## 一、完成nobody进程20端口的绑定

> ```c
> static void privilege_promotion()
> {
> 	
> 	//将进程的实际用户从root改为nobody
> 	struct passwd* pw = getpwnam("nobody");
> 	if(pw == NULL)
> 	{
> 		ERR_EXIT("getpwnam error.");
> 	}
> 	if(setegid(pw->pw_gid) < 0)
> 	{
> 		ERR_EXIT("setegid error.");
> 	}
> 	if(seteuid(pw->pw_uid) < 0)
> 	{
> 		ERR_EXIT("seteuid error.");
> 	}
> 
> 	//提升用户权限,让其能够绑定20端口	
> 	struct __user_cap_header_struct hdrp;
> 	struct __user_cap_data_struct datap;
> 
> 	hdrp.version = _LINUX_CAPABILITY_VERSION_1;
> 	hdrp.pid = 0;
> 
> 	__u32 mask = 0;
> 	mask |=  (1 << CAP_NET_BIND_SERVICE); //获取绑定特权端口(低于1024)的权限
> 	
> 	datap.effective = mask;
> 	datap.permitted = mask;
> 	datap.inheritable = 0; //不需要继承
> 
> 	capset(&hdrp, &datap);
> }
> ```

-------------------------------------------------------------

## 二、完成主动模式与被动模式下nobody进程与FTP服务进程的通信

> ### 获取主动模式下的数据连接套接字
>
> ```c
> static void privop_pasv_recv_data_sock(session_t *sess)
> {
> 	unsigned short port = (unsigned short)priv_sock_recv_int(sess->parent_fd);
> 
> 	char ip[16] = { 0 };
> 	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
> 
> 	struct sockaddr_in addr;
> 	addr.sin_family = AF_INET;
> 	addr.sin_port = htons(port);
> 	addr.sin_addr.s_addr = inet_addr(ip);
> 
> 	//绑定20端口
> 	int fd = tcp_client(20);
> 
> 	if(fd == -1)
> 	{
> 		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
> 		return;
> 	}
> 	if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
> 	{
> 		close(fd);
> 		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
> 		return;
> 	}
> 
> 	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
> 	priv_sock_send_fd(sess->parent_fd, fd);
> 	close(fd);
> }
> ```
>
> ### 判断被动模式是否被激活
>
> ````c
> static void privop_pasv_active(session_t *sess)
> {
> 	int ret = 1;
> 
> 	if(sess->pasv_lst_fd != -1)
> 	{
> 		ret = 1;
> 	}
> 	else
> 	{
> 		ret = 0;
> 	}
> 
> 	priv_sock_send_int(sess->parent_fd, ret);
> }
> ````
>
> ### 获取被动模式下的监听端口号
>
> ```c
> static void privop_pasv_listen(session_t *sess)
> {
> 	char ip[16] = "192.168.0.128"; //服务器IP地址
> 	sess->pasv_lst_fd = tcp_server(ip, 0); //端口号给0,会自动分配端口号
> 	
> 	struct sockaddr_in addr;
> 	socklen_t socklen = sizeof(struct sockaddr);
> 
> 	if(getsockname(sess->pasv_lst_fd, (struct sockaddr*)&addr, &socklen) < 0)
> 	{
> 		ERR_EXIT("getsockname");
> 	}
> 	
> 	unsigned short port = ntohs(addr.sin_port);
> 	priv_sock_send_int(sess->parent_fd, (int)port);
> }
> ```
>
> ### 获取被动模式下的数据连接套接字
>
> ```c
> static void privop_pasv_accept(session_t *sess)
> {
> 	int fd = accept(sess->pasv_lst_fd, 0, 0);
> 	
> 	close(sess->pasv_lst_fd);
> 	sess->pasv_lst_fd = -1;
> 
> 	if(fd == -1)
> 	{
> 		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
> 		return;
> 	}
> 
> 	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
> 	priv_sock_send_fd(sess->parent_fd, fd);
> 	close(fd);
> }
> ```
>
> ### 主动模式与被动模式的重构
>
> ```c
> static void do_port(session_t *sess)
> {
> 	//解析IP地址 例如: PORT 192,168,1,128,5,35
> 	unsigned int addr[6] = { 0 };
> 	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
> 
> 	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
> 	
> 	sess->port_addr->sin_family = AF_INET;
> 	//设置IP地址
> 	unsigned char* p = (unsigned char*)&sess->port_addr->sin_addr;
> 	p[0] = addr[0];
> 	p[1] = addr[1];
> 	p[2] = addr[2];
> 	p[3] = addr[3];
> 
> 	//设置端口号
> 	p = (unsigned char*)&sess->port_addr->sin_port;
> 	p[0] = addr[4];
> 	p[1] = addr[5];
> 
> 	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
> }
> 
> 
> static void do_pasv(session_t *sess)
> {
> 	char ip[16] = "192.168.0.128"; //服务器IP地址
> 
> 	//获取监听套接字的端口号
> 	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
> 	unsigned short port = (unsigned short)priv_sock_recv_int(sess->child_fd);
> 	
> 	int addr[4] = { 0 };
> 	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);
> 
> 	char buf[MAX_BUFFER_SIZE] = { 0 };
> 	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", addr[0], addr[1], addr[2], addr[3], port >> 8, port & 0x00ff);
> 
> 	ftp_reply(sess, FTP_PASVOK, buf);
> }
> 
> int get_port_fd(session_t *sess)
> {
> 	int ret = 1;
> 	//ftp服务进程向nobody进程发起通信
> 	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
> 
> 	unsigned short port = ntohs(sess->port_addr->sin_port);
> 	char* ip = inet_ntoa(sess->port_addr->sin_addr);
> 
> 	//将客户端的地址信息传递给nobody进程，让其进行主动连接
> 	priv_sock_send_int(sess->child_fd, (int)port);
> 	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));
> 
> 	char res = priv_sock_recv_result(sess->child_fd);
> 	if(res == PRIV_SOCK_RESULT_BAD)
> 	{
> 		ret = 0;
> 	}
> 	else if(res == PRIV_SOCK_RESULT_OK)
> 	{
> 		//建立连接成功，获取数据连接
> 		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
> 	}
> 
> 	return ret;
> }
> 
> int get_pasv_fd(session_t *sess)
> {
> 	int ret = 1;
> 
> 	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
> 
> 	char res = priv_sock_recv_result(sess->child_fd);
> 	if(res == PRIV_SOCK_RESULT_BAD)
> 	{
> 		ret = 0;
> 	}
> 	else if(res == PRIV_SOCK_RESULT_OK)
> 	{
> 		//建立连接成功，获取数据连接
> 		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
> 	}
> 
> 	return ret;
> }
> 
> int port_active(const session_t* sess)
> {
> 	if(sess->port_addr)
> 	{
> 		if(pasv_active(sess))
> 		{
> 			perror("both port and pasv are active.");
> 			exit(EXIT_FAILURE);
> 		}
> 		return 1;
> 	}
> 
> 	return 0;
> }
> 
> int pasv_active(const session_t* sess)
> {
> 	//验证是否处于被动模式
> 	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
> 
> 	if(priv_sock_recv_int(sess->child_fd))
> 	{
> 		if(port_active(sess))
> 		{
> 			perror("both port and pasv are active.");
> 			exit(EXIT_FAILURE);
> 		}
> 
> 		return 1;
> 	}
> 
> 	return 0;
> }
> 
> int get_transfer_fd(session_t *sess)
> {
> 	if(!port_active(sess) && !pasv_active(sess))
> 	{
> 		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
> 		return 0;
> 	}
> 	
> 	int ret = 1;
> 	
> 	if(port_active(sess))
> 	{
> 		if(get_port_fd(sess) == 0)
> 		{
> 			ret = 0;
> 		}
> 	}
> 
> 	if(pasv_active(sess))
> 	{
> 		if(get_pasv_fd(sess) == 0)
> 		{
> 			ret = 0;
> 		}
> 	}
> 
> 	if(sess->port_addr)
> 	{
> 		free(sess->port_addr);
> 		sess->port_addr = NULL;
> 	}
> 
> 	return ret;
> }
> ```



--------------------

# 2020_08_11

## 一、命令实现（CWD、CDUP、MKD、RMD、DELE、RNFR、RNTO、SIZE）

>### 实现目录切换功能CWD、CDUP
>
>```c
>//切换目录
>static void do_cwd(session_t *sess)
>{
>	if(chdir(sess->arg) < 0)
>	{
>		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
>		return;
>	}
>
>	ftp_reply(sess, FTP_CWDOK , "Directory successfully changed.");
>}
>
>//返回上一级目录
>void do_cdup(session_t *sess) 
>{ 
>	if(chdir("..") < 0) 
>	{ 
>		ftp_reply(sess, FTP_NOPERM, "Failed to change directory."); 
>		return; 
>	}
>
>	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed."); 
>}
>```
>
>### 实现创建目录功能MKD
>
>```c
>static void do_mkd(session_t *sess)
>{
>	if(mkdir(sess->arg, 0777) < 0)
>	{
>		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed."); 
>		return;
>	}
>
>	//257 "/home/lee/test1/1" created
>	char buf[MAX_BUFFER_SIZE] = { 0 };
>	sprintf(buf, "\"%s\" created", sess->arg);
>	
>	ftp_reply(sess, FTP_MKDIROK, buf);
>}
>```
>
>### 实现文件删除功能RMD、DELE
>
>```c
>//删除目录文件
>static void do_rmd(session_t *sess)
>{
>	if(rmdir(sess->arg) < 0)
>	{
>		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
>		return;
>	}
>
>	ftp_reply(sess, FTP_RMDIROK , "Remove directory operation failed.");
>}
>
>//删除普通文件
>static void do_dele(session_t *sess)
>{
>	if(unlink(sess->arg) < 0)
>	{
>		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
>		return;
>	}
>
>	ftp_reply(sess, FTP_DELEOK , "Delete operation successful.");
>}
>```
>
>### 实现重命名功能RNFR、RNTO
>
>```c
>//获取原文件名
>static void do_rnfr(session_t *sess)
>{
>	
>	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
>	memset(sess->rnfr_name, 0, strlen(sess->rnfr_name) + 1);
>	strcpy(sess->rnfr_name, sess->arg);
>
>	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
>}
>
>//更换名字
>static void do_rnto(session_t *sess)
>{
>	//如果之前没有执行过rnfr
>	if(sess->rnfr_name == NULL)
>	{
>		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
>		return;
>	}
>
>	if(rename(sess->rnfr_name, sess->arg) < 0)
>	{
>		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
>		return;
>	}
>
>	free(sess->rnfr_name);
>	sess->rnfr_name = NULL;
>
>	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
>}
>```
>
>### 实现文件大小获取功能SIZE
>
>```c
>static void do_size(session_t *sess) 
>{
>	struct stat sbuf;
>	//找不到文件
>	if(stat(sess->arg, &sbuf) < 0)
>	{
>		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
>		return;
>	}
>	
>	//判断是否为常规文件
>	if(!S_ISREG(sbuf.st_mode))
>	{
>		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
>		return;
>	}
>
>	char buf[MAX_BUFFER_SIZE] = { 0 };
>	sprintf(buf, "%lld", sbuf.st_size);
>	
>	ftp_reply(sess, FTP_SIZEOK, buf);
>}
>```

-------------------------

# 2020_08_13

## 一、实现上传、下载、断点续传功能

> ### 实现断点续传功能REST
>
> ```c
> static void do_rest(session_t *sess)
> {
> 	//记录断点重传的位置
> 	sess->restart_pos = (long long)atoll(sess->arg);
> 
> 	char msg[MAX_BUFFER_SIZE] = { 0 };
> 	sprintf(msg, "Restart position accepted (%lld).", sess->restart_pos);
> 
> 	ftp_reply(sess, FTP_RESTOK, msg);
> }
> ```
>
> ### 实现文件下载功能RETR
>
> ```c
> //下载文件
> static void do_retr(session_t *sess)
> {
> 	//建立数据连接
> 	if(get_transfer_fd(sess) == 0)
> 	{
> 		return;
> 	}
> 	
> 	//打开文件
> 	int fd = open(sess->arg, O_RDONLY);
> 	if(fd == -1)
> 	{
> 		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
> 		return;
> 	}
> 
> 	//获取文件属性
> 	struct stat sbuf;
> 	fstat(fd, &sbuf);
> 
> 	long long offset = sess->restart_pos;
> 	sess->restart_pos = 0;
> 	
> 	//偏移位置大于等于文件大小，说明文件以及下载完毕
> 	if(offset >= sbuf.st_size)
> 	{
> 		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
> 	}
> 	else
> 	{
> 		char msg[MAX_BUFFER_SIZE] = { 0 };
> 		//获取文件传输格式
> 		if(sess->is_ascii == 1)
> 		{
> 			sprintf(msg, "Opening ASCII mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
> 		}
> 		else
> 		{
> 			sprintf(msg, "Opening BINARY mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
> 		}
> 
> 		ftp_reply(sess, FTP_DATACONN, msg);
> 		
> 		//断点续载，偏移到上次暂停的位置
> 		if(lseek(fd, offset, SEEK_SET) < 0)
> 		{
> 			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
> 			return;
> 		}
> 
> 		char buf[MAX_BUFFER_SIZE] = { 0 };
> 		int ret;
> 
> 		int read_count = 0;//本轮需要读取的大小
> 		int read_total_byte = sbuf.st_size;//需要读取的总大小
> 
> 		//开始数据传输
> 		while(1)
> 		{
> 			read_count = read_total_byte > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : read_total_byte;
> 			//从文件中读取数据
> 			ret = read(fd, buf, read_count);
> 			
> 			//数据读取失败
> 			if(ret == -1 || ret != read_count)
> 			{
> 				ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
> 				break;
> 			}
> 			//文件传输完成
> 			else if(ret == 0)
> 			{
> 				ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
> 				break;
> 			}
> 
> 			//将读取的数据传输给客户端
> 			if(send(sess->data_fd, buf, ret, 0) != ret)
> 			{
> 				//如果写入的数据大小和获取的不一样
> 				ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
> 				break;
> 			}
> 
> 			read_total_byte -= read_count;
> 		}
> 	}
> 
> 	//关闭数据连接
> 	close(fd);
> 	close(sess->data_fd);
> 	sess->data_fd = -1;
> }
> ```
>
> ### 实现文件上传功能STOR
>
> ```c
> static void do_stor(session_t *sess)
> {
> 	//建立数据连接
> 	if(get_transfer_fd(sess) == 0)
> 	{
> 		return;
> 	}
> 	
> 	//在服务器建立文件
> 	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0755);
> 	if(fd == -1)
> 	{
> 		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
> 		return;
> 	}
> 
> 	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");
> 
> 	//断点续传
> 	long long offset = sess->restart_pos;
> 	sess->restart_pos = 0;
> 
> 	//偏移到上次断开的位置
> 	if(lseek(fd, offset, SEEK_SET) < 0)
> 	{
> 		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
> 		return;
> 	}
> 	
> 	char buf[MAX_BUFFER_SIZE] = { 0 };
> 	int ret;
> 
> 	//开始数据传输
> 	while(1)
> 	{
> 		ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
> 		
> 		//数据读取失败
> 		if(ret == -1)
> 		{
> 			ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
> 			break;
> 		}
> 		//文件传输完成
> 		else if(ret == 0)
> 		{
> 			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
> 			break;
> 		}
> 
> 		//将获取的数据写入文件中
> 		if(write(fd, buf, ret) != ret)
> 		{
> 			//如果写入的数据大小和获取的不一样
> 			ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
> 			break;
> 		}
> 	}
> 
> 	//关闭数据连接
> 	close(fd);
> 	close(sess->data_fd);
> 	sess->data_fd = -1;
> }
> ```

------------------------

# 2020_08_13

## 一、实现配置文件解析

> ### 新增配置文件MiniFTP.conf
>
> ```c
> #是否开启被动模式
> pasv_enable=YES
> #是否开启主动模式
> port_enable=YES
> #FTP服务器端口
> listen_port=9188
> #最大连接数
> max_clients=2000
> #每ip最大连接数
> max_per_ip=50
> #accept超时间
> accept_timeout=60
> #connect超时间
> connect_timeout=60
> #控制连接超时时间
> idle_session_timeout=300
> #数据连接超时时间
> data_connection_timeout=300
> #掩码
> loacl_umask=077
> #最大上传速度
> upload_max_rate=0
> #最大下载速度
> download_mas_rate=0		
> #FTP服务器IP地址
> listen_address=192.168.0.128
> ```
>
> ### 新增配置项模块tunable
>
> ```c
> #ifndef _TUNABLE_H_
> #define _TUNABLE_H_
> extern int tunable_pasv_enable;							//是否开启被动模式
> extern int tunable_port_enable;							//是否开启主动模式
> extern unsigned int tunable_listen_port;				//FTP服务器端口
> extern unsigned int tunable_max_clients;				//最大连接数
> extern unsigned int tunable_max_per_ip;					//每ip最大连接数
> extern unsigned int tunable_accept_timeout;				//Accept超时间
> extern unsigned int tunable_connect_timeout;			//Connect超时间
> extern unsigned int tunable_idle_session_timeout;		//控制连接超时时间
> extern unsigned int tunable_data_connection_timeout;	//数据连接超时时间
> extern unsigned int tunable_local_umask;				//掩码
> extern unsigned int tunable_upload_max_rate;			//最大上传速度
> extern unsigned int tunable_download_max_rate;			//最大下载速度
> extern const char *tunable_listen_address;				//FTP服务器IP地址
> 
> #endif /* _TUNABLE_H_ */
> ```
>
> ### 新增配置文件解析模块parseconf
>
> ```c
> #include"parseconf.h"
> #include"tunable.h"
> 
> //建立配置项与变量的映射表
> 
> //bool类型
> static struct parseconf_bool_setting
> {
> 	const char* p_setting_name;
> 	int* p_var;
> }parseconf_bool_array[] = 
> {
> 	{"pasv_enable", &tunable_pasv_enable},
> 	{"port_enable", &tunable_port_enable}
> };
> 
> //uint类型
> static struct parseconf_uint_setting
> {
> 	const char* p_setting_name;
> 	unsigned int* p_var;
> }parseconf_uint_array[] = 
> {
> 	{"listen_port", &tunable_listen_port},
> 	{"max_clients", &tunable_max_clients},
> 	{"max_per_ip", &tunable_max_per_ip},
> 	{"accept_timeout", &tunable_accept_timeout},
> 	{"connect_timeout", &tunable_connect_timeout},
> 	{"idle_session_timeout", &tunable_idle_session_timeout},
> 	{"data_connection_timeout", &tunable_data_connection_timeout},
> 	{"local_umask", &tunable_local_umask},
> 	{"upload_max_rate", &tunable_upload_max_rate},
> 	{"download_max_rate", &tunable_download_max_rate}
> };
> 
> //字符类型
> static struct parseconf_str_setting
> {
> 	const char* p_setting_name;
> 	const char** p_var;
> }parseconf_str_array[] = 
> {
> 	{"listen_address", &tunable_listen_address}
> };
> 
> void parseconf_load_setting(const char *setting)
> {
> 	//分割变量名与值 pasv_enable=1;
> 	char key[MAX_KEY_VALUE_SIZE] = {0};
> 	char value[MAX_KEY_VALUE_SIZE] = {0};
> 	str_split(setting, key, value, '=');
> 
> 	int list_size = sizeof(parseconf_str_array) / sizeof(struct parseconf_str_setting);
> 	for(int i = 0; i < list_size; i++)
> 	{
> 		if(strcmp(key, parseconf_str_array[i].p_setting_name) == 0)
> 		{
> 			const char** p_cur_setting = parseconf_str_array[i].p_var;
> 			
> 			//如果之前不为空，直接释放，防止内存泄漏
> 			if(*p_cur_setting != NULL)
> 			{
> 				free((char*)(*p_cur_setting));
> 			}
> 			*p_cur_setting = strdup(value);//自动开辟空间的深拷贝
> 			return;
> 		}
> 	}
> 
> 	list_size = sizeof(parseconf_bool_array) / sizeof(struct parseconf_bool_setting);
> 	for(int i = 0; i < list_size; i++)
> 	{
> 		if(strcmp(key, parseconf_bool_array[i].p_setting_name) == 0)
> 		{
> 			str_to_upper(value);
> 			
> 			if(strcmp(value, "YES") == 0)
> 			{
> 				*parseconf_bool_array[i].p_var = 1;
> 			}
> 			else if(strcmp(value, "NO") == 0)
> 			{
> 				*parseconf_bool_array[i].p_var = 0;
> 			}
> 			else
> 			{
> 				printf("%d\n", strlen(value));
> 				fprintf(stderr, "bad bool value in config file for : %s\n", key);
> 				exit(EXIT_FAILURE);
> 			}
> 			return;
> 		}
> 	}
> 
> 	list_size = sizeof(parseconf_uint_array) / sizeof(struct parseconf_uint_setting);
> 	for(int i = 0; i < list_size; i++)
> 	{
> 		if(strcmp(key, parseconf_uint_array[i].p_setting_name) == 0)
> 		{
> 			//0则认为默认
> 			if(value[0] != '0')
> 			{
> 				*parseconf_uint_array[i].p_var = atoi(value);
> 			}
> 			return;
> 		}
> 	}
> }
> 
> void parseconf_load_file(const char *path)
> {
> 	FILE* fp = fopen(path, "r");
> 	if(fp == NULL)
> 	{
> 		ERR_EXIT("parseconf_load_file.");
> 	}
> 
> 	char setting_line[MAX_SETTING_LINE] = { 0 };
> 	while(fgets(setting_line, MAX_SETTING_LINE, fp) != NULL)
> 	{
> 		if(strlen(setting_line) == 0 || setting_line[0] == '#')
> 		{
> 			continue;
> 		}
> 
> 		str_trim_crlf(setting_line);
> 		parseconf_load_setting(setting_line);
> 		memset(setting_line, 0, MAX_SETTING_LINE);
> 	}
> 	
> 	fclose(fp);
> }
> ```

-----------------------------------------------------