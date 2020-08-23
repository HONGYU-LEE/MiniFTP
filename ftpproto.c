#include"ftpproto.h"

session_t* p_sess;

void ftp_reply(session_t* sess, int state, char* msg)
{
	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "%d %s\r\n", state, msg);

	send(sess->ctl_fd, buf, strlen(buf), 0);
}

static void do_user(session_t *sess); 
static void do_pass(session_t *sess);
static void do_syst(session_t *sess); 
static void do_feat(session_t *sess); 
static void do_pwd(session_t *sess); 
static void do_type(session_t *sess); 
static void do_port(session_t *sess); 
static void do_pasv(session_t *sess); 
static void do_list(session_t *sess); 
static void do_cwd(session_t *sess); 
static void do_cdup(session_t *sess); 
static void do_mkd(session_t *sess); 
static void do_rmd(session_t *sess); 
static void do_dele(session_t *sess); 
static void do_rnfr(session_t *sess); 
static void do_rnto(session_t *sess); 
static void do_size(session_t *sess); 
static void do_retr(session_t *sess); 
static void do_stor(session_t *sess); 
static void do_rest(session_t *sess); 
static void do_quit(session_t *sess); 

int pasv_active(const session_t* sess);
int port_active(const session_t* sess);

void start_data_alarm();
void start_idle_alarm();


//命令映射表
typedef struct ftpcmd
{
	const char* cmd;
	void(*handler)(session_t *sess);
}ftpcmd_t;

static ftpcmd_t ctl_cmds[] = 
{
	{"USER", do_user },
	{"PASS", do_pass },
	{"PWD" , do_pwd  },
	{"CWD" , do_cwd  },
	{"QUIT", do_quit },
	{"PORT", do_port },
	{"PASV", do_pasv },
	{"TYPE", do_type },
	{"SYST", do_syst },
	{"FEAT", do_feat },
	{"LIST", do_list },
	{"MKD" , do_mkd  },
	{"RMD" , do_rmd	 },
	{"DELE", do_dele },
	{"RNFR", do_rnfr },
	{"RNTO", do_rnto },
	{"SIZE", do_size },
	{"RETR", do_retr },
	{"STOR", do_stor },
	{"CDUP", do_cdup },
	{"REST", do_rest },

};

void handle_child(session_t* sess)
{
	ftp_reply(sess, FTP_GREET, "(MiniFtp 1.0)");
	int ret;

	while(1)
	{
		memset(sess->cmdline, 0, MAX_COMMAND_LINE);
		memset(sess->cmd, 0, MAX_COMMAND);
		memset(sess->arg, 0, MAX_ARG);
		
		start_idle_alarm();//控制连接空闲断开

		//获取命令
		ret = recv(sess->ctl_fd, sess->cmdline, MAX_COMMAND_LINE, 0);
		if(ret < 0)
		{
			ERR_EXIT("recv error.");
		}
		else if(ret == 0)
		{
			exit(EXIT_SUCCESS);
		}

		//解析出命令和参数
		str_trim_crlf(sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		
		int i;
		int list_size = sizeof(ctl_cmds) / sizeof(ftpcmd_t);

		for(i = 0; i < list_size; i++)
		{
			if(strcmp(sess->cmd, ctl_cmds[i].cmd) == 0)
			{
				if(ctl_cmds[i].handler != NULL)
				{
					ctl_cmds[i].handler(sess);
				}
				else
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Command not implemented.");
				}
				break;
			}
		}

		if(i == list_size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}


/////////////////////////////////////////////////////
/*					访问控制					   */
static void do_user(session_t* sess)
{
	struct passwd* pwd = getpwnam(sess->arg);
	
	if(pwd != NULL)
	{
		sess->uid = pwd->pw_uid;
	}

	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

static void do_pass(session_t* sess)
{
	//鉴权,确认用户和密码是否正确
	struct passwd *pwd = getpwuid(sess->uid);

	if(pwd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	struct spwd* spd = getspnam(pwd->pw_name);
	if(spd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	char* encry_pwd = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encry_pwd, spd->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	setegid(pwd->pw_gid);
	seteuid(pwd->pw_uid);
	chdir(pwd->pw_dir);

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t* sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	send(sess->ctl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
	send(sess->ctl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
	send(sess->ctl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
	send(sess->ctl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
	send(sess->ctl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
	send(sess->ctl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0);
	send(sess->ctl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
	send(sess->ctl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
	send(sess->ctl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
	send(sess->ctl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
}

static void do_pwd(session_t *sess)
{
	char buf[MAX_BUFFER_SIZE] = { 0 };
	getcwd(buf, MAX_BUFFER_SIZE); // /home/user
	
	char msg[MAX_BUFFER_SIZE] = { 0 };
	sprintf(msg, "\"%s\" is the current directory", buf); // "/home/user"

	ftp_reply(sess, FTP_PWDOK, msg);
}

static void do_type(session_t *sess)
{
	if(strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}

/////////////////////////////////////////////////////
/*					数据连接					   */
static void do_port(session_t *sess)
{
	//解析IP地址 例如: PORT 192,168,1,128,5,35
	unsigned int addr[6] = { 0 };
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	
	sess->port_addr->sin_family = AF_INET;
	//设置IP地址
	unsigned char* p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = addr[0];
	p[1] = addr[1];
	p[2] = addr[2];
	p[3] = addr[3];

	//设置端口号
	p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = addr[4];
	p[1] = addr[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}


static void do_pasv(session_t *sess)
{
	char ip[16] = { 0 }; //服务器IP地址
	get_localip(ip);

	//获取监听套接字的端口号
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (unsigned short)priv_sock_recv_int(sess->child_fd);
	
	int addr[4] = { 0 };
	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);

	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", addr[0], addr[1], addr[2], addr[3], port >> 8, port & 0x00ff);

	ftp_reply(sess, FTP_PASVOK, buf);
}

int get_port_fd(session_t *sess)
{
	int ret = 1;
	//ftp服务进程向nobody进程发起通信
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

	unsigned short port = ntohs(sess->port_addr->sin_port);
	char* ip = inet_ntoa(sess->port_addr->sin_addr);

	//将客户端的地址信息传递给nobody进程，让其进行主动连接
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	char res = priv_sock_recv_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		//建立连接成功，获取数据连接
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return ret;
}

int get_pasv_fd(session_t *sess)
{
	int ret = 1;

	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);

	char res = priv_sock_recv_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		//建立连接成功，获取数据连接
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return ret;
}

int port_active(const session_t* sess)
{
	if(sess->port_addr)
	{
		if(pasv_active(sess))
		{
			perror("both port and pasv are active.");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

int pasv_active(const session_t* sess)
{
	//验证是否处于被动模式
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);

	if(priv_sock_recv_int(sess->child_fd))
	{
		if(port_active(sess))
		{
			perror("both port and pasv are active.");
			exit(EXIT_FAILURE);
		}

		return 1;
	}

	return 0;
}

int get_transfer_fd(session_t *sess)
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
		return 0;
	}
	
	int ret = 1;
	
	if(port_active(sess))
	{
		if(get_port_fd(sess) == 0)
		{
			ret = 0;
		}
	}

	if(pasv_active(sess))
	{
		if(get_pasv_fd(sess) == 0)
		{
			ret = 0;
		}
	}

	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}
	
	//如果数据连接建立成功，则开启数据连接空闲断开闹钟
	if(ret)
	{
		start_data_alarm();
	}

	return ret;
}

/////////////////////////////////////////////////////
/*					列表显示					   */
static void list_common(session_t *sess)
{
	//打开工作目录
	DIR* dir = opendir(".");
	if(dir == NULL)
	{
		return;
	}

	//drwxr-xr-x    2 1000     1000            6 Mar 03 09:42 Desktop
	char buf[MAX_BUFFER_SIZE] = { 0 };
	
	struct stat sbuf;
	struct dirent* dt;
	
	while((dt = readdir(dir)) != NULL)
	{
		if(stat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
		//忽略隐藏的文件
		if(dt->d_name[0] == '.')
		{
			continue;
		}

		int offset = 0;
		memset(buf, MAX_BUFFER_SIZE, 0);

		//拼接权限信息 : drwxr-xr-x
		const char* perms = statbuf_get_perms(&sbuf);
		offset += sprintf(buf, "%s", perms);
		
		//拼接文件信息 : 2 1000     1000            6
		offset += sprintf(buf + offset, "%3d %-8d %-8d %8lld", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (long long)sbuf.st_size);
		
		//拼接日期信息 : 6 Mar 03 09:42
		const char* date = statbuf_get_date(&sbuf);
		offset += sprintf(buf + offset, " %s ", date);

		//拼接目录名 : Desktop
		sprintf(buf + offset, "%s\r\n", dt->d_name);

		send(sess->data_fd, buf, strlen(buf), 0);
	}
}

static void do_list(session_t *sess)
{
	//1.建立数据连接
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}

	//2.回复响应码150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3.显示文件列表
	list_common(sess);

	//4.关闭连接
	close(sess->data_fd);
	sess->data_fd = -1;

	//5.回复响应码226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

/////////////////////////////////////////////////////
/*					服务命令					   */
static void do_cwd(session_t *sess)
{
	if(chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK , "Directory successfully changed.");
}

void do_cdup(session_t *sess) 
{ 
	if(chdir("..") < 0) 
	{ 
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory."); 
		return; 
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed."); 
}


static void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg, 0777) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed."); 
		return;
	}

	//257 "/home/lee/test1/1" created
	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "\"%s\" created", sess->arg);
	
	ftp_reply(sess, FTP_MKDIROK, buf);
}

static void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_RMDIROK , "Remove directory operation failed.");
}

static void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
		return;
	}

	ftp_reply(sess, FTP_DELEOK , "Delete operation successful.");
}

//获取原文件名
static void do_rnfr(session_t *sess)
{
	
	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->rnfr_name) + 1);
	strcpy(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
	//如果之前没有执行过rnfr
	if(sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}

	if(rename(sess->rnfr_name, sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
		return;
	}

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;

	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
}

static void do_size(session_t *sess) 
{
	struct stat sbuf;
	//找不到文件
	if(stat(sess->arg, &sbuf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	
	//判断是否为常规文件
	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "%lld", sbuf.st_size);
	
	ftp_reply(sess, FTP_SIZEOK, buf);
}

static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
}

/////////////////////////////////////////////////////
/*					数据传输					   */
static void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	init_cur_time();
	long cur_sec = get_time_sec();
	long cur_usec = get_time_usec();

	double pass_time = (double)(cur_sec - sess->transfer_start_sec);//先计算秒数
	pass_time += (double)(cur_usec - sess->transfer_start_usec) / (double)1000000;//计算微秒部分

	if(pass_time <= (double)0) 
	{
		//等于0的情况有可能，因为传的太快了
		pass_time = (double)0.01;
	}

	unsigned long cur_rate = (unsigned long)((double)bytes_transfered / pass_time);//计算当前速度
	unsigned long max_rate = (is_upload == 1) ? sess->upload_max_rate : sess->download_max_rate;
	
	//如果当前速度大于最大速度，则需要进行休眠来限速
	if(cur_rate > max_rate)
	{
		//睡眠时间 = (当前传输速度 / 最大传输速度 - 1) * 传输时间 = 速率查 * 传输时间 
		double rate_ratio = cur_rate / max_rate;//速率差
		double sleep_time = (rate_ratio - (double)1) * pass_time;

		nano_sleep(sleep_time);
	}
	
	
	//更新时间
	init_cur_time();
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}

//上传文件
static void do_stor(session_t *sess)
{
	//建立数据连接
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	//在服务器建立文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0755);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//断点续传
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	//偏移到上次断开的位置
	if(lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}
	
	char buf[MAX_BUFFER_SIZE] = { 0 };
	int ret;

	//记录当前时间
	init_cur_time();
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();

	//开始数据传输
	while(1)
	{
		ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
		
		//数据读取失败
		if(ret == -1)
		{
			ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
			break;
		}
		//文件传输完成
		else if(ret == 0)
		{
			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
			break;
		}
		//设置数据连接状态
		sess->data_process = 1;
		//限速
		if(sess->upload_max_rate != 0)
		{
			limit_rate(sess, ret, 1);
		}

		//将获取的数据写入文件中
		if(write(fd, buf, ret) != ret)
		{
			//如果写入的数据大小和获取的不一样
			ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
			break;
		}
	}

	//关闭数据连接
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	
	start_idle_alarm();//重启控制连接断开计时
}

//下载文件
static void do_retr(session_t *sess)
{
	//建立数据连接
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	//打开文件
	int fd = open(sess->arg, O_RDONLY);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//获取文件属性
	struct stat sbuf;
	fstat(fd, &sbuf);

	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	//偏移位置大于等于文件大小，说明文件以及下载完毕
	if(offset >= sbuf.st_size)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else
	{
		char msg[MAX_BUFFER_SIZE] = { 0 };
		//获取文件传输格式
		if(sess->is_ascii == 1)
		{
			sprintf(msg, "Opening ASCII mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
		}
		else
		{
			sprintf(msg, "Opening BINARY mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
		}

		ftp_reply(sess, FTP_DATACONN, msg);
		
		//断点续载，偏移到上次暂停的位置
		if(lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}

		char buf[MAX_BUFFER_SIZE] = { 0 };
		int ret;

		int read_count = 0;//本轮需要读取的大小
		int read_total_byte = sbuf.st_size;//需要读取的总大小
		
		//记录当前时间
		init_cur_time();
		sess->transfer_start_sec = get_time_sec();
		sess->transfer_start_usec = get_time_usec();

		//开始数据传输
		while(1)
		{
			read_count = read_total_byte > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : read_total_byte;
			//从文件中读取数据
			ret = read(fd, buf, read_count);
			
			//数据读取失败
			if(ret == -1 || ret != read_count)
			{
				ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
				break;
			}
			//文件传输完成
			else if(ret == 0)
			{
				ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
				break;
			}

			//设置数据连接状态
			sess->data_process = 1;
			//限速
			if(sess->download_max_rate != 0)
			{
				limit_rate(sess, ret, 0);
			}

			//将读取的数据传输给客户端
			if(send(sess->data_fd, buf, ret, 0) != ret)
			{
				//如果写入的数据大小和获取的不一样
				ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
				break;
			}

			read_total_byte -= read_count;
		}
	}

	//关闭数据连接
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;

	start_idle_alarm();//重启控制连接断开计时
}

static void do_rest(session_t *sess)
{
	//记录断点重传的位置
	sess->restart_pos = (long long)atoll(sess->arg);

	char msg[MAX_BUFFER_SIZE] = { 0 };
	sprintf(msg, "Restart position accepted (%lld).", sess->restart_pos);

	ftp_reply(sess, FTP_RESTOK, msg);
}

/////////////////////////////////////////////////////
/*					空闲断开					   */
void handle_idle_sigalrm(int sig)
{
	shutdown(p_sess->ctl_fd, SHUT_RD);//先关闭读端，回复完响应码后再关闭写端
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctl_fd, SHUT_WR);
	exit(EXIT_SUCCESS);
}

void start_idle_alarm()
{
	if(tunable_idle_session_timeout != 0)
	{
		signal(SIGALRM, handle_idle_sigalrm);
		alarm(tunable_idle_session_timeout);
	}
}

void handle_data_sigalrm(int sig)
{
	//如果当前没有在传输，则断开连接
	if(p_sess->data_process == 0)
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	//如果当前在传输，则忽略本次，重新启动闹钟
	else
	{
		p_sess->data_process = 0;
		start_data_alarm();
	}
}

void start_data_alarm()
{
	if(tunable_data_connection_timeout != 0)
	{
		signal(SIGALRM, handle_data_sigalrm);
		alarm(tunable_data_connection_timeout);
	}
	//停止控制连接的计时
	else if(tunable_idle_session_timeout > 0)
	{
		alarm(0);
	}
}

