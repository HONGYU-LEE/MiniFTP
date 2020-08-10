#include"ftpproto.h"

void ftp_reply(session_t* sess, int state, char* msg)
{
	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "%d %s\r\n", state, msg);

	send(sess->ctl_fd, buf, strlen(buf), 0);
}


typedef struct ftpcmd
{
	const char* cmd;
	void(*handler)(session_t *sess);
}ftpcmd_t;

static void do_user(session_t *sess); 
static void do_pass(session_t *sess);
static void do_syst(session_t *sess); 
static void do_feat(session_t *sess); 
static void do_pwd(session_t *sess); 
static void do_type(session_t *sess); 
static void do_port(session_t *sess); 
static void do_pasv(session_t *sess); 
static void do_list(session_t *sess); 

int pasv_action(const session_t* sess);
int port_action(const session_t* sess);
/*
static void do_cwd(session_t *sess); 
static void do_cdup(session_t *sess); 
static void do_quit(session_t *sess); 


//static void do_stru(session_t *sess); 
//static void do_mode(session_t *sess); 
static void do_retr(session_t *sess); 
static void do_stor(session_t *sess); 
static void do_appe(session_t *sess); 

static void do_nlst(session_t *sess); 
static void do_rest(session_t *sess); 
static void do_abor(session_t *sess); 

static void do_mkd(session_t *sess); 
static void do_rmd(session_t *sess); 
static void do_dele(session_t *sess); 
static void do_rnfr(session_t *sess); 
static void do_rnto(session_t *sess); 
static void do_site(session_t *sess); 
static void do_feat(session_t *sess); 
static void do_size(session_t *sess); 
static void do_stat(session_t *sess); 
static void do_noop(session_t *sess); 
static void do_help(session_t *sess);
*/
static ftpcmd_t ctl_cmds[] = 
{
	{"USER", do_user },
	{"PASS", do_pass },
	{"SYST", do_syst },
	{"FEAT", do_feat },
	{"PWD",  do_pwd },
	{"TYPE", do_type },
	{"LIST", do_list },
	{"PORT", do_port },
	{"PASV", do_pasv },
	/*
	{"CWD" , do_cwd },
	{"XCWD", do_cwd },
	{"CDUP", do_cdup },
	{"XCUP", do_cdup },
	{"QUIT", do_quit },
	{"ACCT", NULL },
	{"SMNT", NULL },
	{"REIN", NULL },

	//传输参数命令 
	
	
	//{"STRU", do_struNULL },
	//{"MODE", do_modeNULL },

	//服务命令
	{"RETR", do_retr },
	{"STOR", do_stor },
	{"APPE", do_appe },

	{"NLST", do_nlst },
	{"REST", do_rest },
	{"ABOR", do_abor },
	{"\377\364\377\362ABOR", do_abor},

	{"XPWD", do_pwd },
	{"MKD", do_mkd },
	{"XMKD", do_mkd },
	{"RMD", do_rmd },
	{"XRMD", do_rmd },
	{"DELE", do_dele },
	{"RNFR", do_rnfr },
	{"RNTO", do_rnto },
	{"SITE", do_site },
	
	
	{"SIZE", do_size },
	{"STAT", do_stat },
	{"NOOP", do_noop },
	{"HELP", do_help },
	{"STOU", NULL },
	{"ALLO", NULL }
	*/
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

static void do_pasv(session_t *sess)
{
	char ip[16] = "192.168.0.128"; //服务器IP地址

	//获取监听套接字的端口号
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (unsigned short)priv_sock_recv_int(sess->child_fd);
	
	int addr[4] = { 0 };
	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);

	char buf[MAX_BUFFER_SIZE] = { 0 };
	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", addr[0], addr[1], addr[2], addr[3], port >> 8, port & 0x00ff);

	ftp_reply(sess, FTP_PASVOK, buf);
}

int port_action(const session_t* sess)
{
	if(sess->port_addr)
	{
		if(pasv_action(sess))
		{
			perror("both port and pasv are active.");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

int pasv_action(const session_t* sess)
{
	//验证是否处于被动模式
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);

	if(priv_sock_recv_int(sess->child_fd))
	{
		if(port_action(sess))
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
	if(!port_action(sess) && !pasv_action(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
		return 0;
	}
	
	int ret = 1;
	
	if(port_action(sess))
	{
		if(get_port_fd(sess) == 0)
		{
			ret = 0;
		}
	}

	if(pasv_action(sess))
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

	return ret;
}

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
		offset += sprintf(buf + offset, "%3d %-8d %-8d %8u", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, sbuf.st_size);
		
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
