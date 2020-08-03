#include"ftpproto.h"
#include"sysutil.h"

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

		//get command
		ret = recv(sess->ctl_fd, sess->cmdline, MAX_COMMAND_LINE, 0);
		if(ret < 0)
		{
			ERR_EXIT("recv");
		}
		else if(ret == 0)
		{
			exit(EXIT_SUCCESS);
		}

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
	//Authentication, confirm account and password
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
	//resolving ip address : PORT 192,168,1,128,5,35
	unsigned int addr[6] = { 0 };
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	
	sess->port_addr->sin_family = AF_INET;
	//set ip address
	unsigned char* p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = addr[0];
	p[1] = addr[1];
	p[2] = addr[2];
	p[3] = addr[3];

	//set port
	p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = addr[4];
	p[1] = addr[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
	char ip[16] = "192.168.0.128"; //server ip address
	sess->pasv_lst_fd = tcp_server(ip, 0); //automatic allocation port

	struct sockaddr_in address;
	socklen_t socklen = sizeof(struct sockaddr);

	if(getsockname(sess->pasv_lst_fd, (struct sockaddr*)&address, &socklen) < 0)
	{
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(address.sin_port);
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
		return 1;
	}

	return 0;
}

int pasv_action(const session_t* sess)
{
	if(sess->pasv_lst_fd != -1)
	{
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
		int sock = tcp_client();

		if(connect(sock, (struct sockaddr*)sess->port_addr, sizeof(struct sockaddr)) < 0)
		{
			ret = 0;
		}
		else
		{
			sess->data_fd = sock;
		}
	}

	if(pasv_action(sess))
	{
		int sock = accept(sess->pasv_lst_fd, NULL, NULL);
		if(sock < 0)
		{
			ret = 0;
		}
		else
		{
			close(sess->pasv_lst_fd);
			sess->pasv_lst_fd = -1;
			sess->data_fd = sock;
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
	//open working directory
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
		//ignore hidden files
		if(dt->d_name[0] == '.')
		{
			continue;
		}

		int offset = 0;
		memset(buf, MAX_BUFFER_SIZE, 0);

		//add permission information : drwxr-xr-x
		const char* perms = statbuf_get_perms(&sbuf);
		offset += sprintf(buf, "%s", perms);
		
		//add file information : 2 1000     1000            6
		offset += sprintf(buf + offset, "%3d %-8d %-8d %8u", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, sbuf.st_size);
		
		//add data information : 6 Mar 03 09:42
		const char* date = statbuf_get_date(&sbuf);
		offset += sprintf(buf + offset, " %s ", date);

		//add dir information : Desktop
		sprintf(buf + offset, "%s\r\n", dt->d_name);

		send(sess->data_fd, buf, strlen(buf), 0);
	}
}

static void do_list(session_t *sess)
{
	//1.establish data connection
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}

	//2.reply code-150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3.show file list
	list_common(sess);

	//4.close connection
	close(sess->data_fd);
	sess->data_fd = -1;

	//5.reply code-226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}