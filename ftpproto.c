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
static void do_cwd(session_t *sess); 
static void do_cdup(session_t *sess); 
static void do_quit(session_t *sess); 
static void do_port(session_t *sess); 
static void do_pasv(session_t *sess); 
static void do_type(session_t *sess); 
//static void do_stru(session_t *sess); 
//static void do_mode(session_t *sess); 
static void do_retr(session_t *sess); 
static void do_stor(session_t *sess); 
static void do_appe(session_t *sess); 
static void do_list(session_t *sess); 
static void do_nlst(session_t *sess); 
static void do_rest(session_t *sess); 
static void do_abor(session_t *sess); 
static void do_pwd(session_t *sess); 
static void do_mkd(session_t *sess); 
static void do_rmd(session_t *sess); 
static void do_dele(session_t *sess); 
static void do_rnfr(session_t *sess); 
static void do_rnto(session_t *sess); 
static void do_site(session_t *sess); 
static void do_syst(session_t *sess); 
static void do_feat(session_t *sess); 
static void do_size(session_t *sess); 
static void do_stat(session_t *sess); 
static void do_noop(session_t *sess); 
static void do_help(session_t *sess);

static ftpcmd_t ctl_cmds[] = 
{
	/* 访问控制命令 */
	{"USER", do_user },
	{"PASS", do_pass },
	{"CWD" , do_cwd },
	{"XCWD", do_cwd },
	{"CDUP", do_cdup },
	{"XCUP", do_cdup },
	{"QUIT", do_quit },
	{"ACCT", NULL },
	{"SMNT", NULL },
	{"REIN", NULL },

	/* 传输参数命令 */
	{"PORT", do_port },
	{"PASV", do_pasv },
	{"TYPE", do_type },
	{"STRU", /*do_stru*/NULL },
	{"MODE", /*do_mode*/NULL },

	/* 服务命令 */
	{"RETR", do_retr },
	{"STOR", do_stor },
	{"APPE", do_appe },
	{"LIST", do_list },
	{"NLST", do_nlst },
	{"REST", do_rest },
	{"ABOR", do_abor },
	{"\377\364\377\362ABOR", do_abor},
	{"PWD", do_pwd },
	{"XPWD", do_pwd },
	{"MKD", do_mkd },
	{"XMKD", do_mkd },
	{"RMD", do_rmd },
	{"XRMD", do_rmd },
	{"DELE", do_dele },
	{"RNFR", do_rnfr },
	{"RNTO", do_rnto },
	{"SITE", do_site },
	{"SYST", do_syst },
	{"FEAT", do_feat },
	{"SIZE", do_size },
	{"STAT", do_stat },
	{"NOOP", do_noop },
	{"HELP", do_help },
	{"STOU", NULL },
	{"ALLO", NULL }

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
