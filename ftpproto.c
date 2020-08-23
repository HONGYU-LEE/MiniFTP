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


//����ӳ���
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
		
		start_idle_alarm();//�������ӿ��жϿ�

		//��ȡ����
		ret = recv(sess->ctl_fd, sess->cmdline, MAX_COMMAND_LINE, 0);
		if(ret < 0)
		{
			ERR_EXIT("recv error.");
		}
		else if(ret == 0)
		{
			exit(EXIT_SUCCESS);
		}

		//����������Ͳ���
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
/*					���ʿ���					   */
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
	//��Ȩ,ȷ���û��������Ƿ���ȷ
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
/*					��������					   */
static void do_port(session_t *sess)
{
	//����IP��ַ ����: PORT 192,168,1,128,5,35
	unsigned int addr[6] = { 0 };
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	
	sess->port_addr->sin_family = AF_INET;
	//����IP��ַ
	unsigned char* p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = addr[0];
	p[1] = addr[1];
	p[2] = addr[2];
	p[3] = addr[3];

	//���ö˿ں�
	p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = addr[4];
	p[1] = addr[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}


static void do_pasv(session_t *sess)
{
	char ip[16] = { 0 }; //������IP��ַ
	get_localip(ip);

	//��ȡ�����׽��ֵĶ˿ں�
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
	//ftp���������nobody���̷���ͨ��
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

	unsigned short port = ntohs(sess->port_addr->sin_port);
	char* ip = inet_ntoa(sess->port_addr->sin_addr);

	//���ͻ��˵ĵ�ַ��Ϣ���ݸ�nobody���̣����������������
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	char res = priv_sock_recv_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		//�������ӳɹ�����ȡ��������
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
		//�������ӳɹ�����ȡ��������
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
	//��֤�Ƿ��ڱ���ģʽ
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
	
	//����������ӽ����ɹ��������������ӿ��жϿ�����
	if(ret)
	{
		start_data_alarm();
	}

	return ret;
}

/////////////////////////////////////////////////////
/*					�б���ʾ					   */
static void list_common(session_t *sess)
{
	//�򿪹���Ŀ¼
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
		//�������ص��ļ�
		if(dt->d_name[0] == '.')
		{
			continue;
		}

		int offset = 0;
		memset(buf, MAX_BUFFER_SIZE, 0);

		//ƴ��Ȩ����Ϣ : drwxr-xr-x
		const char* perms = statbuf_get_perms(&sbuf);
		offset += sprintf(buf, "%s", perms);
		
		//ƴ���ļ���Ϣ : 2 1000     1000            6
		offset += sprintf(buf + offset, "%3d %-8d %-8d %8lld", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (long long)sbuf.st_size);
		
		//ƴ��������Ϣ : 6 Mar 03 09:42
		const char* date = statbuf_get_date(&sbuf);
		offset += sprintf(buf + offset, " %s ", date);

		//ƴ��Ŀ¼�� : Desktop
		sprintf(buf + offset, "%s\r\n", dt->d_name);

		send(sess->data_fd, buf, strlen(buf), 0);
	}
}

static void do_list(session_t *sess)
{
	//1.������������
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}

	//2.�ظ���Ӧ��150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3.��ʾ�ļ��б�
	list_common(sess);

	//4.�ر�����
	close(sess->data_fd);
	sess->data_fd = -1;

	//5.�ظ���Ӧ��226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

/////////////////////////////////////////////////////
/*					��������					   */
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

//��ȡԭ�ļ���
static void do_rnfr(session_t *sess)
{
	
	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->rnfr_name) + 1);
	strcpy(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
	//���֮ǰû��ִ�й�rnfr
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
	//�Ҳ����ļ�
	if(stat(sess->arg, &sbuf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	
	//�ж��Ƿ�Ϊ�����ļ�
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
/*					���ݴ���					   */
static void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	init_cur_time();
	long cur_sec = get_time_sec();
	long cur_usec = get_time_usec();

	double pass_time = (double)(cur_sec - sess->transfer_start_sec);//�ȼ�������
	pass_time += (double)(cur_usec - sess->transfer_start_usec) / (double)1000000;//����΢�벿��

	if(pass_time <= (double)0) 
	{
		//����0������п��ܣ���Ϊ����̫����
		pass_time = (double)0.01;
	}

	unsigned long cur_rate = (unsigned long)((double)bytes_transfered / pass_time);//���㵱ǰ�ٶ�
	unsigned long max_rate = (is_upload == 1) ? sess->upload_max_rate : sess->download_max_rate;
	
	//�����ǰ�ٶȴ�������ٶȣ�����Ҫ��������������
	if(cur_rate > max_rate)
	{
		//˯��ʱ�� = (��ǰ�����ٶ� / ������ٶ� - 1) * ����ʱ�� = ���ʲ� * ����ʱ�� 
		double rate_ratio = cur_rate / max_rate;//���ʲ�
		double sleep_time = (rate_ratio - (double)1) * pass_time;

		nano_sleep(sleep_time);
	}
	
	
	//����ʱ��
	init_cur_time();
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}

//�ϴ��ļ�
static void do_stor(session_t *sess)
{
	//������������
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	//�ڷ����������ļ�
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0755);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//�ϵ�����
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	//ƫ�Ƶ��ϴζϿ���λ��
	if(lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}
	
	char buf[MAX_BUFFER_SIZE] = { 0 };
	int ret;

	//��¼��ǰʱ��
	init_cur_time();
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();

	//��ʼ���ݴ���
	while(1)
	{
		ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
		
		//���ݶ�ȡʧ��
		if(ret == -1)
		{
			ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
			break;
		}
		//�ļ��������
		else if(ret == 0)
		{
			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
			break;
		}
		//������������״̬
		sess->data_process = 1;
		//����
		if(sess->upload_max_rate != 0)
		{
			limit_rate(sess, ret, 1);
		}

		//����ȡ������д���ļ���
		if(write(fd, buf, ret) != ret)
		{
			//���д������ݴ�С�ͻ�ȡ�Ĳ�һ��
			ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
			break;
		}
	}

	//�ر���������
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	
	start_idle_alarm();//�����������ӶϿ���ʱ
}

//�����ļ�
static void do_retr(session_t *sess)
{
	//������������
	if(get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	//���ļ�
	int fd = open(sess->arg, O_RDONLY);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//��ȡ�ļ�����
	struct stat sbuf;
	fstat(fd, &sbuf);

	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	//ƫ��λ�ô��ڵ����ļ���С��˵���ļ��Լ��������
	if(offset >= sbuf.st_size)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else
	{
		char msg[MAX_BUFFER_SIZE] = { 0 };
		//��ȡ�ļ������ʽ
		if(sess->is_ascii == 1)
		{
			sprintf(msg, "Opening ASCII mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
		}
		else
		{
			sprintf(msg, "Opening BINARY mode data connection for %s (%d bytes).", sess->arg, sbuf.st_size);
		}

		ftp_reply(sess, FTP_DATACONN, msg);
		
		//�ϵ����أ�ƫ�Ƶ��ϴ���ͣ��λ��
		if(lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}

		char buf[MAX_BUFFER_SIZE] = { 0 };
		int ret;

		int read_count = 0;//������Ҫ��ȡ�Ĵ�С
		int read_total_byte = sbuf.st_size;//��Ҫ��ȡ���ܴ�С
		
		//��¼��ǰʱ��
		init_cur_time();
		sess->transfer_start_sec = get_time_sec();
		sess->transfer_start_usec = get_time_usec();

		//��ʼ���ݴ���
		while(1)
		{
			read_count = read_total_byte > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : read_total_byte;
			//���ļ��ж�ȡ����
			ret = read(fd, buf, read_count);
			
			//���ݶ�ȡʧ��
			if(ret == -1 || ret != read_count)
			{
				ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
				break;
			}
			//�ļ��������
			else if(ret == 0)
			{
				ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
				break;
			}

			//������������״̬
			sess->data_process = 1;
			//����
			if(sess->download_max_rate != 0)
			{
				limit_rate(sess, ret, 0);
			}

			//����ȡ�����ݴ�����ͻ���
			if(send(sess->data_fd, buf, ret, 0) != ret)
			{
				//���д������ݴ�С�ͻ�ȡ�Ĳ�һ��
				ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
				break;
			}

			read_total_byte -= read_count;
		}
	}

	//�ر���������
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;

	start_idle_alarm();//�����������ӶϿ���ʱ
}

static void do_rest(session_t *sess)
{
	//��¼�ϵ��ش���λ��
	sess->restart_pos = (long long)atoll(sess->arg);

	char msg[MAX_BUFFER_SIZE] = { 0 };
	sprintf(msg, "Restart position accepted (%lld).", sess->restart_pos);

	ftp_reply(sess, FTP_RESTOK, msg);
}

/////////////////////////////////////////////////////
/*					���жϿ�					   */
void handle_idle_sigalrm(int sig)
{
	shutdown(p_sess->ctl_fd, SHUT_RD);//�ȹرն��ˣ��ظ�����Ӧ����ٹر�д��
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
	//�����ǰû���ڴ��䣬��Ͽ�����
	if(p_sess->data_process == 0)
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	//�����ǰ�ڴ��䣬����Ա��Σ�������������
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
	//ֹͣ�������ӵļ�ʱ
	else if(tunable_idle_session_timeout > 0)
	{
		alarm(0);
	}
}

