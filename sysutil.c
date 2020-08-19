#include"sysutil.h"

int tcp_server(const char* ip, unsigned short port)
{
	int lst_fd;
	
	if((lst_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		ERR_EXIT("socket error.");
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	
	int on = 1;
	//开启地址重用
	if(setsockopt(lst_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
		ERR_EXIT("setsockopt error.");
	}

	if(bind(lst_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		ERR_EXIT("bind error.");
	}

	if(listen(lst_fd, SOMAXCONN) < 0)
	{
		ERR_EXIT("listen error.");
	}

	return lst_fd;
}

int tcp_client(int port)
{
	int sock;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		ERR_EXIT("tcp_client error.");
	}

	if(port > 0)
	{
		int on = 1;
		if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		{
			ERR_EXIT("setsockopt error.");
		}

		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;	

		if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		{
			ERR_EXIT("bind port 20");
		}
	}

	return sock;
}

const char* statbuf_get_perms(const struct stat *sbuf)
{
	//- --- --- ---
	static char perms[] = "----------";
	mode_t mode = sbuf->st_mode;

	switch(mode & S_IFMT)
	{
		//文件属性
		case S_IFREG:
			perms[0] = '-';
			break;
		case S_IFIFO:
			perms[0] = 'p';
			break;
		case S_IFDIR:
			perms[0] = 'd';
			break;
		case S_IFCHR:
			perms[0] = 'c';
			break;
		case S_IFBLK:
			perms[0] = 'b';
			break;
		case S_IFLNK:
			perms[0] = 'l';
			break;
		case S_IFSOCK:
			perms[0] = 's';
			break;
	}
	
	//权限
	if(mode & S_IRUSR)
		perms[1] = 'r';
	if(mode & S_IWUSR)
		perms[2] = 'w';
	if(mode & S_IXUSR)
		perms[3] = 'x';
		
	if(mode & S_IRGRP)
		perms[4] = 'r';
	if(mode & S_IWGRP)
		perms[5] = 'w';	
	if(mode & S_IXGRP)
		perms[6] = 'x';

	if(mode & S_IROTH)
		perms[7] = 'r';
	if(mode & S_IWOTH)
		perms[8] = 'w';
	if(mode & S_IXOTH)
		perms[9] = 'x';

	return perms;
}

const char* statbuf_get_date(const struct stat *sbuf)
{
	static char dates[64] = { 0 };

	time_t file_time = sbuf->st_mtime;
	struct tm* ptm = localtime(&file_time);

	strftime(dates, 64, "%b %e %H:%M", ptm);

	return dates;
}

void send_fd(int sock_fd, int fd)
{
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int *p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}

void get_localip(char* ip)
{
	char name[MAX_HOST_NAME_SIZE] = { 0 };
	//获取主机名
	if(gethostname(name, MAX_HOST_NAME_SIZE) < 0)
	{
		ERR_EXIT("gethostname");
	}

	//通过主机名获取ip地址
	struct hostent* ph;
	ph = gethostbyname(name);
	if(ph == NULL)
	{
		ERR_EXIT("gethostbyname");
	}
	strcpy(ip, inet_ntoa(*(struct in_addr*)ph->h_addr));
}

static struct timeval s_cur_time;

void init_cur_time()
{
	//获取当前系统的时间
	if(gettimeofday(&s_cur_time, NULL) < 0)
	{
		ERR_EXIT("gettimeofdau");
	}
}

long get_time_sec()
{
	return s_cur_time.tv_sec;
}

long get_time_usec()
{
	return s_cur_time.tv_usec;
}

void nano_sleep(double sleep_time)
{
	time_t sec = (time_t)sleep_time;//秒数，整数部分
	double decimal = sleep_time - (double)sec;//纳秒，小数部分

	struct timespec ts;
	ts.tv_sec = sec;
	ts.tv_nsec = (long)(decimal * 1000000000);//将小数部分转换为整数
	
	int ret;

	do
	{
		ret = nanosleep(&ts, &ts);
	}while(ret == -1 && errno == EINTR);
	//循环防止休眠被信号所中断
}