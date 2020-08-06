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

int tcp_client()
{
	int sock;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		ERR_EXIT("tcp_client error.");
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