#include"session.h"
#include"privsock.h"
#include"ftpproto.h"
#include"privparent.h"

void session_start(session_t* sess)
{
	priv_sock_init(sess);

	pid_t pid = fork();
	if(pid == - 1)
	{
		ERR_EXIT("fork error.");
	}

	if(pid == 0)
	{
		//FTP服务进程
		handle_child(sess);
	}
	else
	{
		//nobody进程

		//将进程的实际用户从root改为nobody
		struct passwd* pw = getpwnam("nobody");
		if(pw == NULL)
		{
			ERR_EXIT("getpwnam error.");
		}
		if(setegid(pw->pw_gid) < 0)
		{
			ERR_EXIT("setegid error.");
		}
		if(seteuid(pw->pw_uid) < 0)
		{
			ERR_EXIT("seteuid error.");
		}
		
		handle_parent(sess);
	}
}