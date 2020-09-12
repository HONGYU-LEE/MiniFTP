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
		priv_sock_set_child_context(sess);
		handle_child(sess);
	}
	else
	{
		//nobody进程

		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}