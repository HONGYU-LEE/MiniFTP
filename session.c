#include"session.h"
#include"ftpproto.h"
#include"privparent.h"

void session_start(session_t* sess)
{
	pid_t pid = fork();

	if(pid == - 1)
	{
		ERR_EXIT("fork");
	}

	if(pid == 0)
	{
		//ftp server process
		handle_child(sess);
	}
	else
	{
		//nobody process

		//Change the process from root to nobody
		struct passwd* pw = getpwnam("nobody");
		if(pw == NULL)
		{
			ERR_EXIT("getpwnam");
		}
		if(setegid(pw->pw_gid) < 0)
		{
			ERR_EXIT("setegid");
		}
		if(seteuid(pw->pw_uid) < 0)
		{
			ERR_EXIT("seteuid");
		}
		
		handle_parent(sess);
	}
}