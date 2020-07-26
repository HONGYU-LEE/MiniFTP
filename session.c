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
		//ftp�������
		handle_child(sess);
	}
	else
	{
		//nobody����
		handle_parent(sess);
	}
}