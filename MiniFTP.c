#include"common.h"
#include"session.h"
#include"sysutil.h"

int main(int agrc, char* argv[])
{
	session_t sess = { -1 };

	int lst_sock = tcp_server("192.168.0.128", 9188); 

	int new_sock;
	struct sockaddr_in addr;
	socklen_t addrlen;
	
	while(1)
	{
		if((new_sock = accept(lst_sock, (struct sockaddr*)&addr, &addrlen)) < 0)
		{
			ERR_EXIT("accept");
		}

		pid_t pid = fork();

		if(pid == -1)
		{
			ERR_EXIT("fork");
		}
		
		if(pid == 0)
		{
			//子进程
			close(lst_sock);
			//子进程创建会话
			sess.ctl_fd = new_sock;
			session_start(&sess);
			exit(EXIT_SUCCESS);
		}
		else
		{
			//父进程
			close(new_sock);
		}
	}

	close(lst_sock);
	return 0;
}

