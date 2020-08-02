#include"common.h"
#include"session.h"
#include"sysutil.h"

int main(int agrc, char* argv[])
{
	if(getuid() != 0)
	{
		perror("MiniFTP 1.0 : It must be started by root.\n");
		exit(EXIT_FAILURE);
	}
	session_t sess = {  
						/* control connection*/
						-1, -1, "", "", "",
						/* data connection */
						NULL, -1, 
						/* protocol status */
						1,		
					 };

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
			//chlid
			close(lst_sock);
			//子进程创建会话
			sess.ctl_fd = new_sock;
			session_start(&sess);
			exit(EXIT_SUCCESS);
		}
		else
		{
			//parent
			close(new_sock);
		}
	}

	close(lst_sock);
	return 0;
}

