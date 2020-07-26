#include"sysutil.h"

int tcp_server(const char* ip, unsigned short port)
{
	int lst_fd;
	
	if((lst_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		ERR_EXIT("socket");
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	
	int on = 1;
	if(setsockopt(lst_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
		ERR_EXIT("setsockopt");
	}

	if(bind(lst_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		ERR_EXIT("bind");
	}

	if(listen(lst_fd, SOMAXCONN) < 0)
	{
		ERR_EXIT("listen");
	}

	return lst_fd;
}
