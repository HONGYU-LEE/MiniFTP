#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"

typedef struct session
{
	/* control connection*/
	uid_t uid;
	int ctl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	/* data connection */
	struct sockaddr_in* port_addr;
	int data_fd;
	int pasv_lst_fd;

	/* protocol status */
	int is_ascii;
	
}session_t;

void session_start(session_t* sess);


#endif /* _SESSION_H_ */