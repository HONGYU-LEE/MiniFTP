#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"

typedef struct session
{
	uid_t uid;
	int ctl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
}session_t;

void session_start(session_t* sess);


#endif /* _SESSION_H_ */