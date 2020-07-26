#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"

typedef struct session
{
	int ctl_fd;
}session_t;

void session_start(session_t* sess);


#endif /* _SESSION_H_ */