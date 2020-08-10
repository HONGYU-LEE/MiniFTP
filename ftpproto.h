#ifndef _FTPPROTE_H_
#define _FTPPROTE_H_

#include"common.h"
#include"session.h"
#include"ftpcodes.h"
#include"str.h"
#include"sysutil.h"
#include"privsock.h"

void ftp_reply(session_t* sess, int state, char* msg);
void handle_child(session_t* sess);

#endif /* _FTPPROTE_H_ */