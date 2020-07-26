#ifndef _FTPPROTE_H_
#define _FTPPROTE_H_

#include"common.h"
#include"session.h"

void ftp_reply(session_t* sess, int num, char* msg);
void handle_child(session_t* sess);

#endif /* _FTPPROTE_H_ */