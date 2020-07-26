#include"ftpproto.h"

void ftp_reply(session_t* sess, int num, char* msg)
{
	char buf[MAX_BUFF_SIZE] = { 0 };
	sprintf(buf, "%d %s \n\r", num, msg);

	send(sess->ctl_fd, buf, MAX_BUFF_SIZE, 0);
}

void handle_child(session_t* sess)
{
	ftp_reply(sess, 202, "connect");
	while(1)
	{
		//
	}
}
