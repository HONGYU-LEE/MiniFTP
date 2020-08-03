#ifndef _SYSUTIL_H_
#define _SYSUTIL_H_

#include"common.h"

int tcp_server(const char* ip, unsigned short port);
int tcp_client();
const char* statbuf_get_perms(const struct stat *sbuf);
const char* statbuf_get_date(const struct stat *sbuf);

#endif /* _SYSUTIL_H_ */