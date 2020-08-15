#ifndef _COMMON_H_
#define _COMMON_H_

#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<assert.h>
#include<fcntl.h>
#include<time.h>
#include<errno.h>
#include<signal.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

#include<pwd.h>
#include<crypt.h>
#include<shadow.h>

#include<dirent.h>

#include<sys/stat.h>
#include<sys/time.h>

#include<linux/capability.h>
#include<sys/syscall.h>

#define MAX_BUFFER_SIZE 1024
#define MAX_COMMAND_LINE 1024
#define MAX_SETTING_LINE 1024
#define MAX_HOST_NAME_SIZE 1024
#define MAX_KEY_VALUE_SIZE 128
#define MAX_COMMAND 128
#define MAX_ARG 128

#define ERR_EXIT(msg) \
	do\
	{\
		perror(msg);\
		exit(EXIT_FAILURE);\
	}while (0)

#endif /* __COMMON_H_ */