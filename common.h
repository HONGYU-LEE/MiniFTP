#ifndef _COMMON_H_
#define _COMMON_H_

#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<assert.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#define MAX_BUFFER_SIZE 1024

#define ERR_EXIT(msg) \
	do\
	{\
		perror(msg);\
		exit(EXIT_FAILURE);\
	}while (0)

#endif /* __COMMON_H_ */