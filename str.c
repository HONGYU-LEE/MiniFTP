#include"str.h"

void str_trim_crlf(char* str)
{
	assert(str);

	char* p = str + (strlen(str) - 1);
	while(*p == '\n' || *p == '\r')
	{
		*(p--) = '\0';
	}
}

void str_split(const char* str, char* cmd, char* arg, char split)
{
	assert(str);

	char* pos = strchr(str, split);

	//only command
	if(pos == NULL)
	{
		strcpy(cmd, str);
	}
	else
	{
		strncpy(cmd, str, pos - str);
		strcpy(arg, pos + 1);
	}
}
