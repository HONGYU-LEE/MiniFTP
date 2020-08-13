#include"parseconf.h"
#include"tunable.h"

//建立配置项与变量的映射表

//bool类型
static struct parseconf_bool_setting
{
	const char* p_setting_name;
	int* p_var;
}parseconf_bool_array[] = 
{
	{"pasv_enable", &tunable_pasv_enable},
	{"port_enable", &tunable_port_enable}
};

//uint类型
static struct parseconf_uint_setting
{
	const char* p_setting_name;
	unsigned int* p_var;
}parseconf_uint_array[] = 
{
	{"listen_port", &tunable_listen_port},
	{"max_clients", &tunable_max_clients},
	{"max_per_ip", &tunable_max_per_ip},
	{"accept_timeout", &tunable_accept_timeout},
	{"connect_timeout", &tunable_connect_timeout},
	{"idle_session_timeout", &tunable_idle_session_timeout},
	{"data_connection_timeout", &tunable_data_connection_timeout},
	{"local_umask", &tunable_local_umask},
	{"upload_max_rate", &tunable_upload_max_rate},
	{"download_max_rate", &tunable_download_max_rate}
};

//字符类型
static struct parseconf_str_setting
{
	const char* p_setting_name;
	const char** p_var;
}parseconf_str_array[] = 
{
	{"listen_address", &tunable_listen_address}
};

void parseconf_load_setting(const char *setting)
{
	//分割变量名与值 pasv_enable=1;
	char key[MAX_KEY_VALUE_SIZE] = {0};
	char value[MAX_KEY_VALUE_SIZE] = {0};
	str_split(setting, key, value, '=');

	int list_size = sizeof(parseconf_str_array) / sizeof(struct parseconf_str_setting);
	for(int i = 0; i < list_size; i++)
	{
		if(strcmp(key, parseconf_str_array[i].p_setting_name) == 0)
		{
			const char** p_cur_setting = parseconf_str_array[i].p_var;
			
			//如果之前不为空，直接释放，防止内存泄漏
			if(*p_cur_setting != NULL)
			{
				free((char*)(*p_cur_setting));
			}
			*p_cur_setting = strdup(value);//自动开辟空间的深拷贝
			return;
		}
	}

	list_size = sizeof(parseconf_bool_array) / sizeof(struct parseconf_bool_setting);
	for(int i = 0; i < list_size; i++)
	{
		if(strcmp(key, parseconf_bool_array[i].p_setting_name) == 0)
		{
			str_to_upper(value);
			
			if(strcmp(value, "YES") == 0)
			{
				*parseconf_bool_array[i].p_var = 1;
			}
			else if(strcmp(value, "NO") == 0)
			{
				*parseconf_bool_array[i].p_var = 0;
			}
			else
			{
				printf("%d\n", strlen(value));
				fprintf(stderr, "bad bool value in config file for : %s\n", key);
				exit(EXIT_FAILURE);
			}
			return;
		}
	}

	list_size = sizeof(parseconf_uint_array) / sizeof(struct parseconf_uint_setting);
	for(int i = 0; i < list_size; i++)
	{
		if(strcmp(key, parseconf_uint_array[i].p_setting_name) == 0)
		{
			//0则认为默认
			if(value[0] != '0')
			{
				*parseconf_uint_array[i].p_var = atoi(value);
			}
			return;
		}
	}
}

void parseconf_load_file(const char *path)
{
	FILE* fp = fopen(path, "r");
	if(fp == NULL)
	{
		ERR_EXIT("parseconf_load_file.");
	}

	char setting_line[MAX_SETTING_LINE] = { 0 };
	while(fgets(setting_line, MAX_SETTING_LINE, fp) != NULL)
	{
		if(strlen(setting_line) == 0 || setting_line[0] == '#')
		{
			continue;
		}

		str_trim_crlf(setting_line);
		parseconf_load_setting(setting_line);
		memset(setting_line, 0, MAX_SETTING_LINE);
	}
	
	fclose(fp);
}

void ParseConf_Test()
{
	parseconf_load_file("MiniFTP.conf");

	printf("tunable_pasv_enable = %d\n", tunable_pasv_enable);
	printf("tunable_port_enable = %d\n", tunable_port_enable);
	printf("tunable_listen_port = %d\n", tunable_listen_port);
	printf("tunable_max_clients = %d\n", tunable_max_clients);
	printf("tunable_max_per_ip = %d\n", tunable_max_per_ip);
	printf("tunable_accept_timeout = %d\n", tunable_accept_timeout);
	printf("tunable_connect_timeout = %d\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout = %d\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout = %d\n", tunable_data_connection_timeout);
	printf("tunable_loacl_umask = %d\n", tunable_local_umask);
	printf("tunable_upload_max_rate = %d\n", tunable_upload_max_rate);
	printf("tunable_download_mas_rate = %d\n", tunable_download_max_rate);
	printf("tunable_listen_address = %s\n", tunable_listen_address);
}