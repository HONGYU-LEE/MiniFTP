#include"common.h"
#include"session.h"
#include"sysutil.h"
#include"tunable.h"
#include"ftpproto.h"
#include"parseconf.h"
#include"ftpcodes.h"
#include"hash.h"

static unsigned int s_client_count;//当前连接数
static hash_t* s_ip_count_hash;//建立ip与连接数的映射
static hash_t* s_pid_ip_hash;//建立pid与ip的映射

void check_limit(session_t* sess);
unsigned int add_ip_count(void* ip);
void drop_ip_count(void* ip);
void handle_sigchild(int sig);
unsigned int hash_func(unsigned int buckets, void* key);

int main(int agrc, char* argv[])
{
	parseconf_test();
	if(getuid() != 0)
	{
		perror("MiniFTP 1.0 : It must be started by root.\n");
		exit(EXIT_FAILURE);
	}
	session_t sess = {  
						/* 控制连接*/
						-1, -1, "", "", "",
						/* 数据连接 */
						NULL, -1, -1,
						/* 协议状态 */
						1, NULL, 0, 0, 0,
						/* 父子进程通道 */
						-1, -1,
						/* 限速 */
						0, 0, 0, 0
					 };
	//注册进程终止信号SIGCHLD的处理函数
	signal(SIGCHLD, handle_sigchild);
	
	//设置限速
	sess.upload_max_rate = tunable_upload_max_rate;
	sess.download_max_rate = tunable_download_max_rate;
	
	s_ip_count_hash = hash_alloc(MAX_BUCKETS_SIZE, hash_func);//建立ip与连接数的映射
	s_pid_ip_hash = hash_alloc(MAX_BUCKETS_SIZE, hash_func);//建立pid与ip的映射


	int lst_sock = tcp_server(tunable_listen_address, tunable_listen_port); 
	int new_sock;
	struct sockaddr_in addr;
	socklen_t addrlen;
	
	while(1)
	{
		if((new_sock = accept(lst_sock, (struct sockaddr*)&addr, &addrlen)) < 0)
		{
			ERR_EXIT("accept error.");
		}

		//获取当前连接数
		++s_client_count;
		sess.num_clients = s_client_count;
		
		//获取当前ip最大连接数
		unsigned int ip = addr.sin_addr.s_addr;
		sess.num_per_ip = add_ip_count(&ip);

		pid_t pid = fork();
		if(pid == -1)
		{
			--s_client_count;

			ERR_EXIT("fork error.");
		}
		//子进程
		if(pid == 0)
		{
			
			close(lst_sock);
			sess.ctl_fd = new_sock;
			
			//检查当前的连接数
			check_limit(&sess);

			session_start(&sess);
			exit(EXIT_SUCCESS);
		}
		//父进程
		else
		{
			close(new_sock);

			//登记子进程pid对应的ip地址
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid), &ip, sizeof(ip));
		}
	}

	close(lst_sock);
	return 0;
}

void check_limit(session_t* sess)
{
	if(tunable_max_clients != 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}

	if(tunable_max_per_ip != 0 && sess->num_per_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, "There are too many connections from your internet address.");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchild(int sig)
{
	pid_t pid;
	while((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		--s_client_count;
		
		unsigned int* ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));//获取pid对应ip地址
		if(ip == NULL)
		{
			continue;//获取失败，再次获取
		}

		drop_ip_count(ip);//减少该ip地址的连接数
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));//释放该节点

	}
}

unsigned int add_ip_count(void* ip)
{
	unsigned count = 0;
	unsigned int *p_count = hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));//查找该ip的连接数

	//如果找不到，则说明是该ip是第一次连接，创建新节点
	if(p_count == NULL)
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int), &count, sizeof(unsigned int));
	}
	else
	{
		++(*p_count);
		count = *p_count;
	}

	return count;
}

void drop_ip_count(void* ip)
{
	unsigned int* p_count = hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));//查找该ip的连接数
	if(p_count == NULL)
	{
		return;
	}

	//对应ip的连接数-1，如果为0则说明该ip无连接，释放节点
	--(*p_count);
	
	if(*p_count == 0)
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}

//除留余数法
unsigned int hash_func(unsigned int buckets, void* key)
{
	return (*(unsigned int*)key % buckets);
}