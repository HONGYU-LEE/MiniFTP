#include"common.h"
#include"session.h"
#include"sysutil.h"
#include"tunable.h"
#include"ftpproto.h"
#include"parseconf.h"
#include"ftpcodes.h"
#include"hash.h"

static unsigned int s_client_count;//��ǰ������
static hash_t* s_ip_count_hash;//����ip����������ӳ��
static hash_t* s_pid_ip_hash;//����pid��ip��ӳ��

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
						/* ��������*/
						-1, -1, "", "", "",
						/* �������� */
						NULL, -1, -1,
						/* Э��״̬ */
						1, NULL, 0, 0, 0,
						/* ���ӽ���ͨ�� */
						-1, -1,
						/* ���� */
						0, 0, 0, 0
					 };
	//ע�������ֹ�ź�SIGCHLD�Ĵ�����
	signal(SIGCHLD, handle_sigchild);
	
	//��������
	sess.upload_max_rate = tunable_upload_max_rate;
	sess.download_max_rate = tunable_download_max_rate;
	
	s_ip_count_hash = hash_alloc(MAX_BUCKETS_SIZE, hash_func);//����ip����������ӳ��
	s_pid_ip_hash = hash_alloc(MAX_BUCKETS_SIZE, hash_func);//����pid��ip��ӳ��


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

		//��ȡ��ǰ������
		++s_client_count;
		sess.num_clients = s_client_count;
		
		//��ȡ��ǰip���������
		unsigned int ip = addr.sin_addr.s_addr;
		sess.num_per_ip = add_ip_count(&ip);

		pid_t pid = fork();
		if(pid == -1)
		{
			--s_client_count;

			ERR_EXIT("fork error.");
		}
		//�ӽ���
		if(pid == 0)
		{
			
			close(lst_sock);
			sess.ctl_fd = new_sock;
			
			//��鵱ǰ��������
			check_limit(&sess);

			session_start(&sess);
			exit(EXIT_SUCCESS);
		}
		//������
		else
		{
			close(new_sock);

			//�Ǽ��ӽ���pid��Ӧ��ip��ַ
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
		
		unsigned int* ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));//��ȡpid��Ӧip��ַ
		if(ip == NULL)
		{
			continue;//��ȡʧ�ܣ��ٴλ�ȡ
		}

		drop_ip_count(ip);//���ٸ�ip��ַ��������
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));//�ͷŸýڵ�

	}
}

unsigned int add_ip_count(void* ip)
{
	unsigned count = 0;
	unsigned int *p_count = hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));//���Ҹ�ip��������

	//����Ҳ�������˵���Ǹ�ip�ǵ�һ�����ӣ������½ڵ�
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
	unsigned int* p_count = hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));//���Ҹ�ip��������
	if(p_count == NULL)
	{
		return;
	}

	//��Ӧip��������-1�����Ϊ0��˵����ip�����ӣ��ͷŽڵ�
	--(*p_count);
	
	if(*p_count == 0)
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}

//����������
unsigned int hash_func(unsigned int buckets, void* key)
{
	return (*(unsigned int*)key % buckets);
}