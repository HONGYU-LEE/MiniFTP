#include"privparent.h"

static void privop_pasv_recv_data_sock(session_t *sess);//��ȡ����ģʽ�µ����������׽���

static void privop_pasv_active(session_t *sess);//�жϱ���ģʽ�Ƿ񱻼���

static void privop_pasv_listen(session_t *sess);//��ȡ����ģʽ�µļ����˿ں�

static void privop_pasv_accept(session_t *sess);//��ȡ����ģʽ�µ����������׽���

int capset(cap_user_header_t hdrp, const cap_user_data_t datap) 
{ 
	return syscall(__NR_capset, hdrp, datap); 
}

static void privilege_promotion()
{
	
	//�����̵�ʵ���û���root��Ϊnobody
	struct passwd* pw = getpwnam("nobody");
	if(pw == NULL)
	{
		ERR_EXIT("getpwnam error.");
	}
	if(setegid(pw->pw_gid) < 0)
	{
		ERR_EXIT("setegid error.");
	}
	if(seteuid(pw->pw_uid) < 0)
	{
		ERR_EXIT("seteuid error.");
	}

	//�����û�Ȩ��,�����ܹ���20�˿�	
	struct __user_cap_header_struct hdrp;
	struct __user_cap_data_struct datap;

	hdrp.version = _LINUX_CAPABILITY_VERSION_1;
	hdrp.pid = 0;

	__u32 mask = 0;
	mask |=  (1 << CAP_NET_BIND_SERVICE); //��ȡ����Ȩ�˿�(����1024)��Ȩ��
	
	datap.effective = mask;
	datap.permitted = mask;
	datap.inheritable = 0; //����Ҫ�̳�

	capset(&hdrp, &datap);
}

//nobody����
void handle_parent(session_t* sess)
{
	//get_privilege();
	privilege_promotion();

	char cmd;
	while(1)
	{
		//�ȴ�ftp������Ϣ
		cmd = priv_sock_recv_cmd(sess->parent_fd);

		switch(cmd)
		{
			case PRIV_SOCK_GET_DATA_SOCK: 
				privop_pasv_recv_data_sock(sess);
				break;

			case PRIV_SOCK_PASV_ACTIVE:
				privop_pasv_active(sess);
				break;
			
			case PRIV_SOCK_PASV_LISTEN:
				privop_pasv_listen(sess);
				break;

			case PRIV_SOCK_PASV_ACCEPT:
				privop_pasv_accept(sess);
				break;
		}
	}
}

static void privop_pasv_recv_data_sock(session_t *sess)
{
	unsigned short port = (unsigned short)priv_sock_recv_int(sess->parent_fd);

	char ip[16] = { 0 };
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	//��20�˿�
	int fd = tcp_client(20);

	if(fd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

static void privop_pasv_active(session_t *sess)
{
	int ret = 1;

	if(sess->pasv_lst_fd != -1)
	{
		ret = 1;
	}
	else
	{
		ret = 0;
	}

	priv_sock_send_int(sess->parent_fd, ret);
}


static void privop_pasv_listen(session_t *sess)
{
	char ip[16] = "192.168.0.128"; //������IP��ַ
	sess->pasv_lst_fd = tcp_server(ip, 0); //�˿ںŸ�0,���Զ�����˿ں�
	
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(struct sockaddr);

	if(getsockname(sess->pasv_lst_fd, (struct sockaddr*)&addr, &socklen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	
	unsigned short port = ntohs(addr.sin_port);
	priv_sock_send_int(sess->parent_fd, (int)port);
}

static void privop_pasv_accept(session_t *sess)
{
	int fd = accept(sess->pasv_lst_fd, 0, 0);
	
	close(sess->pasv_lst_fd);
	sess->pasv_lst_fd = -1;

	if(fd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}
