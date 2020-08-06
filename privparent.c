#include"privparent.h"

static void privop_pasv_get_data_sock(session_t *sess);

static void privop_pasv_active(session_t *sess);

static void privop_pasv_listen(session_t *sess);

static void privop_pasv_accept(session_t *sess);



//nobody进程
void handle_parent(session_t* sess)
{
	char cmd;
	while(1)
	{
		//等待ftp进程消息
		cmd = priv_sock_get_cmd(sess->parent_fd);

		switch(cmd)
		{
			case PRIV_SOCK_GET_DATA_SOCK: 
				privop_pasv_get_data_sock(sess);
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

static void privop_pasv_get_data_sock(session_t *sess)
{

}
static void privop_pasv_active(session_t *sess)
{

}
static void privop_pasv_listen(session_t *sess)
{

}

static void privop_pasv_accept(session_t *sess)
{

}