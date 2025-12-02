#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_user_timeout(sock->sk, 1000);
}
