#include <linux/tcp.h>

void foo(struct socket *sock)
{
	sock_set_keepalive(sock->sk);
}
