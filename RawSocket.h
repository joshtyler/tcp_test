#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

// Send/receive data out over a raw socket

#include <stdexcept>
#include <vector>
#include <net/if.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <netinet/in.h>

struct RawSocketException : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

class RawSocket
{
public:
	RawSocket();
	~RawSocket();

	void send(std::vector<uint8_t> data);

	std::vector<uint8_t> receive(void);

private:
	int rx_sock;
	int tx_sock;
	struct sockaddr_ll sock_addr;
};

#endif
