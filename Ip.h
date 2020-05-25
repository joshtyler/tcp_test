#ifndef IP_H
#define IP_H

#include <stdexcept>

#include "RawSocket.h"

struct IpException : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

class Ip
{
public:
	Ip(RawSocket *sock);

	void send(std::vector<uint8_t> data);
	std::vector<uint8_t> receive(void);

private:
	RawSocket *sock;
};

#endif
