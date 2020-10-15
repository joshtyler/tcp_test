#ifndef IP_H
#define IP_H

#include <stdexcept>

#include "Pcap.h"

struct IpException : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

class Ip
{
public:
	Ip(Pcap *pcap);

	void send(std::vector<uint8_t> data);
	std::vector<uint8_t> receive(void);

private:
	Pcap *pcap;
};

#endif
