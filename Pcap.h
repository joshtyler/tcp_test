#ifndef PCAP_H
#define PCAP_H

// Send/receive data out over a raw socket

#include <stdexcept>
#include <vector>

#include <pcap.h>

struct PcapException : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

class Pcap
{
public:
	Pcap();
	~Pcap();

	void send(std::vector<uint8_t> data);
	std::vector<uint8_t> receive(void);

private:
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
};

#endif
