#include "Pcap.h"

#include <iostream>

Pcap::Pcap()
{
	handle  = pcap_open_live("lo", BUFSIZ, true, 10, errbuf); //10ms timeout
	if(handle == NULL)
	{
		throw PcapException("pcap_open_live returned NULL");
	}
}

Pcap::~Pcap()
{

}

void Pcap::send(std::vector<uint8_t> data)
{
	pcap_inject(handle, data.data(), data.size());
}

std::vector<uint8_t> Pcap::receive(void)
{
	std::vector<uint8_t> ret;
	struct pcap_pkthdr packet_header;
	const u_char *packet = pcap_next(handle, &packet_header);
	if (packet != NULL)
	{
		std::cout << "Packet capture length: " << packet_header.caplen << std::endl;
		std::cout << "Packet total length: " << packet_header.len << std::endl;
		std::copy(packet, packet+packet_header.caplen, std::back_inserter(ret));
	} else {
		std::cout << "No packet received" << std::endl;
	}

	return ret;
}
