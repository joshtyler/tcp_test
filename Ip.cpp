#include "Ip.h"

Ip::Ip(RawSocket *sock)
	:sock(sock)
{
}

void Ip::send(std::vector<uint8_t> data)
{
	std::vector<uint8_t> ip_header;
	ip_header.resize(20); // No options, therefore 20 bytes
	ip_header[0] = (0x4 << 4) | 0x5; // IPv4. No options
	ip_header[1] = 0x0; // No DSCP, no ECN
	uint16_t total_len = ip_header.size() + data.size();
	ip_header[2] = (total_len >> 8) & 0xFF;
	ip_header[3] = (total_len >> 0) & 0xFF;
	ip_header[4] = 0; // No ID
	ip_header[5] = 0;
	ip_header[6] = 0x40; // Don't fragment
	ip_header[7] = 0;
	ip_header[8] = 0xFF; // Max time to live
	ip_header[9] = 0x06; // Protocol - TCP
	ip_header[10] = 0x00; //Checksum will go here
	ip_header[11] = 0x00;
	ip_header[12] = 127; // From localhost
	ip_header[13] = 0;
	ip_header[14] = 0;
	ip_header[15] = 1;
	ip_header[16] = 127; // To localhost
	ip_header[17] = 0;
	ip_header[18] = 0;
	ip_header[19] = 1;

	// Calculate checksum
	// N.B. Assuming even length
	uint16_t csum = 0;
	for(auto i = 0u; i < ip_header.size(); i+=2)
	{
		uint16_t word = (ip_header[i] << 8) | ip_header[i+1];
		uint32_t res = word + csum;
		csum = res & 0xFFFF;
		if(res & 0xFFFF0000)
		{
			csum++;
		}
	}
	csum = ~ csum;
	ip_header[10] = (csum >> 8) & 0xFF;
	ip_header[11] = (csum >> 0) & 0xFF;

	data.insert(data.begin(), ip_header.begin(), ip_header.end());
	sock->send(data);
}

std::vector<uint8_t> Ip::receive(void)
{
	auto vec = sock->receive();
	if(vec.size() > 0)
	{
		uint16_t header_len = (vec[2] >> 8) | vec[3];
		if(vec.size() < header_len)
		{
			throw IpException("Vector isn't long enough to contain promised header length");
			vec.erase(vec.begin(),vec.begin()+header_len);
		}
	}
	return vec;
}
