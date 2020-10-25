#include "Ip.h"

#include <iostream>

#include <boost/endian/conversion.hpp>

#include "VectorUtility.h"

Ip::Ip(Pcap *pcap, std::array<4> src_ip)
	:pcap(pcap),
	:src_ip(src_ip)
{
}

void Ip::send_tcp(std::vector<uint8_t> data, uint16_t tcp_partial_csum)
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
	ip_header[12] = src_ip[0]; // From
	ip_header[13] = src_ip[1];
	ip_header[14] = src_ip[2];
	ip_header[15] = src_ip[3];
	ip_header[16] = dst_ip[0]; // To
	ip_header[17] = dst_ip[1];
	ip_header[18] = dst_ip[2];
	ip_header[19] = dst_ip[3];

	// Sort out the TCP pseudo header checksum
    tcp_partial_csum = calc_partial_csum(uint16_t((ip_header[12] << 8) | ip_header[13]), tcp_partial_csum); // Source addr
    tcp_partial_csum = calc_partial_csum(uint16_t((ip_header[14] << 8) | ip_header[15]), tcp_partial_csum);
    tcp_partial_csum = calc_partial_csum(uint16_t((ip_header[16] << 8) | ip_header[17]), tcp_partial_csum); // Dest addr
    tcp_partial_csum = calc_partial_csum(uint16_t((ip_header[18] << 8) | ip_header[19]), tcp_partial_csum);
    tcp_partial_csum = calc_partial_csum(uint16_t(ip_header[0]), tcp_partial_csum); // Zeros + prot
    uint16_t tcp_len = data.size();
    boost::endian::native_to_big_inplace(tcp_len);
    tcp_partial_csum = calc_partial_csum(tcp_len, tcp_partial_csum); // TCP length

    tcp_partial_csum = ~tcp_partial_csum;

    std::cout << "tcp checksum: 0x" << std::hex << tcp_partial_csum << '\n';

    data.at(16) = (tcp_partial_csum >> 8) & 0xFF;
    data.at(17) = (tcp_partial_csum >> 0) & 0xFF;

	// Calculate IP checksum
	// N.B. Assuming even length
	uint16_t csum = 0;
	for(auto i = 0u; i < ip_header.size(); i+=2)
	{
		csum = calc_partial_csum(uint16_t((ip_header[i] << 8) | ip_header[i+1]), csum);
	}
	csum = ~ csum;
	ip_header[10] = (csum >> 8) & 0xFF;
	ip_header[11] = (csum >> 0) & 0xFF;

	data.insert(data.begin(), ip_header.begin(), ip_header.end());

	// Add on an ethernet header
	std::vector<uint8_t> eth_header = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00};
	data.insert(data.begin(), eth_header.begin(), eth_header.end());

	pcap->send(data);
}

std::vector<uint8_t> Ip::receive(void)
{
	std::vector<uint8_t> vec;
	while(true) // Loop until we either have a valid packet, or we timed out
	{
		vec = pcap->receive();
		if(vec.size() > 0)
		{
			// Check if long enough to be an ethernet frame
			if(vec.size() >= 6*2+2)
			{
				//Check if ipv4
				if(vec[12] == 0x08 && vec[13] == 0x00)
				{
					// Erase ethernet header
					vec.erase(vec.begin(),vec.begin()+6*2+2);

					// Check if TCP
					if(vec[9] == 0x06)
					{
						uint16_t header_len = (vec[0] & 0x0F)*4;
						if(vec.size() < header_len)
						{
							throw IpException("Vector isn't long enough to contain promised header length");
						}

                        // Save address so that we know who to send it back to
                        src_ip[0] = vec[12];
                        src_ip[0] = vec[13];
                        src_ip[0] = vec[14];
                        src_ip[0] = vec[15];

						std::cout << "IP Header:";
						VectorUtility::print(vec,true);
						std::cout << std::endl;
						vec.erase(vec.begin(),vec.begin()+header_len);
						std::cout << "TCP Header:";
						VectorUtility::print(vec,true);
						std::cout << std::endl;
						// We have a valid packet
						break;
					}
				}
			}
		} else {
			// Break if we have run out of packets
			break;
		}
	}
	return vec;
}
