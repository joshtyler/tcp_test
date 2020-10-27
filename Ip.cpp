#include "Ip.h"

#include <iostream>

#include <boost/endian/conversion.hpp>

#include "VectorUtility.h"
#include "serdes.h"

Ip::Ip(Tun *interface, std::array<uint8_t,4>  src_ip)
	:interface(interface),
	src_ip(src_ip)
{
}

void Ip::send_tcp(std::vector<uint8_t> data, uint16_t tcp_partial_csum)
{
    // Assmble an IP header
	std::vector<uint8_t> ip_header(20); // No options, therefore 20 bytes
	ip_header[0] = (0x4 << 4) | 0x5; // IPv4. No options
	ip_header[1] = 0x0; // No DSCP, no ECN
    ser_to_be<uint16_t>(&ip_header[2], ip_header.size() + data.size()); // Total len
    ser_to_be<uint16_t>(&ip_header[4], 0); // No ID
    ser_to_be<uint16_t>(&ip_header[6], 0x4000); // Don't fragment
	ip_header[8] = 0xFF; // Max time to live
	ip_header[9] = 0x06; // Protocol - TCP
    ser_to_be<uint16_t>(&ip_header[10], 0); //Checksum will go here
    std::copy(src_ip.begin(), src_ip.end(), &ip_header[12]);
    std::copy(dst_ip.begin(), dst_ip.end(), &ip_header[16]);

    // Calculate checksum and inject
    auto ip_csum = calc_partial_csum(ip_header);
    ip_csum = ~ ip_csum;
    ser_to_be<uint16_t>(&ip_header[10], ip_csum);

	// Calculate the IP pseudo header based on this assembled header, and inject into correct place of TCP header
    auto tcp_csum = tcp_partial_csum;
    tcp_csum = calc_partial_csum(des_from_be<uint16_t>(&ip_header[12]), tcp_csum); // Source addr word 1
    tcp_csum = calc_partial_csum(des_from_be<uint16_t>(&ip_header[14]), tcp_csum); // Source addr word 2
    tcp_csum = calc_partial_csum(des_from_be<uint16_t>(&ip_header[16]), tcp_csum); // Dest addr word 1
    tcp_csum = calc_partial_csum(des_from_be<uint16_t>(&ip_header[18]), tcp_csum); // Dest addr word 2
    tcp_csum = calc_partial_csum(uint16_t(ip_header[9]), tcp_csum); // Zeros + prot
    tcp_csum = calc_partial_csum(uint16_t(data.size()), tcp_csum); // TCP length
    tcp_csum = ~tcp_csum;
    ser_to_be<uint16_t>(&data[16], tcp_csum);

    // Tack the TCP data onto the end of the IP header
	data.insert(data.begin(), ip_header.begin(), ip_header.end());

    interface->send(data);
}

std::vector<uint8_t> Ip::receive_tcp(void)
{
	std::vector<uint8_t> vec;
	while(true) // Loop until we either have a valid packet, or we timed out
	{
		vec = interface->receive();
        // Check long enough for minimum IP header
        // And protocol is TCP
        // And it is destined for us
		if
		(
            vec.size() >= 20
            && vec[9] == 0x06
            && vec[16] == src_ip[0] && vec[17] == src_ip[1] && vec[18] == src_ip[2] && vec[19] == src_ip[3]
		)
		{
            uint16_t header_len = (vec[0] & 0x0F) * 4;
            if (vec.size() < header_len) {
                throw IpException("Vector isn't long enough to contain promised header length");
            }

            // Save address so that we know who to send it back to
            std::copy(&vec[12], &vec[12]+dst_ip.size(),dst_ip.begin());

            // Erase IP header
            vec.erase(vec.begin(), vec.begin() + header_len);
            break;
		}
	}
	return vec;
}
