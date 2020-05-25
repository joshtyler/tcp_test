#include "RawSocket.h"

#include <iostream>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>

RawSocket::RawSocket()
{
	// Open a raw socket
	// SOCK_DGRAM to autofill mac
	// Can't use IPPROTO_RAW because it doesn't support receive (stackoverflow 40795772)
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		throw RawSocketException("Could not open raw socket: "+std::string(std::strerror(errno)));
	}

	int on = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        throw RawSocketException("Could not setsockopt: "+std::string(std::strerror(errno)));
    }

	// Retreive the interaface index for our interface
	unsigned int if_idx = if_nametoindex("lo");
	if(if_idx == 0)
	{
		throw RawSocketException("Could not get interface index for interface");
	}

	/*
	// Construct our socket address structure
	sock_addr.sll_ifindex = if_idx; // Interface index
	sock_addr.sll_halen = ETH_ALEN; // Ethernet address length
	sock_addr.sll_addr[0] = 0xFF; // Destination MAC - broadcast
	sock_addr.sll_addr[1] = 0xFF;
	sock_addr.sll_addr[2] = 0xFF;
	sock_addr.sll_addr[3] = 0xFF;
	sock_addr.sll_addr[4] = 0xFF;
	sock_addr.sll_addr[5] = 0xFF;

	sock_addr.sll_protocol= 0x0008; // Ipv4
	*/


	/*
	struct sockaddr_in sockstr;
	socklen_t socklen;
	sockstr.sin_family = AF_INET;
	sockstr.sin_port = htons(7000);
	sockstr.sin_addr.s_addr = inet_addr("127.0.0.1");
	socklen = (socklen_t) sizeof(sockstr);

	if (bind(sock, (struct sockaddr*) &sockstr, socklen) == -1)
	{
		throw RawSocketException("Could not bind: "+std::string(std::strerror(errno)));
	}
	*/
}

void RawSocket::send(std::vector<uint8_t> data)
{
	int ret = sendto(sock, data.data(), data.size(), 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
	if (ret < 0)
	{
		throw RawSocketException("Sending failed: "+std::string(std::strerror(errno)));
	}
}

std::vector<uint8_t> RawSocket::receive(void)
{
	//sockaddr rx_addr;
	//socklen_t rx_addr_len = sizeof(rx_addr);
	std::vector<uint8_t> ret(9600);
	int received_len = recv(sock, ret.data(), ret.size(), 0);
	ret.resize(received_len);

	/*
	sockaddr_ll *rx_addr_ll = reinterpret_cast<sockaddr_ll *>(&rx_addr);

	if(rx_addr_ll->sll_protocol != 0x0008)
	{
		std::cout << "Dropping packet because it is not ipv4" << std::endl;
		ret.resize(0);
	}
	*/
	return ret;
}
