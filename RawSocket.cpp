#include "RawSocket.h"

#include <iostream>
#include <cerrno>
#include <cstring>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>


RawSocket::RawSocket()
{
	// Open the sockets
	// Can't use IPPROTO_RAW because it doesn't support receive (stackoverflow 40795772)
	rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (rx_sock < 0)
	{
		throw RawSocketException("Could not open socket: "+std::string(std::strerror(errno)));
	}

	struct sockaddr_ll sll;
    struct ifreq ifr; bzero(&sll , sizeof(sll));
    bzero(&ifr , sizeof(ifr));
    strncpy((char *)ifr.ifr_name ,"lo" , IFNAMSIZ);
    //copy device name to ifr
    if((ioctl(rx_sock , SIOCGIFINDEX , &ifr)) == -1)
    {
        perror("Unable to find interface index");
        exit(-1);
    }
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = 0x0008; // Ipv4
    if((bind(rx_sock , (struct sockaddr *)&sll , sizeof(sll))) ==-1)
    {
        perror("bind: ");
        exit(-1);
    }

	// SOCK_DGRAM to autofill mac
	tx_sock = socket(AF_PACKET, SOCK_DGRAM, IPPROTO_RAW);
	if (tx_sock < 0)
	{
		throw RawSocketException("Could not open socket: "+std::string(std::strerror(errno)));
	}

	// Retreive the interaface index for our interface
	unsigned int if_idx = if_nametoindex("lo");
	if(if_idx == 0)
	{
		throw RawSocketException("Could not get interface index for interface");
	}
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
}

RawSocket::~RawSocket()
{
	close(rx_sock);
	close(tx_sock);
}

void RawSocket::send(std::vector<uint8_t> data)
{
	int ret = sendto(tx_sock, data.data(), data.size(), 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
	if (ret < 0)
	{
		throw RawSocketException("Sending failed: "+std::string(std::strerror(errno)));
	}
}

std::vector<uint8_t> RawSocket::receive(void)
{
	std::vector<uint8_t> ret(9600);
	int received_len = recv(rx_sock, ret.data(), ret.size(), 0);
	ret.resize(received_len);
	return ret;
}
