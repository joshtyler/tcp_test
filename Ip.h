#ifndef IP_H
#define IP_H

#include <stdexcept>
#include <array>
#include <iostream>

#include "tun.h"
#include "serdes.h"

struct IpException : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

class Ip
{
public:
	Ip(Tun *interface, std::array<uint8_t, 4> src_ip);

	void send_tcp(std::vector<uint8_t> data, uint16_t tcp_partial_csum);
	std::vector<uint8_t> receive_tcp(void);

private:
	Tun *interface;
	std::array<uint8_t ,4> src_ip;
	std::array<uint8_t ,4> dst_ip = {0,0,0,0};
};

inline uint16_t calc_partial_csum(uint16_t data, uint16_t csum=0)
{
    uint32_t new_csum = data+csum;
    new_csum = (new_csum & 0xFFFF) + ((new_csum& 0xFFFF0000)? 1 : 0);
    //std::cout << "Calculating csum. Dat 0x" << std::hex << data << " Old 0x" << csum <<  ". New csum 0x" << new_csum << std::endl;
    return new_csum;
}

inline uint16_t calc_partial_csum(uint32_t data, uint16_t csum=0)
{
    uint16_t partiala = data & 0xFFFF;
    uint16_t partialb = ((data & 0xFFFF0000) >> 16);
    csum = calc_partial_csum(partiala, csum);
    csum = calc_partial_csum(partialb, csum);
    return csum;
}

inline uint16_t calc_partial_csum(const std::vector<uint8_t> &dat)
{
    if(dat.size() % 2 != 0)
    {
        // N.B. Calculation assumes even length for now...
        throw(IpException("Header did not have even length"));
    }
    uint16_t csum = 0;
    for(auto i = 0u; i < dat.size(); i+=2)
    {
        csum = calc_partial_csum(des_from_be<uint16_t>(&dat[i]), csum);
    }
    return csum;
}

#endif
