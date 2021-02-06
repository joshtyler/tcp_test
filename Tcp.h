#ifndef TCP_H
#define TCP_H

#include <utility>

#include "Ip.h"


class Tcp
{

public:
	Tcp(Ip *ip, uint16_t src_port, bool server);

	bool send(std::vector<uint8_t> data);
	std::vector<uint8_t> receive(void);
	void process(void);

    struct Header
    {
        uint16_t source_port=0;
        uint16_t dest_port=0;
        uint32_t seq_num=0;
        uint32_t ack_num=0;
        bool ack=false;
        bool rst=false;
        bool syn=false;
        bool fin=false;
        uint16_t window_size=0;
        uint16_t checksum=0;
    };
private:

	Ip *ip;

	// If true, don't open the conection, just wait
	bool server;

	Header header;

	// Simplified version of diagram at https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.1.0/com.ibm.zos.v2r1.halu101/constatus.htm
	// N.B. for now we don't support closing from the FPGA application, os these states are removed
	enum class State
	{
		LISTEN,
		SYN_RCVD,
		ESTABLISHED,
		LAST_ACK
	};
	State state;


	std::pair<Header,std::vector<uint8_t>> deserialise(std::vector<uint8_t> packet);

	std::pair<std::vector<uint8_t>, uint16_t> serialise(std::vector<uint8_t> data={}) const;

	inline uint8_t serialise_flags() const
    {
        uint8_t flags =0;
        if(header.ack) flags |= 0x10;
        if(header.rst) flags |= 0x04;
        if(header.syn) flags |= 0x02;
        if(header.fin) flags |= 0x01;
        return flags;
    }

    uint16_t calc_partial_checksum() const;

	void setup_reset(void);

};

#endif
