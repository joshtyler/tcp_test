#include "Tcp.h"

#include <iostream>
#include <cassert>

Tcp::Tcp(Ip *ip, uint16_t local_port, bool server)
	:ip(ip), server(server), state(State::CLOSED)
{
	header.source_port = local_port;
}

// Calcluate the checksum of just the TCP portion of the pseudo header
// See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
static uint16_t calc_partial_checksum(Tcp::Header header)
{
    // N.B. We are sort of duplicating the serialise function
    // TODO Probably needs a refactor
    auto csum = calc_partial_csum(header.source_port);
    csum = calc_partial_csum(header.dest_port,csum);
    csum = calc_partial_csum(header.seq_num,csum);
    csum = calc_partial_csum(header.ack_num,csum);
    csum = calc_partial_csum(uint16_t{0x50},csum);
    uint8_t flags =0;
    if(header.ack) flags |= 0x10;
    if(header.rst) flags |= 0x04;
    if(header.syn) flags |= 0x02;
    if(header.fin) flags |= 0x01;
    csum = calc_partial_csum(uint16_t((uint8_t{0x50} << 8) | flags),csum);
    csum = calc_partial_csum(header.window_size,csum);
    // Urgent pointer will always be zero
    // No options
    return csum;

}

void Tcp::process(void)
{
	std::vector<uint8_t> packet;
	do
	{
		packet = ip->receive();
		auto pkt = deserialise(packet);
		if(pkt.first.dest_port == header.source_port)
		{
			std::cout << "Got packet for us!" << std::endl;
			switch(state)
			{
				case State::CLOSED:
					// For now assert the things we don't handle
					assert(!pkt.first.ack);
					assert(!pkt.first.rst);
					assert(pkt.first.syn);
					assert(!pkt.first.fin);
					if(pkt.first.syn)
					{
						std::cout << "Got syn" << std::endl;
						header.dest_port = pkt.first.source_port;
						header.ack_num = pkt.first.seq_num;
						header.seq_num = rand() & 0xFFFF;
						// Send a syn ack
						header.ack=true;
						header.rst=false;
						header.syn=true;
						header.fin=false;

                        ip->send_tcp(serialise(header), calc_partial_checksum(header));
					}
					break;
				default:
					std::cerr << "Unimplemented state" << std::endl;
					assert(false);
			}

		} else {
			std::cout << "Got packet for someone else (" << pkt.first.dest_port << ")" << std::endl;
		}

	} while(packet.size() > 0);
}

std::pair<Tcp::Header,std::vector<uint8_t>> Tcp::deserialise(std::vector<uint8_t> packet)
{
	Header header;
	header.source_port = packet[1] | (packet[0] << 8);
	header.dest_port   = packet[3] | (packet[2] << 8);
	header.seq_num     = packet[7] | (packet[6] << 8) | (packet[5]  << 16) | (packet[4]  << 24);
	header.ack_num     = packet[11] | (packet[10] << 8) | (packet[9] << 16) | (packet[8] << 24);
	header.ack = packet[13] & 0x10;
	header.rst = packet[13] & 0x04;
	header.syn = packet[13] & 0x02;
	header.fin = packet[13] & 0x01;
	header.window_size  = packet[15] | (packet[14] << 8);
	header.checksum     = packet[17] | (packet[16] << 8);

	uint8_t data_offset_bytes = ((packet[12] & 0xF0) >> 4)*4;
	packet.erase(packet.begin(),packet.begin()+data_offset_bytes);
	return std::make_pair(header,packet);
}

std::vector<uint8_t> Tcp::serialise(Header header, std::vector<uint8_t> data)
{
	std::vector<uint8_t> ret;
	ret.push_back((header.source_port >> 8) & 0xFF);
	ret.push_back((header.source_port >> 0) & 0xFF);
	ret.push_back((header.dest_port >> 8) & 0xFF);
	ret.push_back((header.dest_port >> 0) & 0xFF);
	ret.push_back((header.seq_num >> 24) & 0xFF);
	ret.push_back((header.seq_num >> 16) & 0xFF);
	ret.push_back((header.seq_num >> 8) & 0xFF);
	ret.push_back((header.seq_num >> 0) & 0xFF);
	ret.push_back((header.ack_num >> 24) & 0xFF);
	ret.push_back((header.ack_num >> 16) & 0xFF);
	ret.push_back((header.ack_num >> 8) & 0xFF);
	ret.push_back((header.ack_num >> 0) & 0xFF);
	ret.push_back(0x50);
	uint8_t flags =0;
	if(header.ack) flags |= 0x10;
	if(header.rst) flags |= 0x04;
	if(header.syn) flags |= 0x02;
	if(header.fin) flags |= 0x01;
	ret.push_back(flags);
	ret.push_back((header.window_size >> 8) & 0xFF);
	ret.push_back((header.window_size >> 0) & 0xFF);
	ret.push_back(0x00);
	ret.push_back(0x00);
	ret.push_back(0x00);
	ret.push_back(0x00);

	// Don't bother with checksum for now#

	ret.insert(ret.end(), data.begin(), data.end());

	return ret;
}
