#include "Tcp.h"
#include "serdes.h"
#include "VectorUtility.h"

#include <iostream>
#include <cassert>

#include <boost/endian/conversion.hpp>

Tcp::Tcp(Ip *ip, uint16_t local_port, bool server)
	:ip(ip), server(server), state(State::LISTEN)
{
	header.source_port = local_port;
}

void Tcp::setup_reset(void)
{
    std::cout << "Sending reset" << std::endl;
    header.ack=false;
    header.rst=true;
    header.syn=false;
    header.fin=false;
    state = State::LISTEN;
}

void Tcp::process(void)
{
	std::vector<uint8_t> packet;
	do
	{
		packet = ip->receive_tcp();
		auto pkt = deserialise(packet);
		if(pkt.first.dest_port == header.source_port)
        {
			if(state != State::LISTEN && header.dest_port != pkt.first.source_port) {
                setup_reset();
                auto serialised = serialise();
                ip->send_tcp(serialised.first, serialised.second);
            } else if(pkt.first.rst) {
			    state = State::LISTEN;
            } else {
                std::cout << "Got packet for us!" << std::endl;

                switch (state) {
                    case State::LISTEN:
                        if (
                                (pkt.first.ack)
                                || (!pkt.first.syn)
                                || (pkt.first.fin)
                                ) {
                            setup_reset();
                        } else {
                            std::cout << "Got syn" << std::endl;
                            header.dest_port = pkt.first.source_port;
                            header.ack_num = pkt.first.seq_num + 1;
                            header.seq_num = rand() & 0xFFFFFFFF;
                            // Send a syn ack
                            header.ack = true;
                            header.rst = false;
                            header.syn = true;
                            header.fin = false;

                            // TODO change
                            header.window_size = 2;
                            auto serialised = serialise();
                            ip->send_tcp(serialised.first, serialised.second);
                            header.seq_num = header.seq_num+1;
                            state = State::SYN_RCVD;
                        }
                        break;
                    case State::SYN_RCVD:
                        if (
                                (!pkt.first.ack)
                                || (pkt.first.syn)
                                || (pkt.first.fin)
                                || (header.ack_num != pkt.first.seq_num) // They shouldn't try and send data before established
                                ) {
                            setup_reset();
                        } else {
                            std::cout << "Got ack for initial syn ack" << std::endl;
                            state = State::ESTABLISHED;
                        }
                        break;
                    case State::ESTABLISHED:
                        if ( pkt.first.syn)
                        {
                            setup_reset();
                        } else {
                            std::cout << "Got packet in established" << std::endl;

                            bool send = false;
                            header.ack = false;
                            header.rst = false;
                            header.syn = false;

                            if(pkt.second.size())
                            {
                                std::cout << "Got data: " << std::endl;
                                VectorUtility::print(pkt.second);
                                std::cout << '\n';
                                // Blindly ack for now
                                // Also need to add trimming in IP
                                header.ack_num = pkt.first.seq_num + pkt.second.size();
                                header.ack = true;
                                send = true;
                            }


                            header.fin = pkt.first.fin;
                            if(header.fin)
                            {
                                header.ack = true;
                                send = true;
                                state = State::LAST_ACK;
                            }
                            if(send)
                            {
                                auto serialised = serialise();
                                ip->send_tcp(serialised.first, serialised.second);
                            }
                        }
                        break;
                    case State::LAST_ACK:
                        if (
                        (!pkt.first.ack)
                        || (pkt.first.syn)
                        || (pkt.first.fin)
                        || (header.ack_num != pkt.first.seq_num) // They shouldn't try and send data in last ack
                        )
                        {
                            setup_reset();
                        } else {
                            std::cout << "Got last ack" << std::endl;
                            state = State::LISTEN;
                        }
                        break;
                    default:
                        std::cerr << "Unimplemented state" << std::endl;
                        assert(false);
                }
            }
		} else {
			std::cout << "Got packet for someone else (" << pkt.first.dest_port << ")" << std::endl;
		}

	} while(packet.size() > 0);
}

std::pair<Tcp::Header,std::vector<uint8_t>> Tcp::deserialise(std::vector<uint8_t> packet)
{
	Header header;
	header.source_port = des_from_be<uint16_t>(&packet[0]);
	header.dest_port   = des_from_be<uint16_t>(&packet[2]);;
	header.seq_num     = des_from_be<uint32_t>(&packet[4]);;
	header.ack_num     = des_from_be<uint32_t>(&packet[8]);;
	header.ack = packet[13] & 0x10;
	header.rst = packet[13] & 0x04;
	header.syn = packet[13] & 0x02;
	header.fin = packet[13] & 0x01;
	header.window_size  = des_from_be<uint16_t>(&packet[14]);;
	header.checksum     = des_from_be<uint16_t>(&packet[16]);;

	uint8_t data_offset_bytes = ((packet[12] & 0xF0) >> 4)*4;
	packet.erase(packet.begin(),packet.begin()+data_offset_bytes);
	return std::make_pair(header,packet);
}

std::pair<std::vector<uint8_t>, uint16_t> Tcp::serialise(std::vector<uint8_t> data) const
{
	std::vector<uint8_t> ret(20);
    ser_to_be<uint16_t>(&ret[0], header.source_port );
    ser_to_be<uint16_t>(&ret[2], header.dest_port );
    ser_to_be<uint32_t>(&ret[4], header.seq_num );
    ser_to_be<uint32_t>(&ret[8], header.ack_num );
	ret.at(12) = 0x50; // Data offset. Reserved bits. NS=0
    ret[13] = serialise_flags();
    ser_to_be<uint16_t>(&ret[14], header.window_size );
    ser_to_be<uint16_t>(&ret[16], 0 ); // CRC. Will fill in later
    ser_to_be<uint16_t>(&ret[18], 0 ); // Urgent pointer

    // Calcluate the checksum of just the TCP portion of the pseudo header
    // See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
    uint16_t csum = calc_partial_csum(ret);

	// Add on the data
	ret.insert(ret.end(), data.begin(), data.end());

	return {ret, csum};
}
