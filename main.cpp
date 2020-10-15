
#include <chrono>
#include <thread>

#include "VectorUtility.h"
#include "Pcap.h"
#include "Ip.h"
#include "Tcp.h"


int main(void)
{
	Pcap pcap;
	Ip ip(&pcap);
	Tcp tcp(&ip, 9000, true);

	while(true)
	{
		tcp.process();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}
