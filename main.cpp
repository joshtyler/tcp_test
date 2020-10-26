
#include <chrono>
#include <thread>

#include "Ip.h"
#include "Tcp.h"


int main(void)
{
	Tun tun("tun0");
	Ip ip(&tun, {10, 0, 0, 2});
	Tcp tcp(&ip, 9000, true);

	while(true)
	{
		tcp.process();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}
