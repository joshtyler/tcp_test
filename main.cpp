
#include "VectorUtility.h"
#include "RawSocket.h"
#include "Ip.h"


int main(void)
{
	RawSocket sock;
	Ip ip(&sock);

	//ip.send({0});
	VectorUtility::print(ip.receive(),true);

	return 0;
}
