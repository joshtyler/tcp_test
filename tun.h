// Class to interface with a TUN device
// Assumes that the TUN has been previously allocated and made persistent
// (e.g. with iproute2)
// It would be quite simple to make this alloc a new one, but it's easier just to create externally
// See https://backreference.org/2010/03/26/tuntap-interface-tutorial/
// and https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/tuntap.rst?id=HEAD

#ifndef TCP_TEST_TUN_H
#define TCP_TEST_TUN_H

#include <stdexcept>

struct TunException : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class Tun
{
public:
    Tun(const char *dev_name);

private:
    int fd;


};


#endif //TCP_TEST_TUN_H
