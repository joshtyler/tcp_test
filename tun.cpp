//
// Created by josh on 25/10/2020.
//

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include "tun.h"


Tun::Tun(const char *dev_name)
{
    const char *clonedev = "/dev/net/tun";
    fd = open(clonedev, O_RDWR);
    if(fd < 0)
    {
        throw TunException("Could not open clonedev");
    }

    struct ifreq ifr = {};

    // This is a TUN inteface (IP level not ethernet level)
    // Don't prepend optional protocol header
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    // Create device
    int err = ioctl(fd, TUNSETIFF, reinterpret_cast<void *>(&ifr));

    if(err < 0)
    {
        close(fd);
        throw("Could not create tun device");
    }

}

void Tun::send(std::vector<uint8_t> data)
{
    write(fd, data.data(), data.size());
}

std::vector<uint8_t> Tun::receive(void) {
    std::vector<uint8_t> ret(1500); // TODO. Get MTU size programmatically
    ssize_t n_read;

    do
    {
        n_read = read(fd, ret.data(), ret.size());
    } while (n_read == 0);

    if(n_read < 0)
    {
        throw("Read returned error");
    }

    ret.resize(n_read);

    return ret;
}
