//
// Created by josh on 25/10/2020.
//

#include <bits/fcntl-linux.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <fcntl.h>
#include "tun.h"

Tun::Tun(const char *dev_name)
{
    constexpr char *clonedev = "/dev/net/tun";
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
