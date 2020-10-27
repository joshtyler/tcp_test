//
// Created by josh on 27/10/2020.
//

#ifndef TCP_TEST_SERDES_H
#define TCP_TEST_SERDES_H

#include <cstdint>
#include <algorithm>
#include <boost/endian/conversion.hpp>

template <typename T> inline T des_from_be(const uint8_t *dat)
{
    T ret;
    std::copy(dat, dat+sizeof(T), reinterpret_cast<uint8_t*>(&ret));
    return boost::endian::big_to_native(ret);
}

template <typename T> inline void ser_to_be(uint8_t *buf, T dat)
{
    boost::endian::native_to_big_inplace(dat);
    std::copy(reinterpret_cast<uint8_t*>(&dat), reinterpret_cast<uint8_t*>(&dat)+sizeof(T), buf);
}

#endif //TCP_TEST_SERDES_H
