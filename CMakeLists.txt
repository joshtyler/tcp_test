cmake_minimum_required(VERSION 3.16)
project(tcp_test)

set(CMAKE_CXX_STANDARD 17)

add_executable(tcp_test
        Ip.cpp
        Ip.h
        main.cpp
        Tcp.cpp
        Tcp.h
        VectorUtility.h tun.cpp tun.h serdes.h)

target_link_libraries(tcp_test pcap)