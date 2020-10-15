cmake_minimum_required(VERSION 3.17)
project(tcp_test)

set(CMAKE_CXX_STANDARD 17)

add_executable(tcp_test
        Ip.cpp
        Ip.h
        main.cpp
        Pcap.cpp
        Pcap.h
        RawSocket.cpp
        RawSocket.h
        Tcp.cpp
        Tcp.h
        VectorUtility.h)

target_link_libraries(tcp_test pcap)