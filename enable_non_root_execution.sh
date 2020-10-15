#!/bin/bash

# Enables execution of the binary by non root users who are members of the pcap group
# Argument is path to executable

setcap cap_net_raw,cap_net_admin=eip $1