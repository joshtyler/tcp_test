sudo iptables -t raw -A PREROUTING -p tcp --dport 9000 -j DROP
