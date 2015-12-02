host h1 create
host h2 create

iface h1 0 ip 192.168.1.1
iface h1 0 netmask 255.255.255.0
iface h1 0 mac a2:b1:c1:1:2:3

iface h2 0 ip 192.168.1.2
iface h2 0 netmask 255.255.255.0
iface h2 0 mac a3:c3:d3:a2:10:20

connect h1 0 h2 0
