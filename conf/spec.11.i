set simtime 10

host h1 create
iface h1 0 ip 192.168.1.1
iface h1 0 netmask 255.255.255.0
iface h1 0 mac 1:2:3:4:5:6

host h2 create
iface h2 0 ip 192.168.1.2
iface h2 0 netmask 255.255.255.0
iface h2 0 mac a:b:c:d:e:f

host h3 create
iface h3 0 ip 192.168.1.5
iface h3 0 netmask 255.255.255.0
iface h3 0 mac d:d:d:e:e:e

host h4 create
iface h4 0 ip 192.168.1.6
iface h4 0 netmask 255.255.255.0
iface h4 0 mac e:f:d:a:b:c

#switch sw1 create
hub sw1 create

connect h1 0 sw1 3
connect h2 0 sw1 1
connect h3 0 sw1 4
connect h4 0 sw1 6

host h1 ping 192.168.1.2
