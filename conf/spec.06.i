host h1 create
iface h1 0 ip 192.168.1.1
iface h1 0 netmask 255.255.255.0
iface h1 0 mac 1:2:3:4:5:6

host h2 create
iface h2 0 ip 192.168.1.2
iface h2 0 netmask 255.255.255.0
iface h2 0 mac a:b:c:d:e:f

host h1 ping 192.168.1.2
#host h1 ping 192.168.1.2

#host h2 ping 192.168.1.1

#host h1 ping 192.168.1.2
#hub uh1 create
#connect uh1 0 h1 0
#connect uh1 1 h2 0

connect h1 0 h2 0
