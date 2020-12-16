# Sniff
Sniffer capture all packets, appeared in your network adapter. 
Also allows you to dump all packets to pcap format.

Unfortunately that sniffer cold be used on linux systems only :(

## Usage
Before usage don't forget to add execution permission to file.

cmod +x ./sniff.py

After that you can use program as in the example:

sudo ./sniff.py [options]

Yes, you have to run program with root privileges, 
because only root able to listen all packets on your network adapter

## Parameters and options
To dump your traffic in file use -d option with file path, where information sould be saved.

## Filters
Filter is very simple and is able to filter only by one argument.

General syntax is __SOMETHING == VALUE__

First kind of filtering packets is by protocol used in it. To filter by proto just use constructions like this:

__proto == IP__

Allowed protocols are: Ethernet, IP, TCP, UDP, ARP. The list of allowed protocols will be extended soon.

Other kind of filtering is by some attributes of protocols. For example:

__TCP.syn == True__

__IP.src == 127.0.0.1__

First part is (protocol of packet).(attribute to be compared), and the second is some Value.

All the attributes of packets you may see here:

###TCP
TCP.src_port \
TCP.dst.port \
TCP.syn (True, False) \
TCP.ack (True, False) \
TCP.push (True, False) \
TCP.rst (True, False) \
TCP.fin (True, False) \
TCP.flags (int, 2, for example is equal to syn) \
TCP.seq_num \
TCP.ack_num \
TCP.data_offset \
TCP.urg_ptr \
TCP.window_size \

###UDP
UDP.src_port \
UDP.dst_port \

###IP
IP.qos \
IP.id \
IP.flags (int value) \
IP.ttl \
IP.proto (by integer value) \
IP.src \
IP.dst

###Ethernet
Ethernet.src_mac \
Ethernet.dst_mac \
Ethernet.typ (type by integer value) \

###ARP
ARP.h_type (hardware type by integer value) \
ARP.p_type (protocol type by integer value) \
ARP.h_len (length of hardware address) \
ARP.p_len (length of protocol address) \
ARP.op (operation by integer value) \
ARP.h_src \
ARP.p_src \
ARP.h_dst \
ARP.p_dst