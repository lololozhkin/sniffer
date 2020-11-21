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
