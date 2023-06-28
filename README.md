# Packet Sniffer (WIP)

This project aims to improve an already existing open-source project related to network packet analysis.

## What is a packet sniffer for?
Any conventional network carries data in packets that are manufactured by one device and sent out to one or more devices on the same network. For security reasons or to just be nosy, one might want to analyze the traffic that such a network produces. This means keeping track of the packets that travel across the network by "sniffing" or detecting them and decoding their content.

To understand the code, you might want to develop a basic understanding of [sockets](https://medium.com/swlh/understanding-socket-connections-in-computer-networking-bac304812b5c). The program is made using the Python [Socket API](https://docs.python.org/3/library/socket.html) for Linux. However, since this API can't deal with raw sockets on Windows, we need to use the [Npcap](https://npcap.com/) framework and [Scapy](https://scapy.net/) as an interface.

## Tool features
The current Python implementation captures IPv4 and IPv6 packets and provides the following info:
- Destination and Source MAC address
- Ethernet Protocol 
- TTL (Time-to-Live)
- Header length
- Improved presentation of sniffer results, identifying protocol patterns, for example, instead of displaying “Protocol 6”, displaying “TCP protocol”;
- Identification and treatment for ICMP protocol;
- Improved handling of TCP protocol;
- Identification and treatment for UDP protocol;
- Add an IPV6 packet handling capability;
- Save the output to file or screen to facilitate further analysis;

## To run:

On Linux
> Requirements: Python3
> 
> Run it with root privileges `sudo python3 main.py`

On Windows
> Requirements: Python3, Pip and Npcap
> 
> Create a venv with `python3 -m venv .venv`
> 
> Activate it with `.venv/Scripts/Activate.ps1`
>
> Install Scapy with `python3 -m pip install -r requirements.txt`
> 
> Run it as administrator `python3 main.py`
