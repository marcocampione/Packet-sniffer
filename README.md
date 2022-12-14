# Packet Sniffer
This is a small project in python that i made to better understand how the network works. The code only work on linux based Os because of this **socket.AF_PACKET**. 
## The Ethernet Frame
In computer networking, an Ethernet frame is a data link layer protocol data unit and uses the underlying Ethernet physical layer transport mechanisms. In other words, a data unit on an Ethernet link transports an Ethernet frame as its payload.
![alt text](https://github.com/marcocampione/Packet-sniffer/blob/master/Img/Ethernet_Frame.png)

## What are the IP packets
In networking, a packet is a small segment of a larger message. Data sent over computer networks, such as the Internet, is divided into packets. These packets are then recombined by the computer or device that receives them.
### IP Header
A packet header is a "label" of sorts, which provides information about the packet’s contents, origin, and destination.
This is an example of a IPv4 header

![alt text](https://github.com/marcocampione/Packet-sniffer/blob/master/Img/IPv4%20header.png)  

The program is coded to unpack only some types of protocol :
- **ICMP**: is a supporting protocol in the Internet protocol suite. It is used by network devices, including routers, to send error messages and operational information indicating success or failure when communicating with another IP address, for example, an error is indicated when a requested service is not available or that a host or router could not be reached.
- **TCP**: is one of the main protocols of the Internet protocol suite. It originated in the initial network implementation in which it complemented the Internet Protocol (IP).TCP provides reliable, ordered, and error-checked delivery of a stream of octets (bytes) between applications running on hosts communicating via an IP network. Major internet applications such as the World Wide Web, email, remote administration, and file transfer rely on TCP, which is part of the Transport Layer of the TCP/IP suite.
![alt text](https://github.com/marcocampione/Packet-sniffer/blob/master/Img/tcp-ip.png)  
- **UDP**: is one of the core communication protocols of the Internet protocol suite used to send messages (transported as datagrams in packets) to other hosts on an Internet Protocol (IP) network.


