

# Internet Router #
>CS425: Computer Networking (Project-4)
						
* The router route packets between the Internet and the application servers.
* The router correctly handles ARP requests and replies and traceroutes through it (where it is not the end host) and to it (where it is the end host).
* The router responds correctly to ICMP echo requests and send appropriate type and code when encounters any error.
* The router handles TCP/UDP packets sent to one of its interfaces. In this case the router respond with an ICMP port unreachable.
* The router maintains an ARP cache whose entries are invalidated after a timeout period of 15 seconds.
* The router queues all packets waiting for outstanding ARP replies. If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
* The router enforces guarantee on timeouts--that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router.

### Requirement ##
* This Project runs on top of Mininet which was built at Stanford. which allows to emulate a topology on a single machine. It provides the needed isolation between the emulated nodes so that your router node can process and forward real Ethernet frames between the hosts like a real router.
* Thus it requires a virtual machine with mininet installed in it. Other instructions are provided in `project4.pdf` file.




