# pksniffer

The project involves developing "pktsniffer," a network packet analyzer tool that reads and summarizes network packets. This tool is designed to function similarly to both tcpdump and Wireshark but operates via a shell command. Unlike tcpdump, pktsniffer does not utilize Boolean expressions for filtering. It primarily processes packets from a file specified with the `-r` flag, rather than directly from a network interface. Once executed, pktsniffer examines the captured packets and sequentially displays their header information. It starts with the Ethernet header fields for each frame and, if an IP datagram is detected within an Ethernet frame, proceeds to outline the fields of the IP header. The program further analyzes and displays the details of TCP, UDP, or ICMP packets that are encapsulated within these IP datagrams.

1) Download latest version of Go from https://golang.org/dl/ according to the system specfications. (Paste in terminal or cmd to check: "go version")
2) "go build main.go " to buid the go file.
EXAMPLES:
go run pktsniffer.go -r example.pcap -c 2
go run pktsniffer.go -r example.pcap -port 80
go run pktsniffer.go -r example.pcap tcp true
