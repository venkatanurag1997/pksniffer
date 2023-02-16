# pksniffer
1) Download latest version of Go from https://golang.org/dl/ according to the system specfications. (Paste in terminal or cmd to check: "go version")
2) "go build main.go " to buid the go file.
EXAMPLES:
go run pktsniffer.go -r example.pcap -c 2
go run pktsniffer.go -r example.pcap -port 80
go run pktsniffer.go -r example.pcap tcp true
