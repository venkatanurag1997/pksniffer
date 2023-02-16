package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type PcapHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type PcapRecordHeader struct {
	TimestampSeconds      uint32
	TimestampMicroseconds uint32
	IncludedLength        uint32
	OriginalLength        uint32
}

var (
	file  = flag.String("r", "", "PCAP file to read")
	host  = flag.String("host", "", "Filter packets to a specific host")
	port  = flag.String("port", "", "Filter packets to a specific port")
	tcp   = flag.Bool("tcp", false, "Filter TCP packets")
	udp   = flag.Bool("udp", false, "Filter UDP packets")
	icmp  = flag.Bool("icmp", false, "Filter ICMP packets")
	net   = flag.String("net", "", "Filter packets to a specific network")
	count = flag.Int("c", -1000, "Limit the number of packets to be analyzed")
)

func getDelay(value byte) string {
	if value == 0 {
		return "normal"
	}
	return "low"
}

func getThroughput(value byte) string {
	if value == 0 {
		return "normal"
	}
	return "high"
}

func getReliability(value byte) string {
	if value == 0 {
		return "normal"
	}
	return "high"
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func main() {

	flag.Parse()

	if *file == "" {
		log.Fatalln("Error: PCAP file not specified")
	}

	// Open the PCAP file
	pcapFile, err := os.Open(*file)
	if err != nil {
		log.Fatalf("Error opening PCAP file: %v", err)
	}
	defer pcapFile.Close()

	var header PcapHeader
	err = binary.Read(
		pcapFile,
		binary.LittleEndian,
		&header,
	)
	if err != nil {
		fmt.Println("Error reading pcap header:", err)
		return
	}

	var recordHeader PcapRecordHeader
	for {
		flag := true
		err = binary.Read(pcapFile, binary.LittleEndian, &recordHeader)
		if err != nil {
			break
		}
		//fmt.Println("  Timestamp:", recordHeader.TimestampSeconds, ".", recordHeader.TimestampMicroseconds)
		//fmt.Println("  Included length:", recordHeader.IncludedLength)
		//fmt.Println("  Original length:", recordHeader.OriginalLength)

		data := make([]byte, recordHeader.IncludedLength)
		_, err = pcapFile.Read(data)
		if err != nil {
			fmt.Println("Error reading record data:", err)
			return
		} else {
			//hexValues := make([]string, len(data))
			//for i, number := range data {
			//	hexValues[i] = strconv.FormatUint(uint64(number), 16)
			//}

			totalPacketLength := len(data)
			hexValues := data

			ethernetDestinationAddress := hexValues[0:6]
			ethernetSourceAddress := hexValues[6:12]

			etherType := uint16(hexValues[12])<<8 + uint16(hexValues[13])
			etherTypes := map[uint16]string{
				0x0800: "IPv4",
				0x0806: "ARP",
				0x86dd: "IPv6",
				0x88cc: "LLDP",
				0x88f7: "PTP",
			}

			nameTag, found := etherTypes[etherType]
			if !found {
				nameTag = "Unknown"
			}

			ipVersionHeaderLength := hexValues[14]
			ipVersion := ipVersionHeaderLength >> 4
			headerLength := (ipVersionHeaderLength & 0x0F) * 4
			tos := hexValues[15] // Split it

			precedence := tos >> 5

			delay := (tos & 0x10) >> 4

			throughput := (tos & 0x8) >> 3

			reliability := (tos & 0x4) >> 2

			totalLengthB := hexValues[16:18]
			var totalLength uint16
			err = binary.Read(bytes.NewReader(totalLengthB), binary.BigEndian, &totalLength)
			if err != nil {
				return
			}
			identificationB := hexValues[18:20]
			var identification uint16
			err = binary.Read(bytes.NewReader(identificationB), binary.BigEndian, &identification)
			if err != nil {
				return
			}

			//flags := hexValues[20:22]
			flags := hexValues[20] >> 5 & 0x7
			dontFragment := hexValues[20]&0x40 == 0x40
			lastFragment := hexValues[20]&0x20 == 0x20
			fragmentOffset := binary.BigEndian.Uint16(hexValues[20:22]) & 0x1fff
			ttl := hexValues[22]
			protocol := hexValues[23]
			//protocol, _ := strconv.ParseInt(protocol_hex, 16, 64)
			headerChecksum := hexValues[24:26]

			ipSourceAddress := hexValues[26:30]
			ipDestinationAddress := hexValues[30:34]

			if *host != "" {
				parts := strings.Split(*host, ".")
				var values []uint8
				for _, part := range parts {
					value, err := strconv.ParseUint(part, 10, 8)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					values = append(values, uint8(value))
				}

				if !(values[0] == ipSourceAddress[0] && values[1] == ipSourceAddress[1] && values[2] == ipSourceAddress[2] && values[3] == ipSourceAddress[3]) &&
					!(values[0] == ipDestinationAddress[0] && values[1] == ipDestinationAddress[1] && values[2] == ipDestinationAddress[2] && values[3] == ipDestinationAddress[3]) {

					fmt.Printf("args %v src %v dest %v", values, ipSourceAddress, ipDestinationAddress)
					flag = false
				}
			}
			if *net != "" {
				parts := strings.Split(*net, ".")
				var values []uint8
				for _, part := range parts {
					value, err := strconv.ParseUint(part, 10, 8)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					values = append(values, uint8(value))
				}

				if !(values[0] == ipSourceAddress[0] && values[1] == ipSourceAddress[1] && values[2] == ipSourceAddress[2] && values[3] == ipSourceAddress[3]) &&
					!(values[0] == ipDestinationAddress[0] && values[1] == ipDestinationAddress[1] && values[2] == ipDestinationAddress[2] && values[3] == ipDestinationAddress[3]) {

					fmt.Printf("args %v src %v dest %v", values, ipSourceAddress, ipDestinationAddress)
					flag = false
				}
			}
			if *count != -1000 && *count < 1 {
				flag = false

			}

			if protocol == 17 {
				if *tcp == true || *icmp == true {
					flag = false
				}
				//fmt.Println(ethernetDestinationAddress, ethernetSourceAddress, etherType, ipVersionHeaderLength, tos, totalLength, identification, flags, ttl, headerChecksum, ipSourceAddress, ipDestinationAddress)

				sourcePortB := hexValues[34:36]
				var sourcePort uint16
				err := binary.Read(bytes.NewReader(sourcePortB), binary.BigEndian, &sourcePort)
				if err != nil {
					return
				}

				destinationPortB := hexValues[36:38]
				var destinationPort uint16
				err = binary.Read(bytes.NewReader(destinationPortB), binary.BigEndian, &destinationPort)
				if err != nil {
					return
				}

				udpLengthB := hexValues[38:40]
				var udpLength uint16
				err = binary.Read(bytes.NewReader(udpLengthB), binary.BigEndian, &udpLength)
				if err != nil {
					return
				}
				checksum := hexValues[40:42]
				//packet_data := hexValues[42:]  This is the actual data in the packet

				if *port != "" {

					value, err := strconv.ParseUint(*port, 10, 16)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					fmt.Printf("Port %t ", value)
					value1 := uint16(value)

					if value1 != sourcePort && value1 != destinationPort {
						flag = false
					}
				}

				if flag {
					fmt.Println("ETHER: ----Ether Header----")
					fmt.Println("ETHER:")
					fmt.Printf("ETHER: Packet size = %d bytes\n", totalPacketLength)
					fmt.Printf("ETHER: Destination = %x:%x:%x:%x:%x:%x\n", ethernetDestinationAddress[0], ethernetDestinationAddress[1],
						ethernetDestinationAddress[2], ethernetDestinationAddress[3], ethernetDestinationAddress[4], ethernetDestinationAddress[5])
					fmt.Printf("ETHER: Source = %x:%x:%x:%x:%x:%x\n", ethernetSourceAddress[0], ethernetSourceAddress[1],
						ethernetSourceAddress[2], ethernetSourceAddress[3], ethernetDestinationAddress[4], ethernetSourceAddress[5])
					//fmt.Printf("ETHER: Ethertype = 0x%x%x\n", etherType[0], etherType[1])
					fmt.Printf("ETHER: EtherType = 0x%x (%s)\n", etherType, nameTag)
					fmt.Println("ETHER:")
					fmt.Println("IP:    ---- IP Header ----")
					fmt.Println("IP:")
					fmt.Printf("IP:    Version      = %d\n", ipVersion)
					fmt.Printf("IP: Header length   = %d bytes\n", headerLength)
					fmt.Printf("IP: Type of service = 0x%02x\n", tos)

					fmt.Printf("IP:     %03d. ....   = %d (precedence)\n", precedence, precedence)
					fmt.Printf("IP:     ...%d ....   = %s delay\n", delay, getDelay(delay))
					fmt.Printf("IP:     .... %d...   = %s throughput\n", throughput, getThroughput(throughput))
					fmt.Printf("IP:     .... .%d..   = %s reliability\n", reliability, getReliability(reliability))

					fmt.Printf("IP: Total length: %d bytes\n", totalLength)
					fmt.Printf("IP: Identification: %d\n", identification)

					fmt.Printf("IP: Flags: 0x%X\n", flags)
					if etherType == 0x0800 {
						fmt.Printf("IP:    .%d.. .... = do not fragment\n", btoi(dontFragment))
						fmt.Printf("IP:    ..%d. .... = last fragment\n", btoi(lastFragment))
						fmt.Printf("IP: Fragment offset = %d bytes\n", fragmentOffset)
					}

					fmt.Printf("IP: Time to live: %d seconds/hops\n", ttl)
					fmt.Printf("IP: Protocol: %d", protocol)
					switch protocol {
					case 6:
						fmt.Println(" (TCP)")
					case 17:
						fmt.Println(" (UDP)")
					case 1:
						fmt.Println(" (ICMP)")
					default:
						fmt.Println(" (Unknown)")
					}
					fmt.Printf("IP: Header checksum: 0x%x\n", headerChecksum)
					fmt.Printf("IP: Source address: %d.%d.%d.%d\n", ipSourceAddress[0], ipSourceAddress[1], ipSourceAddress[2], ipSourceAddress[3])
					fmt.Printf("IP: Destination address: %d.%d.%d.%d\n", ipDestinationAddress[0], ipDestinationAddress[1], ipDestinationAddress[2], ipDestinationAddress[3])

					// Check if there are any options
					if headerLength > 20 {
						// Print the options
						fmt.Printf("IP: Options: %d bytes\n", headerLength-20)
					} else {
						// Print the message that there are no options
						fmt.Println("IP: No options")
					}
					fmt.Println("IP:")
					fmt.Println("UDP:  ----UDP Header---- ")
					fmt.Println("UDP:")
					fmt.Println("UDP: Source Port      = ", sourcePort)
					fmt.Println("UDP: Destination Port = ", destinationPort)
					fmt.Println("UDP: Length           = ", udpLength)
					fmt.Printf("UDP: checksum         = 0x%x\n", checksum)
					fmt.Println("UDP:")
				}

			} else if protocol == 6 {

				if *udp == true || *icmp == true {
					flag = false
				}
				sourcePortB := hexValues[34:36]
				var sourcePort uint16
				err := binary.Read(bytes.NewReader(sourcePortB), binary.BigEndian, &sourcePort)
				if err != nil {
					return
				}

				destinationPortB := hexValues[36:38]
				var destinationPort uint16
				err = binary.Read(bytes.NewReader(destinationPortB), binary.BigEndian, &destinationPort)
				if err != nil {
					return
				}

				sequenceNumberB := hexValues[38:42]
				var sequenceNumber uint32
				err = binary.Read(bytes.NewReader(sequenceNumberB), binary.BigEndian, &sequenceNumber)
				if err != nil {
					return
				}

				ackNumberB := hexValues[42:46]
				var ackNumber uint32
				err = binary.Read(bytes.NewReader(ackNumberB), binary.BigEndian, &ackNumber)
				if err != nil {
					return
				}

				//tcpHeaderLength := hexValues[46]
				//tcpFlags := hexValues[47]

				tcpWindowSizeB := hexValues[48:50]
				var tcpWindowSize uint16
				err = binary.Read(bytes.NewReader(tcpWindowSizeB), binary.BigEndian, &tcpWindowSize)
				if err != nil {
					return
				}

				tcpChecksumB := hexValues[50:52]
				var tcpChecksum uint16
				err = binary.Read(bytes.NewReader(tcpChecksumB), binary.BigEndian, &tcpChecksum)
				if err != nil {
					return
				}

				tcpUrgentPointerB := hexValues[52:54]
				var tcpUrgentPointer uint16
				err = binary.Read(bytes.NewReader(tcpUrgentPointerB), binary.BigEndian, &tcpUrgentPointer)
				if err != nil {
					return
				}
				dataOffset := (hexValues[46] & 0xF0) >> 4

				// Extract the flags
				flags := hexValues[47] & 0x3F
				urgentPointer := "No"
				ack := "No"
				push := "No"
				reset := "No"
				syn := "No"
				fin := "No"

				urgentPointerDisplay := "0"
				ackDisplay := "0"
				pushDisplay := "0"
				resetDisplay := "0"
				synDisplay := "0"
				finDisplay := "0"

				if flags&0x20 == 0x20 {
					urgentPointer = "Yes"
					urgentPointerDisplay = "1"
				}

				if flags&0x10 == 0x10 {
					ack = "Yes"
					ackDisplay = "1"
				}

				if flags&0x8 == 0x8 {
					push = "Yes"
					pushDisplay = "1"
				}

				if flags&0x4 == 0x4 {
					reset = "Yes"
					resetDisplay = "1"
				}

				if flags&0x2 == 0x2 {
					syn = "Yes"
					synDisplay = "1"
				}

				if flags&0x1 == 0x1 {
					fin = "Yes"
					finDisplay = "1"
				}
				optionsStart := (hexValues[46] >> 4) * 4
				optionsEnd := len(hexValues[34:])

				for i := optionsStart; int(i) < optionsEnd; {
					kind := hexValues[i]
					if kind == 0 {
						fmt.Printf("TCP: No Option")
						break
					}
					length := hexValues[i+1]
					fmt.Printf("TCP: Option: Kind=%d, Length=%d, Data=%v\n", kind, length, hexValues[i+2:i+length])
					i += length
				}

				if *port != "" {

					value, err := strconv.ParseUint(*port, 10, 16)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					fmt.Printf("Port %t ", value)
					value1 := uint16(value)

					if value1 != sourcePort && value1 != destinationPort {
						flag = false
					}
				}

				if flag {
					fmt.Println("ETHER: ----Ether Header----")
					fmt.Println("ETHER:")
					fmt.Printf("ETHER: Packet size = %d bytes\n", totalPacketLength)
					fmt.Printf("ETHER: Destination = %x:%x:%x:%x:%x:%x\n", ethernetDestinationAddress[0], ethernetDestinationAddress[1],
						ethernetDestinationAddress[2], ethernetDestinationAddress[3], ethernetDestinationAddress[4], ethernetDestinationAddress[5])
					fmt.Printf("ETHER: Source = %x:%x:%x:%x:%x:%x\n", ethernetSourceAddress[0], ethernetSourceAddress[1],
						ethernetSourceAddress[2], ethernetSourceAddress[3], ethernetDestinationAddress[4], ethernetSourceAddress[5])

					fmt.Printf("ETHER: EtherType = 0x%x (%s)\n", etherType, nameTag)
					fmt.Println("ETHER:")
					fmt.Println("IP:    ---- IP Header ----")
					fmt.Println("IP:")
					fmt.Printf("IP:    Version      = %d\n", ipVersion)
					fmt.Printf("IP: Header length   = %d bytes\n", headerLength)
					fmt.Printf("IP: Type of service = 0x%02x\n", tos)

					fmt.Printf("IP:     %03d. ....   = %d (precedence)\n", precedence, precedence)
					fmt.Printf("IP:     ...%d ....   = %s delay\n", delay, getDelay(delay))
					fmt.Printf("IP:     .... %d...   = %s throughput\n", throughput, getThroughput(throughput))
					fmt.Printf("IP:     .... .%d..   = %s reliability\n", reliability, getReliability(reliability))

					fmt.Printf("IP: Total length: %d bytes\n", totalLength)
					fmt.Printf("IP: Identification: %d\n", identification)

					fmt.Printf("IP: Flags: 0x%X\n", flags)
					if etherType == 0x0800 {
						fmt.Printf("IP:    .%d.. .... = do not fragment\n", btoi(dontFragment))
						fmt.Printf("IP:    ..%d. .... = last fragment\n", btoi(lastFragment))
						fmt.Printf("IP: Fragment offset = %d bytes\n", fragmentOffset)
					}

					fmt.Printf("IP: Time to live: %d seconds/hops\n", ttl)
					fmt.Printf("IP: Protocol: %d", protocol)
					switch protocol {
					case 6:
						fmt.Println(" (TCP)")
					case 17:
						fmt.Println(" (UDP)")
					case 1:
						fmt.Println(" (ICMP)")
					default:
						fmt.Println(" (Unknown)")
					}
					fmt.Printf("IP: Header checksum: 0x%x\n", headerChecksum)
					fmt.Printf("IP: Source address: %d.%d.%d.%d\n", ipSourceAddress[0], ipSourceAddress[1], ipSourceAddress[2], ipSourceAddress[3])
					fmt.Printf("IP: Destination address: %d.%d.%d.%d\n", ipDestinationAddress[0], ipDestinationAddress[1], ipDestinationAddress[2], ipDestinationAddress[3])

					// Check if there are any options
					if headerLength > 20 {
						// Print the options
						fmt.Printf("IP: Options: %d bytes\n", headerLength-20)
					} else {
						// Print the message that there are no options
						fmt.Println("IP: No options")
					}
					fmt.Println("IP:")
					fmt.Println("TCP: ----TCP Header----")
					fmt.Println("TCP:")
					fmt.Printf("TCP: Source port  = %d\n", sourcePort)
					fmt.Printf("TCP: Destination port  = %d\n", destinationPort)
					fmt.Printf("TCP: Sequence number =  %d\n", sequenceNumber)
					fmt.Printf("TCP: Acknowledgement number = %d\n", ackNumber)
					fmt.Println("TCP: Data offset =", dataOffset*4, "bytes")
					fmt.Printf("TCP: Flags = 0x%02x ", flags)
					if flags&0x20 != 0 {
						fmt.Print("(URG)\n")
					}
					if flags&0x10 != 0 {
						fmt.Print("(ACK)\n")
					}
					if flags&0x08 != 0 {
						fmt.Print("(PSH)\n")
					}
					if flags&0x04 != 0 {
						fmt.Print("(RST)\n")
					}
					if flags&0x02 != 0 {
						fmt.Print("(SYN)\n")
					}
					if flags&0x01 != 0 {
						fmt.Print("(FIN)\n")
					}
					fmt.Printf("TCP:    ..%s. .... = Urgent pointer: %s\n", urgentPointerDisplay, urgentPointer)
					fmt.Printf("TCP:    ...%s .... = Acknowledgement: %s\n", ackDisplay, ack)
					fmt.Printf("TCP:    .... %s... = Push: %s\n", pushDisplay, push)
					fmt.Printf("TCP:    .... .%s.. = Reset: %s\n", resetDisplay, reset)
					fmt.Printf("TCP:    .... ..%s. = Syn: %s\n", synDisplay, syn)
					fmt.Printf("TCP:    .... ...%s = Fin: %s\n", finDisplay, fin)
					fmt.Printf("TCP: Window = %d\n", tcpWindowSize)
					fmt.Printf("TCP: Checksum = 0x%x\n", tcpChecksum)
					fmt.Printf("TCP: Urgent pointer = %d\n", tcpUrgentPointer)
					fmt.Printf("TCP: No options\n")
					fmt.Printf("TCP: \n")
				}

			} else if protocol == 1 {

				if *tcp == true || *udp == true {
					flag = false
				}
				icmpType := hexValues[34]
				icmpCode := hexValues[35]
				icmpChecksum := hexValues[36:38]

				if flag {
					fmt.Println("ETHER: ----Ether Header----")
					fmt.Println("ETHER:")
					fmt.Printf("ETHER: Packet size = %d bytes\n", totalPacketLength)
					fmt.Printf("ETHER: Destination = %x:%x:%x:%x:%x:%x\n", ethernetDestinationAddress[0], ethernetDestinationAddress[1],
						ethernetDestinationAddress[2], ethernetDestinationAddress[3], ethernetDestinationAddress[4], ethernetDestinationAddress[5])
					fmt.Printf("ETHER: Source = %x:%x:%x:%x:%x:%x\n", ethernetSourceAddress[0], ethernetSourceAddress[1],
						ethernetSourceAddress[2], ethernetSourceAddress[3], ethernetDestinationAddress[4], ethernetSourceAddress[5])

					fmt.Printf("ETHER: EtherType = 0x%x (%s)\n", etherType, nameTag)
					fmt.Println("ETHER:")
					fmt.Println("IP:    ---- IP Header ----")
					fmt.Println("IP:")
					fmt.Printf("IP:    Version      = %d\n", ipVersion)
					fmt.Printf("IP: Header length   = %d bytes\n", headerLength)
					fmt.Printf("IP: Type of service = 0x%02x\n", tos)

					fmt.Printf("IP:     %03d. ....   = %d (precedence)\n", precedence, precedence)
					fmt.Printf("IP:     ...%d ....   = %s delay\n", delay, getDelay(delay))
					fmt.Printf("IP:     .... %d...   = %s throughput\n", throughput, getThroughput(throughput))
					fmt.Printf("IP:     .... .%d..   = %s reliability\n", reliability, getReliability(reliability))

					fmt.Printf("IP: Total length: %d bytes\n", totalLength)
					fmt.Printf("IP: Identification: %d\n", identification)

					fmt.Printf("IP: Flags: 0x%X\n", flags)
					if etherType == 0x0800 {
						fmt.Printf("IP:    .%d.. .... = do not fragment\n", btoi(dontFragment))
						fmt.Printf("IP:    ..%d. .... = last fragment\n", btoi(lastFragment))
						fmt.Printf("IP: Fragment offset = %d bytes\n", fragmentOffset)
					}

					fmt.Printf("IP: Time to live: %d seconds/hops\n", ttl)
					fmt.Printf("IP: Protocol: %d", protocol)
					switch protocol {
					case 6:
						fmt.Println(" (TCP)")
					case 17:
						fmt.Println(" (UDP)")
					case 1:
						fmt.Println(" (ICMP)")
					default:
						fmt.Println(" (Unknown)")
					}
					fmt.Printf("IP: Header checksum: 0x%x\n", headerChecksum)
					fmt.Printf("IP: Source address: %d.%d.%d.%d\n", ipSourceAddress[0], ipSourceAddress[1], ipSourceAddress[2], ipSourceAddress[3])
					fmt.Printf("IP: Destination address: %d.%d.%d.%d\n", ipDestinationAddress[0], ipDestinationAddress[1], ipDestinationAddress[2], ipDestinationAddress[3])

					if headerLength > 20 {

						fmt.Printf("IP: Options: %d bytes\n", headerLength-20)
					} else {

						fmt.Println("IP: No options")
					}
					fmt.Println("IP:")
					fmt.Println("ICMP: ----ICMP Header----")
					fmt.Println("ICMP:")
					fmt.Printf("ICMP: Type = %d\n", icmpType)
					fmt.Printf("ICMP: Code = %d\n", icmpCode)
					fmt.Printf("ICMP: Checksum = %x%x\n", icmpChecksum[0], icmpChecksum[1])
					fmt.Println("ICMP:")
				}

			}
			if flag {
				if *count != -1000 {
					*count = *count - 1
				}
			}
		}

	}
}
