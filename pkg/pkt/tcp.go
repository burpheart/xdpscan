package pkt

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
)

//TODO 实现IPV6

func GenSynPacket(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, srcPort int) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// 创建一个新的以太网层
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 创建一个新的TCP层
	ipLayer := &layers.IPv4{
		Version:  4, // IPv4
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    net.IPv4(8, 8, 8, 8),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(11451),
		SYN:     true,
		Seq:     rand.Uint32(),
		Window:  64240,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4}, // 1460 in big endian
			},
			{
				OptionType:   layers.TCPOptionKindNop,
				OptionLength: 1,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08}, // 128 in big endian
			},
			{
				OptionType:   layers.TCPOptionKindNop,
				OptionLength: 1,
			},
			{
				OptionType:   layers.TCPOptionKindNop,
				OptionLength: 1,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	tcpLayer.LayerPayload()
	// 获取序列化后的数据包
	err := gopacket.SerializeLayers(buffer, opts, ethernetLayer, ipLayer, tcpLayer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

//通过固定偏移修改源端口

func SetSrcPort(tcpHeader []byte, SrcPort uint16) {
	binary.BigEndian.PutUint16(tcpHeader[0:2], SrcPort)
}

//通过固定偏移修改目的端口

func SetDstPort(tcpHeader []byte, DstPort uint16) {
	binary.BigEndian.PutUint16(tcpHeader[2:4], DstPort)
}

//通过固定偏移修改序列号

func SetSeq(tcpHeader []byte, Seq uint32) {
	binary.BigEndian.PutUint32(tcpHeader[4:8], Seq)
}

//通过固定偏移修改标志位
//syn = 0x02 ack = 0x10 rst = 0x04 fin = 0x01

func SetFlag(tcpHeader []byte, Flag uint8) {
	tcpHeader[13] = Flag
}

//通过固定偏移修改校验和

func SetChecksum(tcpHeader []byte, Checksum uint16) {
	binary.BigEndian.PutUint16(tcpHeader[16:18], Checksum)
}

// 构造检验和伪首部
// https://tools.ietf.org/html/rfc793

func PseudoHeader(srcIP, dstIP net.IP, protocol uint8, length uint16) []byte {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], length)
	return pseudoHeader
}

// TCP检验和算法

func TcpChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16

	return ^uint16(sum)
}
