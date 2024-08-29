package pkt

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func GenIcmp(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP) ([]byte, error) {
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
	// 创建一个新的ICMPv4层
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}
	ipLayer := &layers.IPv4{
		Version:  4, // IPv4
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    net.IPv4(8, 8, 8, 8), //占位 后续替换
		Protocol: layers.IPProtocolICMPv4,
	}

	// 获取序列化后的数据包
	err := gopacket.SerializeLayers(buffer, opts, ethernetLayer, ipLayer, icmpLayer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
