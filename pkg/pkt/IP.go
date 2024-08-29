package pkt

import (
	"encoding/binary"
	"net"
)

func SetDstIPv4(ipHeader []byte, DstIP net.IP) {
	copy(ipHeader[16:16+4], DstIP.To4())
	binary.BigEndian.PutUint16(ipHeader[10:], Checksum20(ipHeader))
}

// 用于计算20bytes长度的IP首部校验和

func Checksum20(data []byte) uint16 {
	var sum uint32

	sum += uint32(data[0])<<8 | uint32(data[1])
	sum += uint32(data[2])<<8 | uint32(data[3])
	sum += uint32(data[4])<<8 | uint32(data[5])
	sum += uint32(data[6])<<8 | uint32(data[7])
	sum += uint32(data[8])<<8 | uint32(data[9])
	//省略了data[10]和data[11]
	sum += uint32(data[12])<<8 | uint32(data[13])
	sum += uint32(data[14])<<8 | uint32(data[15])
	sum += uint32(data[16])<<8 | uint32(data[17])
	sum += uint32(data[18])<<8 | uint32(data[19])

	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16

	return ^uint16(sum)
}
