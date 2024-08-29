package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/projectdiscovery/mapcidr"
	"github.com/vishvananda/netlink"
	"github.com/yl2chen/cidranger"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"xdpscan/pkg/pkt"
	"xdpscan/pkg/util"
	"xdpscan/pkg/xdp"
)

type SynScanner struct {
	NumFrames    int
	RateLimit    int
	Hosts        string
	Ports        []int
	xsk          *xdp.Socket
	Iface        string
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	SrcIP        net.IP
	Out          io.Writer
	In           io.Reader
	limiter      *rate.Limiter
	frameLen     uint32
	ShowProgress bool
	SrcPort      int
	ipCount      uint64
	EchoCount    uint64
	pktCount     uint64
	lastPktCount uint64
	Ctx          context.Context
	ipRange      []*net.IPNet
	gen          chan mapcidr.Item
	ranger       cidranger.Ranger
	cancel       context.CancelFunc
	mutex        sync.Mutex
}

func (s *SynScanner) Scan() {

	if len(s.Ports) == 0 {
		log.Println("No ports specified")
		return
	}
	s.limiter = rate.NewLimiter(rate.Limit(s.RateLimit), s.RateLimit)
	s.Ctx, s.cancel = context.WithCancel(s.Ctx)
	s.ranger = cidranger.NewPCTrieRanger()
	link, err := netlink.LinkByName(s.Iface)
	if err != nil {
		panic(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}
	if s.SrcIP == nil {
		for _, iface := range interfaces {
			if iface.Name == s.Iface {

				addrs, err := iface.Addrs()
				if err != nil {
					log.Printf("Error fetching addresses for interface %s: %s", iface.Name, err.Error())
					return
				}
				for i := range addrs {
					if strings.Contains(addrs[i].String(), "/") {
						s.SrcIP = net.ParseIP(strings.Split(addrs[i].String(), "/")[0])
					} else {
						s.SrcIP = net.ParseIP(addrs[i].String())
					}
					break
				}

				break
			}

		}

	}
	if s.SrcMAC == nil {
		s.SrcMAC = link.Attrs().HardwareAddr
	}
	if s.DstMAC == nil {
		table, err := util.GetARPTable()
		if err != nil {
			log.Printf("Get DstMAC Error: %s", err.Error())
			return

		}
		for i := range table {
			if table[i].Device == s.Iface {
				s.DstMAC, _ = net.ParseMAC(table[i].HWAddress)
			}

		}
		if s.DstMAC == nil {
			log.Printf("Get DstMAC Error: %s\n%v\n", "NIC ARP Not found", table)

			return
		}

	}
	log.Printf("link.Attrs().Index: %d", link.Attrs().Index)

	s.xsk, err = xdp.NewSocket(link.Attrs().Index, 0, &xdp.SocketOptions{
		NumFrames:              s.NumFrames,
		FrameSize:              2048,
		FillRingNumDescs:       s.NumFrames / 2,
		CompletionRingNumDescs: s.NumFrames / 2,
		RxRingNumDescs:         0,
		TxRingNumDescs:         s.NumFrames / 2,
	})
	if err != nil {
		panic(err)
	}
	//按行读取
	scanner := bufio.NewScanner(s.In)
	for scanner.Scan() {
		addr := scanner.Text()
		if strings.Contains(addr, "#") {
			continue
		}
		if !strings.Contains(addr, "/") {
			addr = addr + "/32"

		}
		_, cidr, err := net.ParseCIDR(addr)
		if err != nil {
			log.Printf("Error parsing CIDR '%s': %s", addr, err.Error())
			continue
		}
		err = s.ranger.Insert(cidranger.NewBasicRangerEntry(*cidr))
		if err != nil {
			log.Printf("Error parsing CIDR '%s': %s", addr, err.Error())
			continue
		}
		s.ipRange = append(s.ipRange, cidr)
	}
	s.ipCount = mapcidr.TotalIPSInCidrs(s.ipRange) * uint64(len(s.Ports))
	//打乱ip port
	s.gen = mapcidr.ShuffleCidrsWithPortsAndSeed(s.ipRange, s.Ports, time.Now().UnixNano())

	synPkt, err := pkt.GenSynPacket(s.SrcMAC, s.DstMAC, s.SrcIP, s.SrcPort)
	if err != nil {
		log.Fatalf("Error generating syn packet: %s", err)
	}

	if s.ShowProgress {
		go s.PrintStats()
	}

	ipHeader := synPkt[14 : 14+20]
	s.frameLen = uint32(len(synPkt))
	tcpHeader := synPkt[14+20:]

	go s.capture()
	var stop bool
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			if stop {
				time.Sleep(time.Duration(10) * time.Second)
				s.cancel()
				break
			}
			descs := s.xsk.GetDescs(s.xsk.NumFreeTxSlots(), false) //获取描述符
			for i := range descs {
				s.limiter.Wait(s.Ctx)
				ip, ok := <-s.gen
				if !ok {
					stop = true
					break
				}
				pkt.SetDstIPv4(ipHeader, net.ParseIP(ip.IP))
				binary.BigEndian.PutUint16(ipHeader[10:], pkt.Checksum20(ipHeader)) //计算校验和
				pkt.SetDstPort(tcpHeader, uint16(ip.Port))
				//计算校验和
				//生成包含伪头部的tcp数据
				binary.BigEndian.PutUint16(tcpHeader[16:], 0)
				temppkt := append(pkt.PseudoHeader(s.SrcIP, net.ParseIP(ip.IP), uint8(layers.IPProtocolTCP), uint16(len(tcpHeader))), tcpHeader...)
				//设置tcpHeader
				binary.BigEndian.PutUint16(tcpHeader[16:], pkt.TcpChecksum(temppkt))
				copy(s.xsk.GetFrame(descs[i]), synPkt) //复制数据到描述符缓冲区
				descs[i].Len = s.frameLen
				s.pktCount++
			}
			s.xsk.Transmit(descs)      //发送数据
			_, _, err = s.xsk.Poll(-1) //等待数据发送完成
			if err != nil {
				panic(err)
			}
		}

	}

}

func (s *SynScanner) PrintStats() {

	var prevTxPackets, numPkts uint64
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			stats, err := s.xsk.Stats()
			if err != nil {
				panic(err)
			}
			pktCounter := stats.Transmitted

			if prevTxPackets == 0 {
				prevTxPackets = pktCounter
				continue
			}

			numPkts = pktCounter - prevTxPackets
			prevTxPackets = pktCounter

			bps := numPkts * uint64(s.frameLen+42) * 8
			log.Printf("%d pkt/s (%d Mb/s) |  %.2f%% done %d/%d %d\n", numPkts, bps/(1000*1000), (float64(s.pktCount)/float64(s.ipCount))*100, s.pktCount, s.ipCount, s.EchoCount)
			time.Sleep(time.Duration(1) * time.Second)
		}

	}
}
func (s *SynScanner) capture() {

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(s.Iface),
		afpacket.OptFrameSize(2048),
		afpacket.OptBlockSize(2048*128),
		afpacket.OptNumBlocks(256),
	)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			data, _, err := handle.ZeroCopyReadPacketData()
			if err == io.EOF {
				log.Printf(err.Error())
				break
			} else if err != nil {
				log.Printf(err.Error())
				continue
			}

			if len(data) < 14 {
				return
			}

			// Parse Ethernet header
			ethType := binary.BigEndian.Uint16(data[12:14])
			if ethType != 0x0800 { // Only handle IPv4
				return
			}

			// Parse IPv4 header
			if len(data) < 34 {
				return
			}
			ipHeader := data[14:34]
			protocol := ipHeader[9]
			srcIP := net.IP(ipHeader[12:16])
			//dstIP := net.IP(ipHeader[16:20])
			// Check for tcp
			if protocol == 6 {
				// Parse TCP header
				if len(data) < 54 {
					return
				}
				tcpHeader := data[34:54]
				srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])

				flags := tcpHeader[13]
				//判断是否是syn+ack
				if flags == 0x12 {
					//fmt.Printf("TCP: %s:%d -> %s:%d seq=%d ack=%d flags=%d\n", srcIP.String(), srcPort, dstIP.String(), dstPort, seq, ack, flags)
					c, _ := s.ranger.Contains(srcIP)
					if c {

						s.EchoCount++
						//log.Printf("TCP: %s:%d -> %s:%d seq=%d ack=%d\n", srcIP.String(), srcPort, dstIP.String(), dstPort, seq, ack)
						//TODO 结果去重
						fmt.Printf("%s:%d\n", srcIP.String(), srcPort)
						//TODO SEND RST 不然会一直收到重传
					}
				}
			}
		}
	}
}

func (s *SynScanner) xdpCapture() {
	//TODO 虚拟网卡 只能单队列 性能太差
	log.Fatalf("not implemented")
}
