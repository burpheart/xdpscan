package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket/afpacket"
	"github.com/projectdiscovery/mapcidr"
	"github.com/vishvananda/netlink"
	"github.com/yl2chen/cidranger"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"xdpscan/pkg/pkt"
	"xdpscan/pkg/util"
	_ "xdpscan/pkg/util"
	"xdpscan/pkg/xdp"
	"xdpscan/pkg/xdp/program"
)

type IcmpScanner struct {
	NumFrames    int
	RateLimit    int
	Hosts        string
	xsk          *xdp.Socket
	Iface        string
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	SrcIP        net.IP
	Out          io.Writer
	In           io.Reader
	limiter      *rate.Limiter
	XDPRx        bool
	frameLen     uint32
	ShowProgress bool
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
	ch           chan []byte
	wg           sync.WaitGroup
}

//TODO CIDR去重

func (s *IcmpScanner) Scan() {
	bufferSize := 100000
	s.ch = make(chan []byte, bufferSize)
	//runtime.LockOSThread()
	s.limiter = rate.NewLimiter(rate.Limit(s.RateLimit), s.RateLimit)
	s.Ctx, s.cancel = context.WithCancel(s.Ctx)

	s.ranger = cidranger.NewPCTrieRanger()
	link, err := netlink.LinkByName(s.Iface)
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}
	if s.SrcIP == nil {
		for _, iface := range interfaces {
			log.Printf("iface: %s", iface.Name)
			if iface.Name == s.Iface {

				addrs, err := iface.Addrs()
				if err != nil {
					log.Printf("Error fetching addresses for interface %s: %s", iface.Name, err.Error())
					return
				}
				for i := range addrs {
					if strings.Contains(addrs[i].String(), "/") {
						s.SrcIP = net.ParseIP(strings.Split(addrs[i].String(), "/")[0]).To4()
					} else {
						s.SrcIP = net.ParseIP(addrs[i].String()).To4()
					}
					log.Printf("SrcIP: %s", s.SrcIP)
					break
				}

			}
			break
		}
	}
	if s.SrcMAC == nil {
		s.SrcMAC = link.Attrs().HardwareAddr
		log.Printf("SrcMAC: %s", s.SrcMAC)
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
		log.Printf("DstMAC: %s", s.DstMAC)

	}
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

	if s.XDPRx {

		program, err := program.NewIcmpLog()

		if err != nil {
			fmt.Printf("error: failed to create xdp program: %v\n", err)
			return
		}
		defer program.Close()
		if err := program.Attach(link.Attrs().Index); err != nil {
			fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
			return
		}
		defer program.Detach(link.Attrs().Index)
		go s.xdpCapture(program.Queues)
	} else {
		go s.capture()
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

	s.ipCount = mapcidr.TotalIPSInCidrs(s.ipRange)
	if s.ipCount == 0 {
		log.Printf("No valid IP ranges found")
		return
	}

	//打乱ip
	s.gen = mapcidr.ShuffleCidrsWithSeed(s.ipRange, time.Now().Unix())

	icmpPkt, err := pkt.GenIcmp(s.SrcMAC, s.DstMAC, s.SrcIP)
	if err != nil {
		log.Printf("Error generating ICMP packet: %s", err.Error())
		return
	}
	if s.ShowProgress {
		go s.PrintStats()
	}

	s.frameLen = uint32(len(icmpPkt))
	go s.pkgPud(icmpPkt)
	var stop bool //TODO 手动停止
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
				Pkt, ok := <-s.ch
				if !ok {
					stop = true
					break
				}
				copy(s.xsk.GetFrame(descs[i]), Pkt) //复制数据到描述符缓冲区
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

	s.wg.Wait()

}
func (s *IcmpScanner) pkgPud(icmpPkt []byte) {
	ipHeader := icmpPkt[14 : 14+20]
	for {
		ip, ok := <-s.gen
		if !ok {
			close(s.ch)
			return
		}
		pkt.SetDstIPv4(ipHeader, net.ParseIP(ip.IP))
		binary.BigEndian.PutUint16(ipHeader[10:], pkt.Checksum20(ipHeader)) //计算校验和
		var tempPkt []byte
		tempPkt = make([]byte, len(icmpPkt))
		copy(tempPkt, icmpPkt)
		s.ch <- tempPkt
	}

}

func (s *IcmpScanner) PrintStats() {

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
func (s *IcmpScanner) capture() {
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
			// Check for ICMPv4
			if protocol == 1 {
				c, _ := s.ranger.Contains(srcIP)
				if c {
					s.EchoCount++
					//TODO 结果去重
					fmt.Fprintf(s.Out, "%s\n", srcIP)
				}
			}
		}
	}
}

const logBatchSize = 1000

// TODO 虚拟网卡 只能单队列 同时收发性能太差?
// virtio_net virtio0 eth0: XDP request 2 queues but max is 1. XDP_TX and XDP_REDIRECT will operate in a slower locked tx mode.
func (s *IcmpScanner) xdpCapture(perfMap *ebpf.Map) {
	//runtime.LockOSThread()
	//var data []byte
	// 1024KB
	reader, err := perf.NewReader(perfMap, 1024*1024)
	if err != nil {
		panic(err)
	}
	ipChan := make(chan net.IP, logBatchSize*10)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		batch := make([]net.IP, 0, logBatchSize)
		timer := time.NewTimer(5 * time.Second)
		for {
			select {
			case <-s.Ctx.Done():
				if len(batch) > 0 {
					writeBatchToLog(s.Out, batch)
					batch = batch[:0]
				}
				return
			case <-timer.C:
				if len(batch) > 0 {
					writeBatchToLog(s.Out, batch)
					batch = batch[:0]
				}
			case ip := <-ipChan:
				batch = append(batch, ip)
				// 批量写入日志
				if len(batch) >= logBatchSize {
					writeBatchToLog(s.Out, batch)
					batch = batch[:0]
				}
			}
		}
	}()

	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			record, err := reader.Read()
			if err != nil {
				log.Printf("Error reading from perf event array: %v", err)
				continue
			}
			if len(record.RawSample) >= 4 {
				srcIP := net.IP(record.RawSample[0:4])
				go func(srcIP net.IP) {
					c, _ := s.ranger.Contains(srcIP) // SLOW!
					if c {
						atomic.AddUint64(&s.EchoCount, 1)
						//TODO 结果去重
						ipChan <- srcIP
					}
				}(srcIP)
			}

		}
	}
}

func writeBatchToLog(logFile io.Writer, batch []net.IP) {
	bufferedWriter := bufio.NewWriter(logFile)
	defer bufferedWriter.Flush()

	for _, ip := range batch {
		bufferedWriter.WriteString(ip.String() + "\n")
	}
}
