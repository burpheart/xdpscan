package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"xdpscan/pkg/scanner"
	"xdpscan/pkg/util"
)

var (
	NIC       string
	RateLimit int
	SrcMAC    string
	DstMAC    string
	SrcIP     string
	Input     string
	Output    string
	SrcPort   int
	Debug     bool
	Ports     string
	Mode      string
	XdpRX     bool
	NumFrames int
)

func main() {
	flag.StringVar(&NIC, "i", "eth0", "Network interface to attach to.")
	flag.IntVar(&RateLimit, "t", 1000, "Rate limit in packets per second.")
	flag.StringVar(&Ports, "p", "80,443", "TCP Ports to scan. 80,443,100-123")
	flag.StringVar(&SrcMAC, "srcmac", "", "Source MAC address to use in sent frames.")
	flag.StringVar(&DstMAC, "dstmac", "", "Destination MAC address (Router MAC) to use in sent package.")
	flag.StringVar(&SrcIP, "srcip", "", "Source IP address to use in sent package.")
	flag.StringVar(&Input, "in", "", "Input file containing the list of destination IPs/CIDRs. Or pass it as an argument.")
	flag.StringVar(&Output, "out", "-", "Output file to write the results to. Default is stdout.")
	flag.IntVar(&SrcPort, "srcport", 1234, "TCP Source port.")
	flag.BoolVar(&Debug, "d", false, "Enable debug mode.")
	flag.StringVar(&Mode, "m", "icmp", "Scan mode: icmp or syn")
	flag.BoolVar(&XdpRX, "xr", false, "Use XDP for RX.")
	flag.IntVar(&NumFrames, "fn", 64, "Number of frames to use in the XDP socket.")
	flag.Parse()
	if Debug {
		//pprof 监听
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()

	}
	var input io.Reader
	if Input == "" {
		args := flag.Args()
		if len(args) == 0 {
			flag.PrintDefaults()
			return
		} else {
			input = strings.NewReader(args[0])
		}
	}
	var output io.Writer
	if Output == "-" {
		output = os.Stdout
	} else {
		f, err := os.Create(Output)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		output = f
	}
	//NumFrames 必须大于0 且被2整除 且
	if NumFrames <= 0 || NumFrames%2 != 0 {
		panic("NumFrames must be greater than 0 and divisible by 2")
	}

	switch Mode {

	case "icmp":
		var Scanner = scanner.IcmpScanner{}
		Scanner.Iface = NIC
		Scanner.RateLimit = RateLimit
		Scanner.SrcMAC, _ = net.ParseMAC(SrcMAC)
		Scanner.DstMAC, _ = net.ParseMAC(DstMAC)
		if SrcIP != "" {
			Scanner.SrcIP = net.ParseIP(SrcIP)
		}
		Scanner.Ctx = context.Background()
		Scanner.ShowProgress = true
		Scanner.In = input
		Scanner.Out = output
		Scanner.XDPRx = XdpRX
		Scanner.NumFrames = NumFrames
		Scanner.Scan()
		return
	case "syn":
		var Scanner = scanner.SynScanner{}
		Scanner.Iface = NIC
		Scanner.RateLimit = RateLimit
		Scanner.Ports = util.ParsePorts(Ports)
		Scanner.SrcMAC, _ = net.ParseMAC(SrcMAC)
		Scanner.DstMAC, _ = net.ParseMAC(DstMAC)
		if SrcIP != "" {
			Scanner.SrcIP = net.ParseIP(SrcIP)
		}
		Scanner.Ctx = context.Background()
		Scanner.ShowProgress = true
		Scanner.SrcPort = SrcPort
		Scanner.In = input
		Scanner.Out = output
		Scanner.NumFrames = NumFrames
		Scanner.Scan()
		return
	}

}
