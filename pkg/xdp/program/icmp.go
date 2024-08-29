package program

import (
	"log"
	"xdpscan/pkg/xdp"
)

func NewIcmpLog() (*xdp.Program, error) {
	objs := &icmp_logObjects{}
	if err := loadIcmp_logObjects(objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}
	PerfMap := objs.PerfMap
	return &xdp.Program{Program: objs.XdpProg, Queues: PerfMap}, nil

}
