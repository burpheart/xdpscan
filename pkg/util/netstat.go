package util

import (
	"bufio"
	"fmt"
	"github.com/vishvananda/netlink"
	"os"
	"strings"
)

// CounterStats returns the number of transmitted packets per second
func CounterStats(ifaceName string) uint64 {
	// Fetch the link by name
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		fmt.Printf("Error fetching link: %v\n", err)
		return 0
	}

	// Accessing the statistics from the link attributes
	attrs := link.Attrs()
	if attrs == nil || attrs.Statistics == nil {
		fmt.Println("Failed to get link attributes or statistics")
		return 0 // Skip this iteration if stats are unavailable
	}

	// Print the number of packets transmitted per second
	return attrs.Statistics.TxPackets

}

type ARPEntry struct {
	IPAddress string
	HWAddress string
	HWType    string
	Flags     string
	Mask      string
	Device    string
}

func GetARPTable() ([]ARPEntry, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to open ARP table file: %v", err)
	}
	defer file.Close()

	var entries []ARPEntry
	scanner := bufio.NewScanner(file)
	// Skip the header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		entry := ARPEntry{
			IPAddress: fields[0],
			HWAddress: fields[3],
			HWType:    fields[1],
			Flags:     fields[2],
			Mask:      fields[4],
			Device:    fields[5],
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ARP table: %v", err)
	}
	return entries, nil
}
