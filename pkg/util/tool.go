package util

import (
	"strconv"
	"strings"
)

//  string ports  range  to []int  80,443,100-123
//排除 <=0 >=65536
//TODO 去重

func ParsePorts(ports string) []int {
	var portList []int
	portStrList := strings.Split(ports, ",")
	for _, portStr := range portStrList {
		if strings.Contains(portStr, "-") {
			portRange := strings.Split(portStr, "-")
			startPort, err := strconv.Atoi(portRange[0])
			if err != nil {
				continue
			}
			endPort, err := strconv.Atoi(portRange[1])
			if err != nil {
				continue
			}

			for i := startPort; i <= endPort; i++ {
				if i <= 0 || i >= 65536 {
					continue
				}
				portList = append(portList, i)
			}
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			if port <= 0 || port >= 65536 {
				continue
			}
			portList = append(portList, port)
		}
	}
	return portList
}
