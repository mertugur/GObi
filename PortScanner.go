package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

var hostVal string
var subnetVal string
var portStart int
var portEnd int
var portsToScan string

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func worker(ports, results chan int) {
	for p := range ports {
		address := fmt.Sprintf("%s:%d", hostVal, p)
		conn, err := net.Dial("tcp", address)

		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

func parsePorts() {
	s := strings.Split(portsToScan, "-")
	portStart, _ = strconv.Atoi(s[0])
	portEnd, _ = strconv.Atoi(s[1])
}

func scanPorts() {
	ports := make(chan int, 100)
	results := make(chan int)
	var openports []int

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	go func() {
		for i := portStart; i < portEnd; i++ {
			ports <- i
		}
	}()

	for i := portStart; i < portEnd; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		}
	}

	close(ports)
	close(results)

	sort.Ints(openports)
	if len(openports) > 0 {
		fmt.Println("Found open ports :")

		for _, port := range openports {
			fmt.Printf("\t%d / tcp\n", port)
		}
	}

}

func main() {
	flag.StringVar(&hostVal, "host", "NULL", "DNS or IP of Server")
	flag.StringVar(&subnetVal, "subnet", "NULL", "cidr to scan")
	flag.StringVar(&portsToScan, "portVal", "22-444", "port range start-stop")
	//rangePtr := flag.String("portrange", nil, "port range to scan")
	flag.Parse()
	parsePorts()

	if hostVal != "NULL" {
		fmt.Printf("Scanning : %s ....\n", hostVal)
		scanPorts()
	}

	if subnetVal != "NULL" {
		tmp, _ := Hosts(subnetVal)
		for _, iptscan := range tmp {
			hostVal = iptscan
			fmt.Printf("Scanning : %s ....\n", hostVal)
			scanPorts()
		}

	}

}
