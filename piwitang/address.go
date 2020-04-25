package piwitang

import (
	"fmt"
	"net"
	"os"
	"regexp"
)

func (p *Pinger) addIPAddress(ip net.IP) error {
	//verify if it is IPv4 or IPv6
	if isIPv4(ip.String()) && !p.ModeIPv6 {
		//fmt.Println("This address is IPv4")
		p.hasIPv4 = true
		p.network = "ip4:icmp"

		if p.transport != "tcp" {
			p.network = "udp4"
		}

		res, err := net.ResolveIPAddr("ip", ip.String())
		if err != nil {
			fmt.Fprintf(os.Stdout, "An error occured while resolving IP: %s\nmode: %t", ip.String(), p.ModeIPv6)
			return err
		}
		// TODO
		// At this point we will keep all the addresses for a hostname
		// If one fails, we will ping the 2nd, etc..
		p.Address = append(p.Address, IPaddrInfo{
			Addr:   res,
			isIPv6: false,
		})
		return nil
	} else if isIPv6(ip.String()) && p.ModeIPv6 {
		p.hasIPv6 = true
		p.network = "ip6:ipv6-icmp"
		if p.transport != "tcp" {
			p.network = "udp6"
		}
		res, err := net.ResolveIPAddr("ip6", ip.String())
		if err != nil {
			fmt.Printf("An error occured while resolving IP: %s\n", ip.String())
			return err
		}
		// TODO
		// At this point we will keep all the addresses for a hostname
		// If one fails, we will ping the 2nd, etc..
		p.Address = append(p.Address, IPaddrInfo{
			Addr:   res,
			isIPv6: true,
		})
		return nil

	}
	return nil

}

func (p *Pinger) addHostname(hostname string) error {
	ips, err := net.LookupIP(hostname)
	p.hostname = hostname
	if err != nil {
		fmt.Fprintf(os.Stderr, "ping: %s: Name or service not known\n", hostname)
	}
	for _, ip := range ips {
		err := p.addIPAddress(ip)
		if err != nil {
			//no op
		}
	}
	return nil
}

func (p *Pinger) AddInput(addr string) {
	ipAddr := net.ParseIP(addr)
	if ipAddr != nil {
		p.addIPAddress(ipAddr)
	} else {
		p.addHostname(addr)
	}
}

func isIPv6(addr string) bool {
	re := regexp.MustCompile("([a-f0-9:]+:+)+[a-f0-9]+")
	return re.MatchString(addr)
}

func isIPv4(addr string) bool {
	re := regexp.MustCompile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
	return re.MatchString(addr)
}
