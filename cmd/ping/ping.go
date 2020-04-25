package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/iwita/cloudflare/piwitang"
)

type response struct {
	ip  []*net.IPAddr
	ttr time.Duration
	ttl int
}

func main() {
	var privileged, modeIPv6 bool
	var interval, count, ttl, size, deadline, timeout int

	flag.BoolVar(&privileged, "privileged", false, "for privileged raw ICMP endpoints")
	flag.BoolVar(&modeIPv6, "6", false, "only for ipv6 echo request")
	flag.IntVar(&deadline, "deadline", 100, "set read deadline(ms)")
	flag.IntVar(&interval, "i", 1000, "interval between sent requests (ms)")
	flag.IntVar(&interval, "interval", 1000, "interval between sent requests (ms)")
	flag.IntVar(&timeout, "timeout", 100000, "duration of the command(ms), default: 100s")
	flag.IntVar(&count, "count", -1, "number of requests")
	flag.IntVar(&count, "c", -1, "number of requests")
	flag.IntVar(&ttl, "ttl", 90, "Time to live (or HopTimes for IPv6)")
	flag.IntVar(&size, "size", 32, "size of delivered packerts(b)")

	flag.Parse()

	// Handle empty input
	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	// Create a new pinger
	p := piwitang.NewPinger()

	hostname := flag.Arg(0)

	// Add the user defined config flags
	if !privileged {
		p.SetTransport("udp")
	}
	// Set IPv6 mode if enabled
	p.ModeIPv6 = modeIPv6

	// Set time to Live (Hop times)
	p.TTL = ttl

	// Set packet size
	p.Size = size

	//set read deadline
	p.ReadDeadline = time.Millisecond * time.Duration(deadline)

	// Set Interval
	p.Interval = time.Millisecond * time.Duration(interval)

	// Set total timeout
	p.Timeout = time.Millisecond * time.Duration(timeout)
	// Set number of requests
	// default: -1 --> sends forever
	p.Count = count

	// add the addresses
	p.AddInput(hostname)

	// listen for ctrl-C signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			p.Stop()
		}
	}()

	// Customize message printed on packet receiving
	p.OnRecv = func(pkt *piwitang.Response) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
			pkt.Size, pkt.Addr.String(), pkt.Seq, pkt.Rtt, pkt.Ttl)
	}

	// Customize message for the  time to live exceeded cases
	p.OnTimeExceeded = func(pkt *piwitang.Response) {
		fmt.Printf("From %v icmp_seq=%d Time to live exceeded\n", pkt.Addr, pkt.Seq)
	}

	// Customize message for the statistics printed in the end of the execution
	p.OnFinish = func(stats *piwitang.Stats) {
		fmt.Printf("\n--- %s ping statistics ---\n", hostname)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss, time = %v\n",
			stats.PacketsSent, stats.PacketsReceived, stats.PacketLoss, stats.TotalTime)
		// for Solaris machines
		if runtime.GOOS == "solaris" {
			fmt.Printf("rtt min/avg/max/stddev = %v/%v/%v/%v\n", stats.Rtt.Min, stats.Rtt.Avg, stats.Rtt.Max, stats.Rtt.Stddev)

			// for linix machines
		} else {
			fmt.Printf("rtt min/avg/max/mdev = %v/%v/%v/%v\n", stats.Rtt.Min, stats.Rtt.Avg, stats.Rtt.Max, stats.Rtt.Mdev)
		}

	}
	// Customize message printed in the beginning of the execution
	p.OnStart = func(hostname string, addr []piwitang.IPaddrInfo) {
		if len(addr) == 0 {
			return
		}
		fmt.Printf("PING %s (%s):\n", hostname, addr[0].Addr)
	}

	p.Exec()
}
