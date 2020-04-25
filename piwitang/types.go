package piwitang

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
)

type packet struct {
	addr        net.IP
	payload     []byte
	ttl         int
	numberBytes int
}

type Response struct {
	Ttl  int
	Rtt  time.Duration
	Addr net.IP
	Seq  int
	Size int
}

type context struct {
	stop chan bool
	done chan bool
	err  error
}

type IPaddrInfo struct {
	Addr      *net.IPAddr
	isIPv6    bool
	transport string
	network   string
}

type RTT struct {
	Min, Max, Avg, Mdev, Stddev time.Duration
}

type Stats struct {
	Rtt             RTT
	PacketLoss      float32
	PacketsReceived int
	PacketsSent     int
	TotalTime       time.Duration
}

type Pinger struct {
	hasIPv4   bool
	hasIPv6   bool
	transport string
	network   string
	Address   []IPaddrInfo
	hostname  string

	Size         int
	Interval     time.Duration
	Timeout      time.Duration
	Count        int
	TTL          int
	ReadDeadline time.Duration

	rtts []time.Duration
	conn *icmp.PacketConn

	done chan bool

	ModeIPv6        bool
	sequence        int
	PacketsSent     int
	PacketsReceived int
	id              int
	Source          string

	OnStart        func(string, []IPaddrInfo)
	OnRecv         func(*Response)
	OnTimeExceeded func(*Response)
	OnFinish       func(*Stats)
}
