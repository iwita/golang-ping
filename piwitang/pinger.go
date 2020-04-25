package piwitang

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"golang.org/x/net/icmp"
)

var (
	timeInBytes      = 8
	packetHeaderSize = 8
	protocolICMP     = 1
	protocolICMPv6   = 58
)

func NewPinger() *Pinger {
	return &Pinger{
		transport: "tcp",
		Interval:  time.Second * 1,
		Timeout:   time.Second * 1000,
		Source:    "",
		Size:      32,
		ModeIPv6:  false,
		id:        rand.Intn(1<<16 - 1),
		done:      make(chan bool),
		sequence:  1,
	}
}

func (p *Pinger) SetTransport(t string) {
	if t == "udp" || t == "udp4" || t == "udp6" {
		p.transport = t
	}
}

func (p *Pinger) PrintLog() {
	fmt.Printf("Network: %s\nTransport: %s\nIPs:%v\nIPv4: %t\nIPv6: %t\n", p.network, p.transport, p.Address, p.hasIPv4, p.hasIPv6)
}

func (p *Pinger) SetNetwork(network string) {
	if network != "ip4:icmp" && network != "ip6:ipv6-icmp" {
		fmt.Fprintf(os.Stderr, "Network Protocol: %s is not a valid one for this application\nPlease use ICMP network protocol", network)
		os.Exit(1)
	} else {
		p.network = network
	}
}

func (p *Pinger) Exec() {
	p.exec()
}

func (p *Pinger) exec() {

	allBeganAt := time.Now()
	handler := p.OnStart
	if handler != nil {
		handler(p.hostname, p.Address)
	}
	if len(p.Address) == 0 {
		return
	}
	var err error
	p.conn, err = icmp.ListenPacket(p.network, p.Source)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Printf("Error listening to source: %s\n...exiting\n", p.Source)
		close(p.done)
		return
	}
	defer p.conn.Close()
	defer p.finish(allBeganAt)

	if p.ModeIPv6 && p.conn.IPv6PacketConn() != nil {
		p.conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
		p.conn.IPv6PacketConn().SetControlMessage(ipv6.FlagSrc, true)
		p.conn.IPv6PacketConn().SetControlMessage(ipv6.FlagDst, true)
		p.conn.IPv6PacketConn().SetHopLimit(p.TTL)
	} else {
		p.conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
		p.conn.IPv4PacketConn().SetControlMessage(ipv4.FlagSrc, true)
		p.conn.IPv4PacketConn().SetControlMessage(ipv4.FlagDst, true)
		p.conn.IPv4PacketConn().SetTTL(p.TTL)
	}

	var wg sync.WaitGroup
	recv := make(chan *packet, 10)
	defer close(recv)
	wg.Add(1)
	go p.receiveResponse(recv, &wg)

	err = p.sendRequest()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// connection timeout
	timeout := time.NewTicker(p.Timeout)
	defer timeout.Stop()
	// interval between sending
	interval := time.NewTicker(p.Interval)
	defer interval.Stop()

	for {
		select {
		case <-p.done:
			wg.Wait()
			return
		case <-timeout.C:
			close(p.done)
			wg.Wait()
			return
		// time to send a new request
		case <-interval.C:
			// count is set but there are no remaining requests to be sent
			if p.Count > 0 && p.PacketsSent >= p.Count {
				continue
			}
			// send a new request
			err = p.sendRequest()
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		// when receiving a response to the connection (p.conn)
		case res := <-recv:
			err := p.openResponse(res)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		}
		if p.Count > 0 && p.PacketsReceived >= p.Count {
			close(p.done)
			wg.Wait()
			return
		}
	}
}

func (p *Pinger) Statistics() *Stats {
	results := &Stats{
		PacketsReceived: p.PacketsReceived,
		PacketsSent:     p.PacketsSent,
		PacketLoss:      float32((p.PacketsSent-p.PacketsReceived)*100) / float32(p.PacketsSent),
	}

	var sum, sum2 time.Duration

	if len(p.rtts) > 0 {
		results.Rtt.Min = p.rtts[0]
		results.Rtt.Max = p.rtts[0]
	}
	for _, rtt := range p.rtts {
		if rtt > results.Rtt.Max {
			results.Rtt.Max = rtt
		}
		if rtt < results.Rtt.Min {
			results.Rtt.Min = rtt
		}
		sum += time.Microsecond * time.Duration(rtt.Microseconds())
		sum2 += time.Microsecond * time.Duration(rtt.Microseconds()*rtt.Microseconds())
	}
	if len(p.rtts) > 0 {
		results.Rtt.Avg = time.Microsecond * time.Duration(float64(sum.Microseconds())/float64(len(p.rtts)))
		temp := time.Microsecond * time.Duration(float64(sum2.Microseconds())/float64(len(p.rtts)))
		results.Rtt.Mdev = time.Microsecond * time.Duration(math.Sqrt(float64(temp.Microseconds()-results.Rtt.Avg.Microseconds()*results.Rtt.Avg.Microseconds())))
		results.Rtt.Stddev = time.Microsecond * time.Duration(math.Sqrt(float64(temp.Microseconds()-results.Rtt.Avg.Microseconds()*results.Rtt.Avg.Microseconds())*float64(len(p.rtts))/float64(len(p.rtts)-1)))
	}
	return results
}

func (p *Pinger) openResponse(recv *packet) error {
	var res *icmp.Message
	var err error
	var proto int
	if p.conn.IPv4PacketConn() != nil && !p.ModeIPv6 {
		proto = protocolICMP
	} else if p.conn.IPv6PacketConn() != nil && p.ModeIPv6 {
		proto = protocolICMPv6
	}
	if res, err = icmp.ParseMessage(proto, recv.payload); err != nil {
		return fmt.Errorf("error parsing icmp message: %s", err.Error())
	}

	if res.Type == ipv4.ICMPTypeDestinationUnreachable || res.Type == ipv6.ICMPTypeDestinationUnreachable {
		fmt.Println("Destination unreachable")
		return nil

	}

	response := &Response{
		Ttl:  recv.ttl,
		Addr: recv.addr,
		Size: recv.numberBytes,
	}

	switch pkt := res.Body.(type) {
	case *icmp.Echo:
		if p.transport == "tcp" {
			if pkt.ID != p.id {
				fmt.Printf("Wrong id:\nWanted: id=%d\nReceived: id=%d\n", p.id, pkt.ID)
				return nil
			}
		}
		response.Seq = pkt.Seq
		if len(pkt.Data) < timeInBytes+packetHeaderSize {
			return fmt.Errorf("insufficient data reveived for time recalculation")
		} else if len(pkt.Data) < p.Size {
			return fmt.Errorf("data received are not equal to the provided size\nWanted: %d  Received: %d",
				p.Size, len(pkt.Data))
		}

		timeSent := bytesToTime(pkt.Data[:timeInBytes])
		response.Rtt = time.Since(timeSent)
		p.PacketsReceived++
		p.rtts = append(p.rtts, response.Rtt)
		handler := p.OnRecv
		if handler != nil {
			handler(response)
		}

		return nil
	case *icmp.TimeExceeded:
		response.Seq = int(pkt.Data[27])
		handler := p.OnTimeExceeded
		if handler != nil {
			handler(response)
		}
		// TODO count this as an error
		return nil
	default:
	}

	return nil

}

func (p *Pinger) receiveResponse(recv chan<- *packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			return
		default:
			payload := make([]byte, 512)
			err := p.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			if err != nil {
				fmt.Println(err.Error())
			}
			var cm *ipv4.ControlMessage
			var cm6 *ipv6.ControlMessage
			var nb int
			var ttl int
			var destination net.IP
			//var destination
			// _, _, err = p.conn.ReadFrom(payload)
			// fmt.Println(err.Error())

			if p.ModeIPv6 {
				nb, cm6, _, err = p.conn.IPv6PacketConn().ReadFrom(payload)
				if cm6 != nil {
					ttl = cm6.HopLimit
					destination = cm6.Src
				}
			} else {
				nb, cm, _, err = p.conn.IPv4PacketConn().ReadFrom(payload)
				if cm != nil {
					destination = cm.Src
					ttl = cm.TTL
				}
			}
			//fmt.Println(cm.TTL)

			if err != nil {
				//fmt.Println(err.Error())
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
						close(p.done)
						return
					}
				}
				// Error handling
			}
			recv <- &packet{payload: payload, ttl: ttl, numberBytes: nb, addr: destination}
		}
	}
}

func (p *Pinger) sendRequest() error {

	info := p.Address[0]
	var dst net.Addr = info.Addr
	var typ icmp.Type

	// WriteTo needs a *UDPAddr as 2nd arguement
	if p.transport != "tcp" {
		dst = &net.UDPAddr{IP: info.Addr.IP, Zone: info.Addr.Zone}
	}
	if p.conn.IPv4PacketConn() != nil {
		typ = ipv4.ICMPTypeEcho
	} else if p.conn.IPv6PacketConn() != nil {
		typ = ipv6.ICMPTypeEchoRequest
	} else {
		// no op
		// continue
	}

	// The payload may include a timestamp indicating the time of transmission
	// and a sequence number, which are not found in this example.
	// This allows ping to compute the round trip time in a stateless manner
	// without needing to record the time of transmission of each packet.

	// otherwise, I can also use a map: packetID: time

	// We insert the time of packet creation inside the packet payload
	// and then we fill the rest of the payload with dummy data

	t := timeToBytes(time.Now())
	if p.Size-timeInBytes-packetHeaderSize > 0 {
		t = append(t, createByteSlice(p.Size-timeInBytes-packetHeaderSize)...)
	}
	msg := &icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  p.sequence,
			Data: t,
		},
	}
	packet, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("Failed to Marshall the message: %v", msg)
		return err
	}
	for {
		// cm := &ipv4.ControlMessage{
		// 	TTL: p.TTL,
		// }

		if _, err := p.conn.WriteTo(packet, dst); err != nil {
			fmt.Println(err.Error())
			if ne, ok := err.(*net.OpError); ok {
				if ne.Timeout() {
					continue
				} else if !ne.Temporary() {
					fmt.Println("ping: sendto: network is unreachable")
				}
			}

		}
		p.sequence++
		p.PacketsSent++
		break
	}

	return nil
}

func (p *Pinger) Stop() {
	close(p.done)
}

func (p *Pinger) finish(t time.Time) {
	handler := p.OnFinish
	if handler != nil {
		stats := p.Statistics()
		stats.TotalTime = time.Since(t)
		handler(stats)
	}
}
