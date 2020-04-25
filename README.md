# Custom Ping tool (piwitang)

## Transport Layer Support
- TCP (use --privileged flag)
- UDP

## Internet Layer Support
- ICMP
- ICMPv6

## Getting started
1.Compile the /cmd/ping/ping.go

2.Use the following command in order to enable the default unprivileged mode (UDP):
`
sudo sysctl -w net.ipv4.ping_group_range="0   2147483647"
`

3.Use *sudo* command for privileged mode

### Example:
The following example sends an ICMP echo request:
- every i=10000(ms)
- using IPv6(-6)
- running on privileged mode (using TCP/IP)
- total requests sent c=2

`
sudo ./ping -6 --privileged --ttl=10 -c=2 -i=10000 www.google.com  
`
