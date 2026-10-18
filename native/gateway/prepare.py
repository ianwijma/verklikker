"""Apply narrow, checked policy hooks to the pinned upstream checkout."""
from pathlib import Path
import sys
root = Path(sys.argv[1])
def replace(file, old, new):
    p = root / file
    content = p.read_text()
    if content.count(old) != 1:
        raise SystemExit(f"Upstream patch context changed: {file}: {old[:80]}")
    p.write_text(content.replace(old, new))
replace('pkg/services/forwarder/tcp.go', 'net.DialTimeout("tcp", net.JoinHostPort(localAddress.String(), fmt.Sprint(r.ID().LocalPort)), connectTimeout)', 'PolicyDial("tcp", net.JoinHostPort(localAddress.String(), fmt.Sprint(r.ID().LocalPort)))')
replace('pkg/services/forwarder/udp.go', 'net.Dial("udp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort))))', 'PolicyDial("udp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort))))')
(root / 'pkg/services/forwarder/policy.go').write_text('package forwarder\nimport "net"\n// Installed before the network accepts any packets.\nvar PolicyDial func(string,string)(net.Conn,error)\n')
replace('pkg/services/dns/dns.go', 'h.addAnswers(m)', 'PolicyAnswer(m)')
(root / 'pkg/services/dns/policy.go').write_text('package dns\nimport "github.com/miekg/dns"\nvar PolicyAnswer func(*dns.Msg)\n')
replace('pkg/virtualnetwork/services.go', '\t"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"\n', '')
replace('pkg/virtualnetwork/services.go', '\ticmpForwarder := forwarder.ICMP(s, translation, &natLock)\n\ts.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)\n', '\t// ICMP is captured but not forwarded; no unfiltered egress path.\n')
replace('pkg/virtualnetwork/virtualnetwork.go', '"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"', '"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"\n"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"\n"gvisor.dev/gvisor/pkg/tcpip/header"')
replace('pkg/virtualnetwork/virtualnetwork.go', 'ipv4.NewProtocol,', 'ipv4.NewProtocol,\n ipv6.NewProtocol,')
replace('pkg/virtualnetwork/virtualnetwork.go', '\ts.SetSpoofing(1, true)', '''
    if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom16Slice(net.ParseIP("fd00:7665::1").To16()).WithPrefix()}, stack.AddressProperties{}); err != nil { return nil, errors.New(err.String()) }
    s.SetSpoofing(1, true)''')
replace('pkg/virtualnetwork/virtualnetwork.go', 's.SetRouteTable([]tcpip.Route{', 's.SetRouteTable([]tcpip.Route{\n {Destination: header.IPv6EmptySubnet, NIC: 1},')
replace('pkg/virtualnetwork/virtualnetwork.go', 'icmp.NewProtocol4,', 'icmp.NewProtocol4,\n icmp.NewProtocol6,')
replace('pkg/tap/switch.go', 'if dst == header.EthernetBroadcastAddress {', 'if header.IsMulticastEthernetAddress(dst) {')
replace('pkg/tap/switch.go', 'eth.DestinationAddress() == header.EthernetBroadcastAddress {', 'header.IsMulticastEthernetAddress(eth.DestinationAddress()) {')
# An endpoint failure must release the already-authorized upstream connection.
replace('pkg/services/forwarder/tcp.go', 'if tcpErr != nil {', 'if tcpErr != nil {\n outbound.Close()')
