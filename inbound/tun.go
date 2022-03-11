package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	defaultNICID = 1
	defaultMtu   = 1500
)

type tunInbound struct {
	tag   string
	l2ep  stack.LinkEndpoint
	dnsgw string
}

func newTunInboundWithEndpoint(u *url.URL, tag string, l2ep stack.LinkEndpoint) (*tunInbound, error) {
	dnsgw := u.Query().Get("dnsgw")
	if len(dnsgw) > 0 && strings.IndexByte(dnsgw, ':') < 0 {
		dnsgw = dnsgw + ":53"
	}

	return &tunInbound{
		tag:   tag,
		l2ep:  l2ep,
		dnsgw: dnsgw,
	}, nil
}

func (t *tunInbound) Name() string {
	return "tun"
}

func (t *tunInbound) Serve(r router.Router) error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	defer s.Close()

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 100, func(req *tcp.ForwarderRequest) {
		id := req.ID()
		targetAddr := tunAddrToString(id.LocalAddress, id.LocalPort)
		clientAddr := tunAddrToString(id.RemoteAddress, id.RemotePort)
		if len(targetAddr) == 0 || len(clientAddr) == 0 {
			req.Complete(true)
			return
		}

		wq := waiter.Queue{}
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			global.Stderr.Println("[tun] failed to create tcp endpoint for " + clientAddr + "->" + targetAddr + ": " + err.String())
			req.Complete(true)
			return
		}

		conn := gonet.NewTCPConn(&wq, ep)
		req.Complete(false)
		r.HandleTcpStream("tun", conn, clientAddr, targetAddr)
	}).HandlePacket)

	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(id.LocalAddress) {
			return true
		}
		targetAddr := tunAddrToString(id.LocalAddress, id.LocalPort)
		clientAddr := tunAddrToString(id.RemoteAddress, id.RemotePort)
		if len(targetAddr) == 0 || len(clientAddr) == 0 {
			return true
		}

		hdr := header.UDP(pkt.TransportHeader().View())
		data := pkt.Data()
		if int(hdr.Length()) > data.Size()+header.UDPMinimumSize {
			s.Stats().UDP.MalformedPacketsReceived.Increment()
			return true
		}
		if data.Size() > global.UdpMaxLength {
			return true
		}
		s.Stats().UDP.PacketsReceived.Increment()

		isDns := false
		if len(t.dnsgw) > 0 && id.LocalPort == 53 {
			isDns = true
			clientAddr = "dns-" + clientAddr + "-" + targetAddr
			targetAddr = t.dnsgw
		}
		vv := data.ExtractVV()
		r.SendUdpPacket("tun", clientAddr, targetAddr, vv.ToView(), func(remoteAddr net.Addr, data []byte) {
			var replySrcAddr tcpip.Address
			var replySrcPort uint16
			if isDns {
				replySrcAddr = id.LocalAddress
				replySrcPort = id.LocalPort
			} else {
				udpAddr, ok := remoteAddr.(*net.UDPAddr)
				if !ok {
					return
				}
				replySrcAddr = tcpip.Address(udpAddr.IP.To4())
				replySrcPort = uint16(udpAddr.Port)
			}

			route, err := s.FindRoute(defaultNICID, replySrcAddr, id.RemoteAddress, ipv4.ProtocolNumber, false)
			if err != nil {
				global.Stderr.Println("[tun] failed to find udp route for " + id.RemoteAddress.String() + ": " + err.String())
				return
			}
			defer route.Release()

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
				Data:               buffer.NewVectorisedView(len(data), []buffer.View{data}),
			})
			defer pkt.DecRef()
			pkt.TransportProtocolNumber = udp.ProtocolNumber

			hdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
			hdr.SetSourcePort(replySrcPort)
			hdr.SetDestinationPort(id.RemotePort)
			hdr.SetLength(uint16(pkt.Size()))
			hdr.SetChecksum(0)

			if err := route.WritePacket(stack.NetworkHeaderParams{
				Protocol: udp.ProtocolNumber,
				TTL:      route.DefaultTTL(),
			}, pkt); err != nil {
				global.Stderr.Println("[tun] failed to write udp packet: " + err.String())
				route.Stats().UDP.PacketSendErrors.Increment()
				return
			}
			route.Stats().UDP.PacketsSent.Increment()
		})
		return true
	})

	if serr := s.CreateNIC(defaultNICID, t.l2ep); serr != nil {
		return errors.New("failed to create nic: " + serr.String())
	}
	if serr := s.SetPromiscuousMode(defaultNICID, true); serr != nil {
		return errors.New("failed to enable promiscuous mode: " + serr.String())
	}
	if serr := s.SetSpoofing(defaultNICID, true); serr != nil {
		return errors.New("failed to enable address spoofing: " + serr.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNICID},
	})

	global.Stdout.Println("[tun] listening on " + t.tag)
	select {}
}

func tunAddrToString(addr tcpip.Address, port uint16) string {
	if port == 0 {
		return addr.String()
	} else {
		return addr.String() + ":" + strconv.Itoa(int(port))
	}
}
