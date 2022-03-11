package inbound

import (
	"github.com/DeepAQ/mut/global"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"net/url"
	"strconv"
)

func NewTunUdpInbound(u *url.URL) (*tunInbound, error) {
	conn, err := net.ListenPacket("udp", u.Host)
	if err != nil {
		return nil, err
	}

	mtu, _ := strconv.Atoi(u.Query().Get("mtu"))
	if mtu <= 0 {
		mtu = defaultMtu
	}

	return newTunInboundWithEndpoint(u, u.Host, &tunUdpLinkEndpoint{
		conn: conn,
		mtu:  mtu,
	})
}

type tunUdpLinkEndpoint struct {
	conn       net.PacketConn
	clientAddr net.Addr
	mtu        int
	dispatcher stack.NetworkDispatcher
	writeCh    chan *stack.PacketBuffer
	writeErrCh chan tcpip.Error
}

func (ep *tunUdpLinkEndpoint) MTU() uint32 {
	return uint32(ep.mtu)
}

func (ep *tunUdpLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *tunUdpLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *tunUdpLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *tunUdpLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher != nil {
		ep.dispatcher = dispatcher
		ep.writeCh = make(chan *stack.PacketBuffer)
		ep.writeErrCh = make(chan tcpip.Error)
		go ep.readLoop()
		go ep.writeLoop()
	}
}

func (ep *tunUdpLinkEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *tunUdpLinkEndpoint) Wait() {
}

func (ep *tunUdpLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *tunUdpLinkEndpoint) AddHeader(_ *stack.PacketBuffer) {
}

func (ep *tunUdpLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		ep.writeCh <- pkt
		if err := <-ep.writeErrCh; err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (ep *tunUdpLinkEndpoint) readLoop() {
	buf := global.BufPool.Get(ep.mtu)
	defer global.BufPool.Put(buf)

	for {
		n, addr, err := ep.conn.ReadFrom(buf)
		if n <= 0 || err != nil {
			return
		}
		ep.clientAddr = addr

		var protocol tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.NewVectorisedView(n, []buffer.View{buffer.NewViewFromBytes(buf[:n])}),
		})
		ep.dispatcher.DeliverNetworkPacket(protocol, pkt)
		pkt.DecRef()
	}
}

func (ep *tunUdpLinkEndpoint) writeLoop() {
	buf := global.BufPool.Get(ep.mtu)
	defer global.BufPool.Put(buf)

	for {
		pkt, ok := <-ep.writeCh
		if !ok {
			return
		}
		if ep.clientAddr == nil {
			continue
		}

		pktSize := pkt.Size()
		if pktSize <= 0 {
			ep.writeErrCh <- nil
			continue
		}
		if pktSize > ep.mtu {
			ep.writeErrCh <- &tcpip.ErrMessageTooLong{}
			continue
		}

		pktBuf := buf[:0]
		for _, v := range pkt.Views() {
			pktBuf = append(pktBuf, v...)
		}

		if _, err := ep.conn.WriteTo(pktBuf, ep.clientAddr); err != nil {
			ep.writeErrCh <- &tcpip.ErrInvalidEndpointState{}
		} else {
			ep.writeErrCh <- nil
		}
	}
}
