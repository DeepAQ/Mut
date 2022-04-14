//go:build darwin

package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/global"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	errIncorrectFormat = errors.New("tun device name must start with 'utun'")
	errIncorrectName   = errors.New("incorrect tun device name")
)

func newTunInboundWithDevice(u *url.URL) (*tunInbound, error) {
	if !strings.HasPrefix(u.Host, "utun") {
		return nil, errIncorrectFormat
	}

	id, err := strconv.Atoi(u.Host[4:])
	if err != nil {
		return nil, errIncorrectName
	}

	fd, err := openTunDevice(id)
	if err != nil {
		return nil, errors.New("failed to open tun device " + u.Host + ": " + err.Error())
	}

	return newTunInboundWithFD(u, fd, u.Host)
}

func newTunInboundWithFD(u *url.URL, fd int, tag string) (*tunInbound, error) {
	mtu, _ := strconv.Atoi(u.Query().Get("mtu"))
	if mtu <= 0 {
		mtu = defaultMtu
	}

	return newTunInboundWithEndpoint(u, tag, &tunLinkEndpoint{
		tun: os.NewFile(uintptr(fd), "tun"),
		mtu: mtu,
	})
}

func openTunDevice(id int) (int, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return -1, err
	}

	ctlInfo := unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ctlInfo); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(id) + 1,
	}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

type tunLinkEndpoint struct {
	tun        io.ReadWriteCloser
	mtu        int
	dispatcher stack.NetworkDispatcher
	writeCh    chan *stack.PacketBuffer
	writeErrCh chan tcpip.Error
}

func (ep *tunLinkEndpoint) MTU() uint32 {
	return uint32(ep.mtu)
}

func (ep *tunLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *tunLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *tunLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *tunLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher != nil {
		ep.dispatcher = dispatcher
		ep.writeCh = make(chan *stack.PacketBuffer)
		ep.writeErrCh = make(chan tcpip.Error)
		go ep.readLoop()
		go ep.writeLoop()
	}
}

func (ep *tunLinkEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *tunLinkEndpoint) Wait() {
}

func (ep *tunLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *tunLinkEndpoint) AddHeader(_ *stack.PacketBuffer) {
}

func (ep *tunLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
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

func (ep *tunLinkEndpoint) readLoop() {
	buf := global.BufPool.Get(ep.mtu + 4)
	defer global.BufPool.Put(buf)

	for {
		n, err := ep.tun.Read(buf)
		if err != nil {
			return
		}
		if n <= 4 {
			continue
		}

		var protocol tcpip.NetworkProtocolNumber
		switch buf[3] {
		case unix.AF_INET:
			protocol = header.IPv4ProtocolNumber
		case unix.AF_INET6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.NewVectorisedView(n-4, []buffer.View{buffer.NewViewFromBytes(buf[4:n])}),
		})
		ep.dispatcher.DeliverNetworkPacket(protocol, pkt)
		pkt.DecRef()
	}
}

func (ep *tunLinkEndpoint) writeLoop() {
	buf := global.BufPool.Get(ep.mtu + 4)
	defer global.BufPool.Put(buf)

	for {
		pkt, ok := <-ep.writeCh
		if !ok {
			return
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

		views := pkt.Views()
		pktBuf := buf[:4]
		pktBuf[0] = 0
		pktBuf[1] = 0
		pktBuf[2] = 0
		switch views[0][0] >> 4 {
		case 4:
			pktBuf[3] = unix.AF_INET
		case 6:
			pktBuf[3] = unix.AF_INET6
		default:
			ep.writeErrCh <- &tcpip.ErrMalformedHeader{}
			continue
		}
		for i := range views {
			pktBuf = append(pktBuf, views[i]...)
		}

		if _, err := ep.tun.Write(pktBuf); err != nil {
			ep.writeErrCh <- &tcpip.ErrInvalidEndpointState{}
		} else {
			ep.writeErrCh <- nil
		}
	}
}
