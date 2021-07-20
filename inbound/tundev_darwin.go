// +build darwin,!ios

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

func newTunInboundWithDevice(u *url.URL) (*tunInbound, error) {
	tag := u.Query().Get("fd")
	fd, err := strconv.Atoi(tag)
	if err != nil {
		tag = u.Host
		if !strings.HasPrefix(tag, "utun") {
			return nil, errors.New("tun device name must start with 'utun'")
		}

		id, err := strconv.Atoi(tag[4:])
		if err != nil {
			return nil, errors.New("incorrect tun device name")
		}

		fd, err = openTunDevice(id)
		if err != nil {
			return nil, errors.New("failed to open tun device " + tag + ": " + err.Error())
		}
	}

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

	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ctlInfo); err != nil {
		return -1, err
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(id) + 1,
	}); err != nil {
		return -1, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		return -1, err
	}
	return fd, nil
}

type tunLinkEndpoint struct {
	tun        io.ReadWriteCloser
	mtu        int
	dispatcher stack.NetworkDispatcher
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
	return stack.CapabilityNone
}

func (ep *tunLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
	go func() {
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

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: buffer.NewVectorisedView(n-4, []buffer.View{buffer.NewViewFromBytes(buf[4:])}),
			})
			ep.dispatcher.DeliverNetworkPacket("", "", header.IPv4ProtocolNumber, pkt)
		}
	}()
}

func (ep *tunLinkEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *tunLinkEndpoint) Wait() {
}

func (ep *tunLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *tunLinkEndpoint) AddHeader(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
}

func (ep *tunLinkEndpoint) WritePacket(_ stack.RouteInfo, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	return ep.writePacketInternal(pkt)
}

func (ep *tunLinkEndpoint) WritePackets(_ stack.RouteInfo, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err := ep.writePacketInternal(pkt); err != nil {
			break
		}
		n++
	}
	return n, nil
}

func (ep *tunLinkEndpoint) writePacketInternal(pkt *stack.PacketBuffer) tcpip.Error {
	if pkt.Size() > ep.mtu {
		return &tcpip.ErrMessageTooLong{}
	}

	buf := global.BufPool.Get(pkt.Size() + 4)[:4]
	defer global.BufPool.Put(buf)

	buf[3] = unix.AF_INET
	for _, v := range pkt.Views() {
		buf = append(buf, v...)
	}

	if _, err := ep.tun.Write(buf); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}
