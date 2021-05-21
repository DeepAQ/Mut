package udp

import "net"

type Inbound interface {
	Name() string
	ReplyUdpPacket(clientAddr, remoteAddr net.Addr, data []byte) error
}
