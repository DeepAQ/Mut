package inbound

import (
	"encoding/binary"
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	l2tpDefaultMtu         = 1450
	pppIP                  = 0x0021
	pppLCP                 = 0xc021
	pppIPCP                = 0x8021
	lcpOptionMRU           = 1
	lcpOptionMagic         = 5
	ipcpOptionIP           = 3
	ipcpOptionPrimaryDNS   = 129
	ipcpOptionSecondaryDNS = 131
	pppLocalIPAddress      = 203<<24 + 113<<8 + 1
	pppTerminateReason     = "Never gonna give you up"
)

var (
	errMessageTooShort   = errors.New("message is too short")
	errAVPLengthMismatch = errors.New("AVP length does not match its type")
)

type l2tpInbound struct {
	sessions map[string]*l2tpTunLinkEndpoint
	addr     string
	dnsgw    string
	magic    uint32
}

func NewL2TPInbound(u *url.URL) *l2tpInbound {
	addr := u.Host
	if strings.IndexByte(addr, ':') < 0 {
		addr += ":1701"
	}
	dnsgw := u.Query().Get("dnsgw")
	if len(dnsgw) > 0 && strings.IndexByte(dnsgw, ':') < 0 {
		dnsgw = dnsgw + ":53"
	}

	return &l2tpInbound{
		addr:     addr,
		dnsgw:    dnsgw,
		magic:    rand.Uint32(),
		sessions: map[string]*l2tpTunLinkEndpoint{},
	}
}

func (l *l2tpInbound) Name() string {
	return "l2tp"
}

func (l *l2tpInbound) Serve(r router.Router) error {
	conn, err := net.ListenPacket("udp", l.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	global.Stdout.Println("[l2tp] listening on " + l.addr)

	buf := global.BufPool.Get(global.UdpMaxLength)
	defer global.BufPool.Put(buf)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue
		}

		data := buf[:n]
		header, err := parseL2TPHeader(data)
		if err != nil {
			continue
		}
		if header.Length > 0 && int(header.Length) != n {
			continue
		}

		if header.Control {
			l.processControlMessage(conn, clientAddr, header, buf[header.HeaderLength:n])
		} else {
			l.processDataMessage(conn, clientAddr, r, header, buf[header.HeaderLength:n])
		}
	}
}

func (l *l2tpInbound) processControlMessage(conn net.PacketConn, clientAddr net.Addr, header *l2tpHeader, data []byte) {
	body, err := parseL2TPControlBody(data)
	if err != nil {
		return
	}

	repHeader := l2tpHeader{
		Control:   true,
		TunnelID:  header.TunnelID - 1,
		SessionID: 0,
		Ns:        header.Nr,
		Nr:        header.Ns + 1,
	}
	switch body.MessageType {
	case 3, 4, 6, 12, 14: // SCCCN, StopCCN, HELLO, ICCN, CDN
		zlbBody := l2tpControlBody{}
		sendL2TPControlMessage(conn, clientAddr, data, &repHeader, &zlbBody)
	case 1: // SCCRQ
		repHeader.TunnelID = body.AssignedTunnelID
		sccrpBody := l2tpControlBody{
			HostName:         "Mut",
			MessageType:      2, // SCCRP
			AssignedTunnelID: body.AssignedTunnelID + 1,
			ProtocolVer:      1,
			ProtocolRev:      0,
			AsyncFraming:     false,
			SyncFraming:      true,
		}
		sendL2TPControlMessage(conn, clientAddr, data, &repHeader, &sccrpBody)
	case 10: // ICRQ
		repHeader.SessionID = body.AssignedSessionID
		icrpBody := l2tpControlBody{
			MessageType:       11, // ICRP
			AssignedSessionID: body.AssignedSessionID + 1,
		}
		sendL2TPControlMessage(conn, clientAddr, data, &repHeader, &icrpBody)
	}
}

func (l *l2tpInbound) processDataMessage(conn net.PacketConn, clientAddr net.Addr, r router.Router, header *l2tpHeader, data []byte) {
	if len(data) < 4 || data[0] != 0xff || data[1] != 0x03 {
		return
	}

	repHeader := l2tpHeader{
		Control:   false,
		TunnelID:  header.TunnelID - 1,
		SessionID: header.SessionID - 1,
	}
	protocol := binary.BigEndian.Uint16(data[2:4])
	switch protocol {
	case pppLCP, pppIPCP:
		frame, err := parsePPPCPFrame(data[4:], protocol)
		if err != nil {
			return
		}

		switch protocol + uint16(frame.Code) {
		// LCP
		case pppLCP + 1: // Configure-Request
			confReqFrame := pppcpFrame{
				Protocol:   pppLCP,
				Code:       1, // Configure-Request
				Identifier: frame.Identifier + 1,
				Options:    map[uint8][]byte{},
			}
			if mru, ok := frame.Options[lcpOptionMRU]; ok {
				confReqFrame.Options[lcpOptionMRU] = mru
			}
			confReqFrame.Options[lcpOptionMagic] = []byte{byte(l.magic >> 24), byte(l.magic >> 16), byte(l.magic >> 8), byte(l.magic)}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confReqFrame)
			confAckFrame := pppcpFrame{
				Protocol:   pppLCP,
				Code:       2, // Configure-Ack
				Identifier: frame.Identifier,
				Options:    frame.Options,
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confAckFrame)
		case pppLCP + 2: // Configure-Ack
			sessionKey := clientAddr.String()
			if ep, ok := l.sessions[sessionKey]; ok {
				ep.close()
			}
			mtu := uint32(l2tpDefaultMtu)
			if mru, ok := frame.Options[lcpOptionMRU]; ok {
				mtu = uint32(binary.BigEndian.Uint16(mru))
			}
			l.sessions[sessionKey] = &l2tpTunLinkEndpoint{
				conn:       conn,
				clientAddr: clientAddr,
				l2tpHeader: &repHeader,
				mtu:        mtu,
			}
		case pppLCP + 5: // Terminate-Request
			l.sendLCPTerminateRequest(conn, clientAddr, data, &repHeader)
			termAckFrame := pppcpFrame{
				Protocol:   pppLCP,
				Code:       6, // Terminate-Ack
				Identifier: frame.Identifier,
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &termAckFrame)
		case pppLCP + 9: // Echo-Request
			sessionKey := clientAddr.String()
			if _, ok := l.sessions[sessionKey]; ok {
				echoReplyFrame := pppcpFrame{
					Protocol:   pppLCP,
					Code:       10, // Echo-Reply
					Identifier: frame.Identifier,
					Magic:      l.magic,
					ExtraData:  frame.ExtraData,
				}
				sendPPPCPFrame(conn, clientAddr, data, &repHeader, &echoReplyFrame)
			} else {
				l.sendLCPTerminateRequest(conn, clientAddr, data, &repHeader)
			}
		// IPCP
		case pppIPCP + 1: // Configure-Request
			confRepFrame := pppcpFrame{
				Protocol:   pppIPCP,
				Code:       2, // Configure-Ack
				Identifier: frame.Identifier,
				Options:    frame.Options,
			}
			if ip, ok := frame.Options[ipcpOptionIP]; ok && binary.BigEndian.Uint32(ip) == 0 {
				confRepFrame.Code = 3 // Configure-Nak
				ip := pppLocalIPAddress + 1
				confRepFrame.Options[ipcpOptionIP] = []byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}
				dns := pppLocalIPAddress
				if _, ok := frame.Options[ipcpOptionPrimaryDNS]; ok {
					confRepFrame.Options[ipcpOptionPrimaryDNS] = []byte{byte(dns >> 24), byte(dns >> 16), byte(dns >> 8), byte(dns)}
				}
				if _, ok := frame.Options[ipcpOptionSecondaryDNS]; ok {
					confRepFrame.Options[ipcpOptionSecondaryDNS] = []byte{byte(dns >> 24), byte(dns >> 16), byte(dns >> 8), byte(dns)}
				}
			} else {
				confReqFrame := pppcpFrame{
					Protocol:   pppIPCP,
					Code:       1, // Configure-Request
					Identifier: frame.Identifier + 1,
					Options:    map[uint8][]byte{},
				}
				if ip, ok := frame.Options[ipcpOptionIP]; ok {
					ip := binary.BigEndian.Uint32(ip) - 1
					confReqFrame.Options[ipcpOptionIP] = []byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}
				}
				sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confReqFrame)
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confRepFrame)
		case pppIPCP + 2: // Configure-Ack
			sessionKey := clientAddr.String()
			if ep, ok := l.sessions[sessionKey]; ok {
				st, err := createTunStack("l2tp", ep, r, l.dnsgw)
				if err != nil {
					global.Stderr.Println("[l2tp] failed to establish new session with " + sessionKey + ": " + err.Error())
					l.sendLCPTerminateRequest(conn, clientAddr, data, &repHeader)
				}
				ep.stack = st
				global.Stdout.Println("[l2tp] established new session with " + sessionKey)
			}
		case pppIPCP + 3: // Configure-Nak
			confReqFrame := pppcpFrame{
				Protocol:   pppIPCP,
				Code:       1, // Configure-Request
				Identifier: frame.Identifier + 1,
				Options:    frame.Options,
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confReqFrame)
		case pppIPCP + 4: // Configure-Reject
			confReqFrame := pppcpFrame{
				Protocol:   pppIPCP,
				Code:       1, // Configure-Request
				Identifier: frame.Identifier + 1,
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &confReqFrame)
		case pppIPCP + 5: // Terminate-Request
			termReqFrame := pppcpFrame{
				Protocol:   pppIPCP,
				Code:       5, // Terminate-Request
				Identifier: frame.Identifier + 1,
				ExtraData:  []byte(pppTerminateReason),
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &termReqFrame)
			termAckFrame := pppcpFrame{
				Protocol:   pppIPCP,
				Code:       6, // Terminate-Ack
				Identifier: frame.Identifier,
			}
			sendPPPCPFrame(conn, clientAddr, data, &repHeader, &termAckFrame)
		}
	case pppIP:
		sessionKey := clientAddr.String()
		if ep, ok := l.sessions[sessionKey]; ok {
			ep.injectPacket(data[4:])
		} else {
			l.sendLCPTerminateRequest(conn, clientAddr, data, &repHeader)
		}
	}
}

func (l *l2tpInbound) sendLCPTerminateRequest(conn net.PacketConn, clientAddr net.Addr, buf []byte, header *l2tpHeader) {
	termReqFrame := pppcpFrame{
		Protocol:   pppLCP,
		Code:       5, // Terminate-Request
		Identifier: 1,
		ExtraData:  []byte(pppTerminateReason),
	}
	sendPPPCPFrame(conn, clientAddr, buf, header, &termReqFrame)
	sessionKey := clientAddr.String()
	if ep, ok := l.sessions[sessionKey]; ok {
		ep.close()
		delete(l.sessions, sessionKey)
	}
}

func sendL2TPControlMessage(conn net.PacketConn, clientAddr net.Addr, buf []byte, header *l2tpHeader, body *l2tpControlBody) {
	buf = header.writeTo(buf)
	buf = body.appendTo(buf)
	if _, err := conn.WriteTo(buf, clientAddr); err != nil {
		global.Stderr.Println("[l2tp] failed to send control message: " + err.Error())
	}
}

func sendPPPCPFrame(conn net.PacketConn, clientAddr net.Addr, buf []byte, header *l2tpHeader, frame *pppcpFrame) {
	buf = header.writeTo(buf)
	// write PPP header
	buf = append(buf, 0xff, 0x03, byte(frame.Protocol>>8), byte(frame.Protocol))
	buf = frame.appendTo(buf)
	if _, err := conn.WriteTo(buf, clientAddr); err != nil {
		global.Stderr.Println("[l2tp] failed to send PPPCP frame: " + err.Error())
	}
}

type l2tpHeader struct {
	HeaderLength int
	Control      bool
	Length       uint16
	TunnelID     uint16
	SessionID    uint16
	Ns           uint16
	Nr           uint16
	Offset       uint16
}

func parseL2TPHeader(data []byte) (*l2tpHeader, error) {
	dataLen := len(data)
	if dataLen < 6 {
		return nil, errMessageTooShort
	}
	hasLength := data[0]&(1<<6) != 0
	hasSequence := data[0]&(1<<3) != 0
	hasOffset := data[0]&(1<<1) != 0
	headerLen := 6
	if hasLength {
		headerLen += 2
	}
	if hasSequence {
		headerLen += 4
	}
	if hasOffset {
		headerLen += 2
	}
	if dataLen < headerLen {
		return nil, errMessageTooShort
	}
	version := data[1] & (1<<4 - 1)
	if version != 2 {
		return nil, errors.New("unsupported l2tp header version: " + strconv.Itoa(int(version)))
	}

	header := &l2tpHeader{
		HeaderLength: headerLen,
		Control:      data[0]&(1<<7) != 0,
	}
	dataOffset := 2
	if hasLength {
		header.Length = binary.BigEndian.Uint16(data[dataOffset : dataOffset+2])
		dataOffset += 2
	}
	header.TunnelID = binary.BigEndian.Uint16(data[dataOffset : dataOffset+2])
	header.SessionID = binary.BigEndian.Uint16(data[dataOffset+2 : dataOffset+4])
	dataOffset += 4
	if hasSequence {
		header.Ns = binary.BigEndian.Uint16(data[dataOffset : dataOffset+2])
		header.Nr = binary.BigEndian.Uint16(data[dataOffset+2 : dataOffset+4])
		dataOffset += 4
	}
	if hasOffset {
		header.Offset = binary.BigEndian.Uint16(data[dataOffset : dataOffset+2])
		// dataOffset += 2
	}
	return header, nil
}

type l2tpControlBody struct {
	HostName          string
	MessageType       uint16
	AssignedTunnelID  uint16 // SCCRQ, SCCRP
	ProtocolVer       uint8  // SCCRQ, SCCRP
	ProtocolRev       uint8  // SCCRQ, SCCRP
	AsyncFraming      bool   // SCCRQ, SCCRP
	SyncFraming       bool   // SCCRQ, SCCRP
	AssignedSessionID uint16 // ICRQ, ICRP
}

func (header *l2tpHeader) writeTo(buf []byte) []byte {
	if header.Control {
		// write header without length
		buf = append(buf[:0], 0xc8, 0x02, 0x00, 0x00,
			byte(header.TunnelID>>8), byte(header.TunnelID),
			byte(header.SessionID>>8), byte(header.SessionID),
			byte(header.Ns>>8), byte(header.Ns),
			byte(header.Nr>>8), byte(header.Nr))
	} else {
		buf = append(buf[:0], 0x00, 0x02,
			byte(header.TunnelID>>8), byte(header.TunnelID),
			byte(header.SessionID>>8), byte(header.SessionID))
	}
	return buf
}

func parseL2TPControlBody(body []byte) (*l2tpControlBody, error) {
	msg := &l2tpControlBody{}
	bodyLen := len(body)
	offset := 0
	for offset < bodyLen {
		if bodyLen-offset < 6 {
			return nil, errMessageTooShort
		}
		avpLen := int(binary.BigEndian.Uint16(body[offset:offset+2])&(1<<10-1) - 6)
		if avpLen < 0 {
			return nil, errors.New("invalid AVP length: " + strconv.Itoa(avpLen))
		}
		avpType := binary.BigEndian.Uint16(body[offset+4 : offset+6])
		offset += 6
		if bodyLen-offset < avpLen {
			return nil, errMessageTooShort
		}

		switch avpType {
		case 0: // Control Message
			if avpLen != 2 {
				return nil, errAVPLengthMismatch
			}
			msg.MessageType = binary.BigEndian.Uint16(body[offset : offset+2])
		case 2: // Protocol Version
			if avpLen != 2 {
				return nil, errAVPLengthMismatch
			}
			msg.ProtocolVer = body[offset]
			msg.ProtocolRev = body[offset+1]
		case 3: // Framing Capabilities
			if avpLen != 4 {
				return nil, errAVPLengthMismatch
			}
			msg.AsyncFraming = body[offset+3]&0x10 != 0
			msg.SyncFraming = body[offset+3]&0x1 != 0
		case 7: // Host Name
			msg.HostName = string(body[offset : offset+avpLen])
		case 9: // Assigned Tunnel ID
			if avpLen != 2 {
				return nil, errAVPLengthMismatch
			}
			msg.AssignedTunnelID = binary.BigEndian.Uint16(body[offset : offset+2])
		case 14: // Assigned Session ID
			if avpLen != 2 {
				return nil, errAVPLengthMismatch
			}
			msg.AssignedSessionID = binary.BigEndian.Uint16(body[offset : offset+2])
		}
		offset += avpLen
	}
	return msg, nil
}

func (body *l2tpControlBody) appendTo(buf []byte) []byte {
	// write Control Message AVP
	if body.MessageType > 0 {
		buf = append(buf, 0x80, 0x08, 0x00, 0x00, 0x00, 0x00,
			byte(body.MessageType>>8), byte(body.MessageType))
	}
	// write Protocol Version AVP
	if body.ProtocolVer+body.ProtocolRev > 0 {
		buf = append(buf, 0x80, 0x08, 0x00, 0x00, 0x00, 0x02,
			body.ProtocolVer, body.ProtocolRev)
	}
	// write Framing Capabilities AVP
	if body.AsyncFraming || body.SyncFraming {
		frameCap := byte(0)
		if body.AsyncFraming {
			frameCap |= 2
		}
		if body.SyncFraming {
			frameCap |= 1
		}
		buf = append(buf, 0x80, 0x0a, 0x00, 0x00, 0x00, 0x03,
			0x00, 0x00, 0x00, frameCap)
	}
	// write Host Name AVP
	hostNameLen := len(body.HostName)
	if hostNameLen > 0 && hostNameLen < 250 {
		buf = append(buf, 0x80, byte(hostNameLen+6), 0x00, 0x00, 0x00, 0x07)
		buf = append(buf, []byte(body.HostName)...)
	}
	// write Assigned Tunnel ID AVP
	if body.AssignedTunnelID > 0 {
		buf = append(buf, 0x80, 0x08, 0x00, 0x00, 0x00, 0x09,
			byte(body.AssignedTunnelID>>8), byte(body.AssignedTunnelID))
	}
	// write Assigned Session ID AVP
	if body.AssignedSessionID > 0 {
		buf = append(buf, 0x80, 0x08, 0x00, 0x00, 0x00, 0x0e,
			byte(body.AssignedSessionID>>8), byte(body.AssignedSessionID))
	}
	// set length in header
	bufLen := len(buf)
	buf[2] = byte(bufLen >> 8)
	buf[3] = byte(bufLen)
	return buf
}

type pppcpFrame struct {
	Options    map[uint8][]byte
	ExtraData  []byte
	Protocol   uint16
	Code       uint8
	Identifier uint8
	Magic      uint32
}

func parsePPPCPFrame(data []byte, protocol uint16) (*pppcpFrame, error) {
	dataLen := len(data)
	if dataLen < 4 {
		return nil, errMessageTooShort
	}
	cpLen := binary.BigEndian.Uint16(data[2:4])
	if int(cpLen) != dataLen {
		return nil, errMessageTooShort
	}

	frame := &pppcpFrame{
		Protocol:   protocol,
		Code:       data[0],
		Identifier: data[1],
		Options:    map[uint8][]byte{},
	}
	offset := 4
	switch frame.Code {
	case 1, 2, 3, 4:
		for offset < dataLen {
			if dataLen-offset < 2 {
				return nil, errMessageTooShort
			}
			optType := data[offset]
			optLen := int(data[offset+1]) - 2
			if optLen < 0 {
				return nil, errors.New("invalid PPPCP option length: " + strconv.Itoa(optLen))
			}
			offset += 2
			if dataLen-offset < optLen {
				return nil, errMessageTooShort
			}
			optBytes := make([]byte, optLen)
			copy(optBytes, data[offset:])
			frame.Options[optType] = optBytes
			offset += optLen
		}
	case 9, 10, 11:
		if dataLen-offset < 4 {
			return nil, errMessageTooShort
		}
		frame.Magic = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if offset < dataLen {
		frame.ExtraData = make([]byte, dataLen-offset)
		copy(frame.ExtraData, data[offset:])
	}

	return frame, nil
}

func (frame *pppcpFrame) appendTo(buf []byte) []byte {
	start := len(buf)
	// write header without length
	buf = append(buf, frame.Code, frame.Identifier, 0x00, 0x00)
	switch frame.Code {
	case 1, 2, 3, 4:
		if frame.Options != nil {
			keys := make([]int, 0, len(frame.Options))
			for key := range frame.Options {
				keys = append(keys, int(key))
			}
			sort.Ints(keys)
			for _, key := range keys {
				optType := uint8(key)
				optBytes := frame.Options[optType]
				buf = append(buf, optType, byte(len(optBytes)+2))
				buf = append(buf, optBytes...)
			}
		}
	case 9, 10, 11:
		buf = append(buf, byte(frame.Magic>>24), byte(frame.Magic>>16), byte(frame.Magic>>8), byte(frame.Magic))
	}

	// write extra data
	if frame.ExtraData != nil {
		buf = append(buf, frame.ExtraData...)
	}
	// set header length
	frameLen := len(buf) - start
	buf[start+2] = byte(frameLen >> 8)
	buf[start+3] = byte(frameLen)
	return buf
}

type l2tpTunLinkEndpoint struct {
	conn       net.PacketConn
	clientAddr net.Addr
	l2tpHeader *l2tpHeader
	stack      *stack.Stack
	dispatcher stack.NetworkDispatcher
	mtu        uint32
}

func (ep *l2tpTunLinkEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *l2tpTunLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *l2tpTunLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *l2tpTunLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *l2tpTunLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher != nil {
		ep.dispatcher = dispatcher
	}
}

func (ep *l2tpTunLinkEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *l2tpTunLinkEndpoint) Wait() {
}

func (ep *l2tpTunLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *l2tpTunLinkEndpoint) AddHeader(_ *stack.PacketBuffer) {
}

func (ep *l2tpTunLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	buf := global.BufPool.Get(int(ep.mtu + 20))
	defer global.BufPool.Put(buf)

	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if pkt.Size() > int(ep.mtu) {
			continue
		}

		pktBuf := ep.l2tpHeader.writeTo(buf)
		pktBuf = append(pktBuf, 0xff, 0x03, pppIP>>8, pppIP)
		views := pkt.Views()
		for i := range views {
			pktBuf = append(pktBuf, views[i]...)
		}

		if _, err := ep.conn.WriteTo(pktBuf, ep.clientAddr); err != nil {
			return n, &tcpip.ErrInvalidEndpointState{}
		}
		n++
	}
	return n, nil
}

func (ep *l2tpTunLinkEndpoint) close() {
	if ep.stack != nil {
		ep.stack.Close()
		ep.stack = nil
		ep.dispatcher = nil
	}
}

func (ep *l2tpTunLinkEndpoint) injectPacket(buf []byte) {
	if ep.dispatcher == nil {
		return
	}
	n := len(buf)
	if n <= 0 {
		return
	}

	var protocol tcpip.NetworkProtocolNumber
	switch buf[0] >> 4 {
	case 4:
		protocol = header.IPv4ProtocolNumber
	case 6:
		protocol = header.IPv6ProtocolNumber
	default:
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.NewVectorisedView(n, []buffer.View{buffer.NewViewFromBytes(buf)}),
	})
	ep.dispatcher.DeliverNetworkPacket(protocol, pkt)
	pkt.DecRef()
}
