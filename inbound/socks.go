package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"github.com/DeepAQ/mut/config"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/util"
	"io"
	"net"
	"net/url"
	"strconv"
	"unsafe"
)

var (
	errAuthTooLong      = errors.New("username or password too long")
	errAuthNotSupported = errors.New("client does not support password auth")
	errAuthFailed       = errors.New("incorrect username or password")
)

type socksInbound struct {
	router     router.Router
	addr       string
	needsAuth  bool
	username   string
	password   string
	udpEnabled bool
	udpConn    net.PacketConn
}

func Socks(u *url.URL, rt router.Router) (*socksInbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	if len(username) > 255 || len(password) > 255 {
		return nil, errAuthTooLong
	}
	s := &socksInbound{
		router:    rt,
		addr:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}
	if u.Query().Get("udp") == "1" {
		if !s.needsAuth {
			s.udpEnabled = true
		} else {
			util.Stdout.Println("[socks] udp with auth is not supported yet")
		}
	}
	return s, nil
}

func (s *socksInbound) OnMutStart(ctx context.Context) {
	if s.udpEnabled {
		s.startUdpGw(ctx)
	}
}

func (s *socksInbound) Name() string {
	return "socks"
}

func (s *socksInbound) ServeConn(conn net.Conn, handleTcpStream StreamHandler) error {
	reader := bufio.NewReaderSize(conn, 64)

	// client greeting
	ver, _ := reader.ReadByte()
	if ver != 0x05 {
		return errors.New("unsupported socks version from client greeting: " + strconv.Itoa(int(ver)))
	}
	nAuth, err := reader.ReadByte()
	if err != nil {
		return err
	}
	authSupported := false
	for ; nAuth > 0; nAuth-- {
		auth, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if auth == 0x02 {
			authSupported = true
		}
	}

	// server choice / auth
	if s.needsAuth {
		if !authSupported {
			conn.Write([]byte{0x05, 0xff})
			return errAuthNotSupported
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return err
		}

		authVer, _ := reader.ReadByte()
		if authVer != 0x01 {
			return errors.New("unsupported auth version: " + strconv.Itoa(int(authVer)))
		}
		username, err := readLengthAndString(reader, 1, 255)
		if err != nil {
			return err
		}
		password, err := readLengthAndString(reader, 1, 255)
		if err != nil {
			return err
		}
		if username != s.username || password != s.password {
			conn.Write([]byte{0x01, 0x01})
			return errAuthFailed
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return err
		}
	}

	// client request
	ver, _ = reader.ReadByte()
	if ver != 0x05 {
		return errors.New("unsupported socks version from client request: " + strconv.Itoa(int(ver)))
	}
	cmd, _ := reader.ReadByte()
	if cmd != 0x01 {
		return errors.New("unsupported command: " + strconv.Itoa(int(cmd)))
	}
	reader.Discard(1)
	addrType, _ := reader.ReadByte()
	var addrAndPort string
	switch addrType {
	case 0x01:
		var ipAndPort [6]byte
		if _, err := io.ReadFull(reader, ipAndPort[:]); err != nil {
			return err
		}
		addrAndPort = net.IP(ipAndPort[:4]).String() + ":" + strconv.Itoa(int(ipAndPort[4])<<8+int(ipAndPort[5]))
	case 0x04:
		var ipAndPort [18]byte
		if _, err := io.ReadFull(reader, ipAndPort[:]); err != nil {
			return err
		}
		addrAndPort = "[" + net.IP(ipAndPort[:16]).String() + "]:" + strconv.Itoa(int(ipAndPort[16])<<8+int(ipAndPort[17]))
	case 0x03:
		domain, err := readLengthAndString(reader, 1, 255)
		if err != nil {
			return err
		}
		var port [2]byte
		if _, err := io.ReadFull(reader, port[:]); err != nil {
			return err
		}
		addrAndPort = domain + ":" + strconv.Itoa(int(port[0])<<8+int(port[1]))
	default:
		return errors.New("invalid address type: " + strconv.Itoa(int(addrType)))
	}

	// server response
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return err
	}
	handleTcpStream(&TcpStream{
		Conn:       conn,
		Protocol:   "socks5",
		ClientAddr: conn.RemoteAddr().String(),
		TargetAddr: addrAndPort,
	})
	return nil
}

func (s *socksInbound) startUdpGw(ctx context.Context) {
	var err error
	s.udpConn, err = net.ListenPacket("udp", s.addr)
	if err != nil {
		util.Stderr.Println("[socks-udp] failed to listen on " + s.addr + ": " + err.Error())
		return
	}
	util.Stdout.Println("[socks-udp] listening on " + s.addr)

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-cancelCtx.Done():
			s.udpConn.Close()
		}
		util.Stdout.Println("[socks-udp] udp listener stopped")
	}()

	go func() {
		buf := util.BufPool.Get(config.UdpMaxLength)
		defer util.BufPool.Put(buf)

		for {
			n, cAddr, err := s.udpConn.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					util.Stderr.Println("[socks-udp] failed to read request: " + err.Error())
				}
				cancel()
				return
			}

			if n <= 8 || (buf[0]|buf[1]|buf[2]) != 0 {
				continue
			}
			var off int
			var addrAndPort string
			switch buf[3] {
			case 0x01:
				if n <= 10 {
					continue
				}
				addrAndPort = net.IP(buf[4:8]).String() + ":" + strconv.Itoa(int(buf[8])<<8+int(buf[9]))
				off = 10
			case 0x04:
				if n <= 22 {
					continue
				}
				addrAndPort = "[" + net.IP(buf[4:20]).String() + "]:" + strconv.Itoa(int(buf[20])<<8+int(buf[21]))
				off = 22
			case 0x03:
				l := buf[4]
				if n <= int(l)+7 {
					continue
				}
				addrAndPort = string(buf[5:5+l]) + ":" + strconv.Itoa(int(buf[5+l])<<8+int(buf[6+l]))
				off = int(l) + 7
			default:
				continue
			}

			s.router.SendUdpPacket(s, cAddr, addrAndPort, buf[off:n])
		}
	}()
}

func (s *socksInbound) ReplyUdpPacket(clientAddr, remoteAddr net.Addr, data []byte) error {
	buf := util.BufPool.Get(len(data) + 10)
	defer util.BufPool.Put(buf)

	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0x01
	rAddr := remoteAddr.(*net.UDPAddr)
	ip4 := rAddr.IP.To4()
	if ip4 == nil {
		return nil
	}
	copy(buf[4:8], ip4)
	binary.BigEndian.PutUint16(buf[8:10], uint16(rAddr.Port))
	copy(buf[10:], data)

	_, err := s.udpConn.WriteTo(buf, clientAddr)
	return err
}

func readLengthAndString(r *bufio.Reader, minLength, maxLength byte) (string, error) {
	l, _ := r.ReadByte()
	if l <= 0 || l < minLength || l > maxLength {
		return "", errors.New("invalid length: " + strconv.Itoa(int(l)))
	}

	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return *(*string)(unsafe.Pointer(&buf)), nil
}
