package inbound

import (
	"bufio"
	"encoding/binary"
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
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

type socksProtocol struct {
	router     router.Router
	addr       string
	needsAuth  bool
	username   string
	password   string
	udpEnabled bool
	udpConn    net.PacketConn
}

func NewSocksProtocol(u *url.URL) *socksProtocol {
	username := u.User.Username()
	password, _ := u.User.Password()
	s := &socksProtocol{
		addr:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}
	if u.Query().Get("udp") == "1" {
		if !s.needsAuth {
			s.udpEnabled = true
		} else {
			global.Stdout.Println("[socks] udp with auth is not supported yet")
		}
	}
	return s
}

func (s *socksProtocol) Name() string {
	return "socks5"
}

func (s *socksProtocol) Serve(l net.Listener, r router.Router) error {
	if len(s.username) > 255 || len(s.password) > 255 {
		return errAuthTooLong
	}
	s.startUdpGw(r)
	return serveListenerWithConnHandler("socks", l, r, s.serveConn)
}

func (s *socksProtocol) serveConn(conn net.Conn, r router.Router) error {
	defer conn.Close()
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
	r.HandleTcpStream("socks5", conn, conn.RemoteAddr().String(), addrAndPort)
	return nil
}

func (s *socksProtocol) startUdpGw(r router.Router) {
	if !s.udpEnabled {
		return
	}

	var err error
	s.udpConn, err = net.ListenPacket("udp", s.addr)
	if err != nil {
		global.Stderr.Println("[socks-udp] failed to listen on " + s.addr + ": " + err.Error())
		return
	}
	global.Stdout.Println("[socks-udp] listening on " + s.addr)

	go func() {
		buf := global.BufPool.Get(global.UdpMaxLength)
		defer global.BufPool.Put(buf)

		for {
			n, cAddr, err := s.udpConn.ReadFrom(buf)
			if err != nil {
				global.Stderr.Println("[socks-udp] failed to read request: " + err.Error())
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

			r.SendUdpPacket(s, "socks-udp", cAddr, addrAndPort, buf[off:n])
		}
	}()
}

func (s *socksProtocol) ReplyUdpPacket(clientAddr, remoteAddr net.Addr, data []byte) {
	buf := global.BufPool.Get(len(data) + 10)
	defer global.BufPool.Put(buf)

	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0x01
	rAddr := remoteAddr.(*net.UDPAddr)
	ip4 := rAddr.IP.To4()
	if ip4 == nil {
		return
	}
	copy(buf[4:8], ip4)
	binary.BigEndian.PutUint16(buf[8:10], uint16(rAddr.Port))
	copy(buf[10:], data)

	s.udpConn.WriteTo(buf, clientAddr)
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
