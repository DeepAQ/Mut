package inbound

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"unsafe"
)

var (
	errAuthTooLong      = errors.New("username or password too long")
	errAuthNotSupported = errors.New("client does not support password auth")
)

type socksInbound struct {
	needsAuth bool
	username  string
	password  string
}

func Socks(u *url.URL) (*socksInbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	if len(username) > 255 || len(password) > 255 {
		return nil, errAuthTooLong
	}
	return &socksInbound{
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}, nil
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
			return errors.New("incorrect username or password")
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
