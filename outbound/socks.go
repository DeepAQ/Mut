package outbound

import (
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/transport"
	"io"
	"net"
	"net/url"
	"strconv"
)

var (
	errAuthTooLong  = errors.New("username or password too long")
	errAddrTooLong  = errors.New("target address too long")
	errNoCredential = errors.New("auth required by server but no credential is provided")
	errAuthFailed   = errors.New("auth failed")
)

type socksOutbound struct {
	transport transport.TcpOutboundTransport
	needsAuth bool
	username  string
	password  string
}

func NewSocksOutbound(u *url.URL, tp transport.OutboundTransport) (*socksOutbound, error) {
	tcpTransport, err := transport.RequireTcpOutboundTransport(u, tp)
	if err != nil {
		return nil, err
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	if len(username) > 255 || len(password) > 255 {
		return nil, errAuthTooLong
	}
	return &socksOutbound{
		transport: tcpTransport,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}, nil
}

func (s *socksOutbound) Name() string {
	return "socks"
}

func (s *socksOutbound) DialTcp(targetAddr string) (net.Conn, error) {
	targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	if len(targetHost) > 255 {
		return nil, errAddrTooLong
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return nil, err
	}
	conn, err := s.transport.OpenConnection()
	if err != nil {
		return nil, err
	}

	bufSize := len(targetHost) + 6
	bufSize2 := len(s.username) + len(s.password) + 3
	if bufSize2 > bufSize {
		bufSize = bufSize2
	}
	if bufSize < 32 {
		bufSize = 32
	}
	buf := global.BufPool.Get(bufSize)
	defer global.BufPool.Put(buf)

	// client greeting
	buf = append(buf[:0], 0x05)
	if s.needsAuth {
		buf = append(buf, 0x02, 0x00, 0x02)
	} else {
		buf = append(buf, 0x01, 0x00)
	}
	if _, err := conn.Write(buf); err != nil {
		conn.Close()
		return nil, err
	}

	// server choice / auth
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 {
		conn.Close()
		return nil, errors.New("invalid version from server: " + strconv.Itoa(int(buf[0])))
	}
	switch buf[1] {
	case 0x02:
		if !s.needsAuth {
			conn.Close()
			return nil, errNoCredential
		}
		buf = append(buf[:0], 0x01, byte(len(s.username)))
		buf = append(buf, s.username...)
		buf = append(buf, byte(len(s.password)))
		buf = append(buf, s.password...)
		if _, err := conn.Write(buf); err != nil {
			conn.Close()
			return nil, err
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[0] != 0x01 {
			conn.Close()
			return nil, errors.New("invalid auth version from server: " + strconv.Itoa(int(buf[0])))
		}
		if buf[1] != 0x00 {
			conn.Close()
			return nil, errAuthFailed
		}
	case 0x00:
	default:
		conn.Close()
		return nil, errors.New("invalid auth method from server: " + strconv.Itoa(int(buf[1])))
	}

	// client request
	buf = append(buf[:0], 0x05, 0x01, 0x00)
	ip := net.ParseIP(targetHost)
	if ip == nil {
		buf = append(buf, 0x03, byte(len(targetHost)))
		buf = append(buf, targetHost...)
	} else {
		ip4 := ip.To4()
		if ip4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ip4...)
		} else {
			ip6 := ip.To16()
			buf = append(buf, 0x04)
			buf = append(buf, ip6...)
		}
	}
	buf = append(buf, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err := conn.Write(buf); err != nil {
		conn.Close()
		return nil, err
	}

	// server response
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 {
		conn.Close()
		return nil, errors.New("invalid version from server: " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] != 0x00 {
		conn.Close()
		return nil, errors.New("server connect failed: " + strconv.Itoa(int(buf[1])))
	}
	switch buf[3] {
	case 0x01:
		_, err = io.ReadFull(conn, buf[:6])
	case 0x04:
		_, err = io.ReadFull(conn, buf[:18])
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			conn.Close()
			return nil, err
		}
		if cap(buf) >= int(buf[0])+2 {
			_, err = io.ReadFull(conn, buf[:buf[0]+2])
		} else {
			buf2 := global.BufPool.Get(int(buf[0]) + 2)
			_, err = io.ReadFull(conn, buf2[:buf[0]+2])
			global.BufPool.Put(buf2)
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
