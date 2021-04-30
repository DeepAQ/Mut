package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/util"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	errUnknownConnType = errors.New("unknown conn type")
)

type mixInbound struct {
	http  *httpInbound
	socks *socksInbound
}

func Mix(u *url.URL, rt router.Router) (*mixInbound, error) {
	h, err := Http(u, rt)
	if err != nil {
		return nil, err
	}
	s, err := Socks(u)
	if err != nil {
		return nil, err
	}
	return &mixInbound{
		http:  h,
		socks: s,
	}, nil
}

func (m *mixInbound) Name() string {
	return "mix"
}

func (m *mixInbound) ServeConn(conn net.Conn, handleTcpStream StreamHandler) error {
	buf := util.BufPool.Get(64)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil {
		util.BufPool.Put(buf)
		return err
	}
	buf = buf[:n]
	if buf[0] == 0x05 {
		return m.socks.ServeConn(newMixConn(conn, buf), handleTcpStream)
	} else {
		str := *(*string)(unsafe.Pointer(&buf))
		if strings.HasPrefix(str, "CONNECT ") ||
			strings.Index(str, "HTTP/") >= 0 ||
			strings.Index(str, "http://") >= 0 {
			return m.http.ServeConn(newMixConn(conn, buf), handleTcpStream)
		} else {
			util.BufPool.Put(buf)
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return errUnknownConnType
		}
	}
}

type mixConn struct {
	sync.Mutex
	conn      net.Conn
	buf       []byte
	bufOffset uint32
	bufLimit  uint32
}

func newMixConn(conn net.Conn, buf []byte) *mixConn {
	return &mixConn{
		conn:      conn,
		buf:       buf,
		bufOffset: 0,
		bufLimit:  uint32(len(buf)),
	}
}

func (m *mixConn) closeBufLocked() {
	if m.buf != nil {
		m.bufOffset = m.bufLimit
		util.BufPool.Put(m.buf)
		m.buf = nil
	}
}

func (m *mixConn) Read(b []byte) (n int, err error) {
	if m.buf != nil && atomic.LoadUint32(&m.bufOffset) < m.bufLimit {
		m.Lock()
		defer m.Unlock()
		if m.buf != nil && m.bufOffset < m.bufLimit {
			n := copy(b, m.buf[m.bufOffset:m.bufLimit])
			m.bufOffset += uint32(n)
			if m.bufOffset >= m.bufLimit {
				m.closeBufLocked()
			}
			return n, nil
		}
	}
	return m.conn.Read(b)
}

func (m *mixConn) Write(b []byte) (n int, err error) {
	return m.conn.Write(b)
}

func (m *mixConn) Close() error {
	m.Lock()
	defer m.Unlock()
	m.closeBufLocked()
	return m.conn.Close()
}

func (m *mixConn) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

func (m *mixConn) RemoteAddr() net.Addr {
	return m.conn.RemoteAddr()
}

func (m *mixConn) SetDeadline(t time.Time) error {
	return m.conn.SetDeadline(t)
}

func (m *mixConn) SetReadDeadline(t time.Time) error {
	return m.conn.SetReadDeadline(t)
}

func (m *mixConn) SetWriteDeadline(t time.Time) error {
	return m.conn.SetWriteDeadline(t)
}
