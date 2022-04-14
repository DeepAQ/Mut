package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
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

type mixProtocol struct {
	http  *httpProtocol
	socks *socksProtocol
}

func NewMixProtocol(u *url.URL) *mixProtocol {
	return &mixProtocol{
		http:  NewHttpProtocol(u),
		socks: NewSocksProtocol(u),
	}
}

func (m *mixProtocol) Serve(l net.Listener, r router.Router) error {
	if len(m.socks.username) > 255 || len(m.socks.password) > 255 {
		return errAuthTooLong
	}
	m.socks.startUdpGw(r)
	return serveListenerWithConnHandler("mix", l, r, m.serveConn)
}

func (m *mixProtocol) serveConn(conn net.Conn, r router.Router) error {
	buf := global.BufPool.Get(64)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil {
		global.BufPool.Put(buf)
		return err
	}
	buf = buf[:n]
	if buf[0] == 0x05 {
		return m.socks.serveConn(newMixConn(conn, buf), r)
	} else {
		str := *(*string)(unsafe.Pointer(&buf))
		if strings.HasPrefix(str, "CONNECT ") ||
			strings.Index(str, "HTTP/") >= 0 ||
			strings.Index(str, "http://") >= 0 {
			return m.http.serveConn(newMixConn(conn, buf), r)
		} else {
			global.BufPool.Put(buf)
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return errUnknownConnType
		}
	}
}

type mixConn struct {
	conn net.Conn
	buf  []byte
	sync.Mutex
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
		global.BufPool.Put(m.buf)
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
