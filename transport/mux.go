package transport

import (
	"github.com/hashicorp/yamux"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	muxTransportName = "mux"
)

type muxInboundTransport struct {
	inner      TcpInboundTransport
	closed     chan struct{}
	err        error
	streams    chan *yamux.Stream
	listenOnce sync.Once
}

func NewMuxInboundTransport(u *url.URL, inner InboundTransport) (*muxInboundTransport, error) {
	tInner, err := RequireTcpInboundTransport(u, inner)
	if err != nil {
		return nil, err
	}

	return &muxInboundTransport{
		inner:   tInner,
		closed:  make(chan struct{}),
		streams: make(chan *yamux.Stream),
	}, nil
}

func (m *muxInboundTransport) InboundTransportName() string {
	return muxTransportName
}

func (m *muxInboundTransport) Accept() (net.Conn, error) {
	m.listenOnce.Do(func() {
		go func() {
			for {
				conn, err := m.inner.Accept()
				if err != nil {
					m.err = err
					m.Close()
					return
				}

				go func() {
					sess, err := yamux.Server(conn, yamux.DefaultConfig())
					if err != nil {
						conn.Close()
						return
					}

					for {
						stream, err := sess.AcceptStream()
						if err != nil {
							sess.Close()
							return
						}
						m.streams <- stream
					}
				}()
			}
		}()
	})

	select {
	case <-m.closed:
		if m.err != nil {
			return nil, m.err
		}
		return nil, net.ErrClosed
	case stream := <-m.streams:
		return stream, nil
	}
}

func (m *muxInboundTransport) Close() error {
	select {
	case <-m.closed:
		return nil
	default:
	}

	close(m.closed)
	return m.inner.Close()
}

func (m *muxInboundTransport) Addr() net.Addr {
	return m.inner.Addr()
}

type muxOutboundTransport struct {
	inner     TcpOutboundTransport
	sessions  []unsafe.Pointer //*yamux.Session
	sessionMu []sync.Mutex
}

func NewMuxOutboundTransport(u *url.URL, inner OutboundTransport) (*muxOutboundTransport, error) {
	tInner, err := RequireTcpOutboundTransport(u, inner)
	if err != nil {
		return nil, err
	}

	concurrency, err := strconv.Atoi(u.Query().Get("concurrency"))
	if concurrency <= 0 || err != nil {
		concurrency = 1
	}

	return &muxOutboundTransport{
		inner:     tInner,
		sessions:  make([]unsafe.Pointer, concurrency),
		sessionMu: make([]sync.Mutex, concurrency),
	}, nil
}

func (m *muxOutboundTransport) OutboundTransportName() string {
	return muxTransportName
}

func (m *muxOutboundTransport) OpenConnection() (net.Conn, error) {
	sess, err := m.getSession()
	if err != nil {
		return nil, err
	}

	stream, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, err
	}
	return stream, nil
}

func (m *muxOutboundTransport) getSession() (*yamux.Session, error) {
	i := rand.Intn(len(m.sessions))
	sess := (*yamux.Session)(atomic.LoadPointer(&m.sessions[i]))
	if sess == nil || sess.IsClosed() {
		m.sessionMu[i].Lock()
		defer m.sessionMu[i].Unlock()

		sess = (*yamux.Session)(m.sessions[i])
		if sess == nil || sess.IsClosed() {
			newConn, err := m.inner.OpenConnection()
			if err != nil {
				return nil, err
			}
			sess, err = yamux.Client(newConn, yamux.DefaultConfig())
			if err != nil {
				newConn.Close()
				return nil, err
			}
			m.sessions[i] = unsafe.Pointer(sess)
		}
	}

	return sess, nil
}
