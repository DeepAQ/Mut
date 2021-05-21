package dns

import (
	"encoding/binary"
	"errors"
	"github.com/DeepAQ/mut/util"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	errMaxConcurrency = errors.New("too many concurrent requests")
	errTimeout        = errors.New("dns request timed out")
)

type udpRequest struct {
	buf  []byte
	resc chan []byte
}

type udpClient struct {
	server  string
	conn    unsafe.Pointer //*net.Conn
	connMu  sync.Mutex
	reqId   uint32
	reqs    sync.Map //map[uint16]udpRequest
	timeout time.Duration
}

func NewUDPClient(server string, timeout time.Duration) *udpClient {
	if strings.IndexByte(server, ':') < 0 {
		server += ":53"
	}
	return &udpClient{
		server:  server,
		reqId:   rand.Uint32(),
		reqs:    sync.Map{},
		timeout: timeout,
	}
}

func (u *udpClient) RoundTrip(req []byte) ([]byte, error) {
	resc := make(chan []byte, 1)
	ur := udpRequest{
		buf:  req,
		resc: resc,
	}
	var reqId uint16
	for i := 0; ; i++ {
		reqId = uint16(atomic.AddUint32(&u.reqId, 1) & (1<<16 - 1))
		if _, exists := u.reqs.LoadOrStore(reqId, ur); !exists {
			break
		}
		if i >= 1<<16-1 {
			return nil, errMaxConcurrency
		}
	}
	defer func() {
		u.reqs.Delete(reqId)
	}()
	originalReqId := binary.BigEndian.Uint16(req[:2])
	binary.BigEndian.PutUint16(req[:2], reqId)

	conn := atomic.LoadPointer(&u.conn)
	if conn == nil {
		u.connMu.Lock()
		if u.conn == nil {
			newConn, err := net.Dial("udp", u.server)
			if err != nil {
				u.connMu.Unlock()
				return nil, err
			}
			go u.readLoop(newConn)
			conn = unsafe.Pointer(&newConn)
			u.conn = conn
		}
		u.connMu.Unlock()
	}
	if _, err := (*(*net.Conn)(conn)).Write(req); err != nil {
		return nil, err
	}
	timeOut := time.NewTimer(u.timeout)
	select {
	case result := <-resc:
		timeOut.Stop()
		binary.BigEndian.PutUint16(result[:2], originalReqId)
		return result, nil
	case <-timeOut.C:
		return nil, errTimeout
	}
}

func (u *udpClient) readLoop(conn net.Conn) {
	buf := util.BufPool.Get(udpPacketSize)
	defer util.BufPool.Put(buf)

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			atomic.StorePointer(&u.conn, nil)
			return
		}
		reqId := binary.BigEndian.Uint16(buf[:2])
		if v, ok := u.reqs.Load(reqId); ok {
			ur := v.(udpRequest)
			ur.buf = ur.buf[:n]
			copy(ur.buf, buf)
			select {
			case ur.resc <- ur.buf:
			default:
			}
		}
	}
}
