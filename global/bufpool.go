package global

import (
	"sync"
)

var BufPool BufferPool

func init() {
	BufPool = NewBufPool(64, 65536)
}

type BufferPool interface {
	Get(size int) []byte
	Put(b []byte)
}

type defaultBufPool struct {
	minExp int
	maxExp int
	bufs   []sync.Pool
}

func NewBufPool(minSize, maxSize uint32) *defaultBufPool {
	minExp := log2(minSize)
	maxExp := log2(maxSize)
	bp := &defaultBufPool{
		minExp: minExp,
		maxExp: maxExp,
		bufs:   make([]sync.Pool, maxExp-minExp+1),
	}
	for i := range bp.bufs {
		size := 1 << (minExp + i)
		bp.bufs[i].New = func() interface{} {
			return make([]byte, size)
		}
	}
	return bp
}

func log2(x uint32) int {
	var multiplyDeBruijnBitPosition = [32]int{
		0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
		8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31,
	}
	v := x
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	result := multiplyDeBruijnBitPosition[(v*0x07c4acdd)>>27]

	if x <= (1 << result) {
		return result
	} else {
		return result + 1
	}
}

func (bp *defaultBufPool) Get(size int) []byte {
	exp := log2(uint32(size))
	if exp > bp.maxExp {
		return make([]byte, size)
	}
	if exp < bp.minExp {
		exp = bp.minExp
	}

	return bp.bufs[exp-bp.minExp].Get().([]byte)[:size]
}

func (bp *defaultBufPool) Put(b []byte) {
	exp := log2(uint32(cap(b)))
	if exp > bp.maxExp || exp < bp.minExp || cap(b) != (1<<exp) {
		return
	}

	b = b[:cap(b)]
	bp.bufs[exp-bp.minExp].Put(b)
}
