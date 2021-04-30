package util

import (
	"sync"
)

var BufPool *bufPool

func init() {
	BufPool = newBufPool(64, 65536)
}

type bufPool struct {
	minExp int
	maxExp int
	bufs   []sync.Pool
}

func newBufPool(minSize, maxSize int) *bufPool {
	minExp := log2(minSize)
	maxExp := log2(maxSize)
	bp := &bufPool{
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

func log2(x int) int {
	result := 0
	for x > 1 {
		x >>= 1
		result += 1
	}

	if x <= (1 << result) {
		return result
	} else {
		return result + 1
	}
}

func (bp *bufPool) Get(size int) []byte {
	exp := log2(size)
	if exp > bp.maxExp {
		return make([]byte, size)
	}
	if exp < bp.minExp {
		exp = bp.minExp
	}

	return bp.bufs[exp-bp.minExp].Get().([]byte)[:size]
}

func (bp *bufPool) Put(b []byte) {
	exp := log2(cap(b))
	if exp > bp.maxExp || exp < bp.minExp || cap(b) != (1<<exp) {
		return
	}

	b = b[:cap(b)]
	bp.bufs[exp-bp.minExp].Put(b)
}
