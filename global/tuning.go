package global

import (
	"log"
	"runtime"
	"runtime/debug"
)

func UseDefaultLogger() {
	Stdout = log.Default()
	Stderr = log.Default()
}

func DisableBufPool() {
	BufPool = NewBufPool(0, 0)
}

func SetGOMAXPROCS(value int) {
	runtime.GOMAXPROCS(value)
}

func SetGCPercent(percent int) {
	debug.SetGCPercent(percent)
}

func FreeOSMemory() {
	debug.FreeOSMemory()
}
