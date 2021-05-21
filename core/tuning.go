package core

import (
	"github.com/DeepAQ/mut/util"
	"log"
	"runtime/debug"
)

func UseDefaultLogger() {
	util.Stdout = log.Default()
	util.Stderr = log.Default()
}

func DisableBufPool() {
	util.BufPool = util.NewBufPool(0, 0)
}

func SetGCPercent(percent int) {
	debug.SetGCPercent(percent)
}

func FreeOSMemory() {
	debug.FreeOSMemory()
}
