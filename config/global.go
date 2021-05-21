package config

import "time"

var (
	FreeMemoryInterval = 0
	LastMemoryFree     = int64(0)
	ConnBufSize        = 4 * 1024
	UdpMaxLength       = 2 * 1024
	TcpStreamTimeout   = 5 * time.Minute
	UdpStreamTimeout   = 2 * time.Minute
	TlsCertVerifier    func(serverName string, certs [][]byte) bool
)

func SetFreeMemoryInterval(interval int) {
	LastMemoryFree = time.Now().Unix()
	FreeMemoryInterval = interval
}

func SetTcpStreamTimeout(seconds int) {
	TcpStreamTimeout = time.Duration(seconds) * time.Second
}

func SetUdpStreamTimeout(seconds int) {
	UdpStreamTimeout = time.Duration(seconds) * time.Second
}
