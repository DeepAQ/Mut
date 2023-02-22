module github.com/DeepAQ/mut

go 1.18

require (
	github.com/hashicorp/yamux v0.0.0-20211028200310-0bc27b27de87
	github.com/lucas-clemente/quic-go v0.27.0
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
	gvisor.dev/gvisor v0.0.0-20220319025644-e785bfc153f5
)

require (
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/marten-seemann/qpack v0.2.1 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.5 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.1 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.1 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/text v0.3.8 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
)

replace golang.org/x/net => github.com/DeepAQ/golang-net v0.0.0-20220415083153-e1dc1ab89722
