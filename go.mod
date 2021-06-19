module github.com/DeepAQ/mut

go 1.16

require (
	github.com/hashicorp/yamux v0.0.0-20210316155119-a95892c5f864
	github.com/lucas-clemente/quic-go v0.21.1
	golang.org/x/mobile v0.0.0-20210614202936-7c8f154d1008 // indirect
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
)

replace golang.org/x/net => github.com/DeepAQ/golang-net v0.0.0-20210615163537-2a873e64d425
