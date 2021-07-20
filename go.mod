module github.com/DeepAQ/mut

go 1.16

require (
	github.com/hashicorp/yamux v0.0.0-20210707203944-259a57b3608c
	github.com/lucas-clemente/quic-go v0.21.2
	golang.org/x/mobile v0.0.0-20210716004757-34ab1303b554 // indirect
	golang.org/x/net v0.0.0-20210716203947-853a461950ff
	gvisor.dev/gvisor v0.0.0-20210716193733-566c23a60eea
)

replace golang.org/x/net => github.com/DeepAQ/golang-net v0.0.0-20210615163537-2a873e64d425
