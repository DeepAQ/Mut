package dns

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strconv"
	"testing"
	"time"
)

func startMockDnsServer() string {
	name := dnsmessage.MustNewName("testdomain.com.")
	ip := [4]byte{1, 2, 3, 4}
	conn, _ := net.ListenPacket("udp", "127.0.0.1:")
	go func() {
		buf := make([]byte, udpPacketSize)
		for {
			n, rAddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			parser := dnsmessage.Parser{}
			header, _ := parser.Start(buf[:n])
			header.Response = true
			header.RCode = dnsmessage.RCodeSuccess
			builder := dnsmessage.NewBuilder(buf[:0], header)
			builder.EnableCompression()
			builder.StartAnswers()
			builder.AResource(dnsmessage.ResourceHeader{
				Name:   name,
				Type:   dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				TTL:    0,
				Length: 1,
			}, dnsmessage.AResource{A: ip})
			buf2, _ := builder.Finish()
			conn.WriteTo(buf2, rAddr)
		}
	}()
	fmt.Println("mock dns server started at " + conn.LocalAddr().String())
	return conn.LocalAddr().String()
}

func TestUdpClient(t *testing.T) {
	server := startMockDnsServer()
	r := NewCustomResolver(udpPacketSize, NewUDPClient(server, 1*time.Second))
	r.Lookup("testdomain.com")
	ip, err := r.Lookup("testdomain.com")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "1.2.3.4" {
		t.Fatal("wrong result")
	}
}

func BenchmarkUdpClient(b *testing.B) {
	server := startMockDnsServer()
	r := NewCustomResolver(udpPacketSize, NewUDPClient(server, 1*time.Second))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Lookup("testdomain.com"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDohClient(t *testing.T) {
	client := NewCustomResolver(dohPacketSize, NewDoHClient("223.5.5.5/dns-query", 2*time.Second))
	ip, err := client.Lookup("api.vc.bilibili.com")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(ip.String())
}

func BenchmarkFakeIpPool(b *testing.B) {
	server := startMockDnsServer()
	r := NewCustomResolver(udpPacketSize, NewUDPClient(server, 1*time.Second))
	r.localAddr = "127.0.0.1:8053"
	r.useFakeIp = true
	r.listenLocal()
	client := NewUDPClient("127.0.0.1:8053", 1*time.Second)
	buf := make([]byte, udpPacketSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if q, err := queryToWire(buf, strconv.Itoa(i%100), dnsmessage.TypeA); err == nil {
			client.RoundTrip(q)
		} else {
			b.Fatal(err)
		}
	}
}
