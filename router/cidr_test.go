package router

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
)

//func BenchmarkCIDRLoad(b *testing.B) {
//	lines, err := readLinesFromFile("chinaip.txt")
//	if err != nil {
//		b.Fatal(err)
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		ranger := cidranger.NewPCTrieRanger()
//		for _, line := range lines {
//			if len(line) > 0 {
//				if _, cidr, err := net.ParseCIDR(line); err == nil {
//					if err := ranger.Insert(cidranger.NewBasicRangerEntry(*cidr)); err != nil {
//						b.Fatal(err)
//					}
//				}
//			}
//		}
//	}
//}

func BenchmarkCIDRLoad2(b *testing.B) {
	lines, err := readLinesFromFile("chinaip.txt")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidrs := map[uint64]struct{}{}
		for _, line := range lines {
			if len(line) > 0 {
				if _, cidr, err := net.ParseCIDR(line); err == nil {
					ip4 := cidr.IP.To4()
					prefix, _ := cidr.Mask.Size()
					cidrInt := uint64(ip4[0])<<56 + uint64(ip4[1])<<48 + uint64(ip4[2])<<40 + uint64(ip4[3])<<32 + uint64(prefix)
					cidrs[cidrInt] = struct{}{}
				}
			}
		}
	}
}

func BenchmarkCIDRLoad3(b *testing.B) {
	lines, err := readLinesFromFile("chinaip.txt")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidrs := map[uint64]struct{}{}
		for _, line := range lines {
			ipAndPrefix := strings.Split(line, "/")
			if len(ipAndPrefix) != 2 {
				continue
			}
			prefix, err := strconv.Atoi(ipAndPrefix[1])
			if err != nil {
				continue
			}
			ip := net.ParseIP(ipAndPrefix[0])
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			cidrInt := uint64(ip4[0])<<56 + uint64(ip4[1])<<48 + uint64(ip4[2])<<40 + uint64(ip4[3])<<32 + uint64(prefix)
			cidrs[cidrInt] = struct{}{}
		}
	}
}

func BenchmarkCIDRLoad4(b *testing.B) {
	lines, err := readLinesFromFile("chinaip.txt")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidrs := make([]uint64, len(lines))
		for i, line := range lines {
			ipAndPrefix := strings.Split(line, "/")
			if len(ipAndPrefix) != 2 {
				continue
			}
			prefix, err := strconv.Atoi(ipAndPrefix[1])
			if err != nil {
				continue
			}
			ip := net.ParseIP(ipAndPrefix[0])
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			cidrInt := uint64(ip4[0])<<56 + uint64(ip4[1])<<48 + uint64(ip4[2])<<40 + uint64(ip4[3])<<32 + uint64(prefix)
			cidrs[i] = cidrInt
		}
		sort.Slice(cidrs, func(i, j int) bool {
			return cidrs[i] < cidrs[j]
		})
	}
}
