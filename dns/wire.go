package dns

import (
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
)

func queryToWire(buf []byte, host string, questionType dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, err
	}
	if name.Length > 0 && name.Data[name.Length-1] != '.' {
		name.Data[name.Length] = '.'
		name.Length += 1
	}

	builder := dnsmessage.NewBuilder(buf[:0], dnsmessage.Header{
		RecursionDesired: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  questionType,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func ipv4ResultFromWire(buf []byte) ([]net.IP, int, error) {
	parser := dnsmessage.Parser{}
	header, err := parser.Start(buf)
	if err != nil {
		return nil, 0, err
	}
	if !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, errors.New("dns query failed: " + header.RCode.String())
	}

	var ips []net.IP
	var ttl uint32
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}
	for {
		ah, err := parser.AnswerHeader()
		if err != nil {
			if err == dnsmessage.ErrSectionDone {
				break
			}
			return nil, 0, err
		}
		if ah.Type != dnsmessage.TypeA || ah.Class != dnsmessage.ClassINET {
			if err := parser.SkipAnswer(); err != nil {
				return nil, 0, err
			}
			continue
		}
		ar, err := parser.AResource()
		if err != nil {
			return nil, 0, err
		}
		ips = append(ips, ar.A[:])
		if ttl == 0 || ah.TTL < ttl {
			ttl = ah.TTL
		}
	}
	return ips, int(ttl), nil
}

func ipv4AnswerToWire(header dnsmessage.Header, question dnsmessage.Question, ip, ttl uint32, buf []byte) ([]byte, error) {
	header.Response = true
	header.Truncated = false
	header.RecursionAvailable = true
	header.RCode = dnsmessage.RCodeSuccess

	builder := dnsmessage.NewBuilder(buf[:0], header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if err := builder.AResource(dnsmessage.ResourceHeader{
		Name:  question.Name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   ttl,
	}, dnsmessage.AResource{
		A: [4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)},
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func writeServFail(buf []byte) []byte {
	buf[2] |= 0b10000000
	buf[2] &= 0b11111011
	buf[3] |= 0b10001111
	buf[3] &= 0b10010010
	buf[4] = 0
	buf[5] = 0
	buf[6] = 0
	buf[7] = 0
	buf[8] = 0
	buf[9] = 0
	buf[10] = 0
	buf[11] = 0
	return buf[:12]
}

func compressMessage(msg, buf []byte) ([]byte, error) {
	parser := dnsmessage.Parser{}
	header, err := parser.Start(msg)
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(buf[:0], header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	for {
		q, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		} else if err != nil {
			return nil, err
		}
		if err := builder.Question(q); err != nil {
			return nil, err
		}
	}

	processResources := func(startFunc func() error, headerFunc func() (dnsmessage.ResourceHeader, error)) error {
		if err := startFunc(); err != nil {
			return err
		}
		for {
			h, err := headerFunc()
			if err == dnsmessage.ErrSectionDone {
				break
			} else if err != nil {
				return err
			}
			r, err := parser.UnknownResource()
			if err != nil {
				return err
			}
			if err := builder.UnknownResource(h, r); err != nil {
				return err
			}
		}
		return nil
	}
	if err := processResources(builder.StartAnswers, parser.AnswerHeader); err != nil {
		return nil, err
	}
	if err := processResources(builder.StartAuthorities, parser.AuthorityHeader); err != nil {
		return nil, err
	}
	if err := processResources(builder.StartAdditionals, parser.AdditionalHeader); err != nil {
		return nil, err
	}
	return builder.Finish()
}
