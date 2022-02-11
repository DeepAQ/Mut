package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"github.com/DeepAQ/mut/global"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	tlsTransportName = "tls"
)

var (
	errCertNotTrusted = errors.New("server certificate is not trusted")
	errNoCert         = errors.New("no certificate presented by server")
	errCertInvalid    = errors.New("server certificate exceeds validity bounds")
)

type TLSTransport interface {
	TLSConfig() *tls.Config
}

type tlsInboundTransport struct {
	inner     TcpInboundTransport
	tlsConfig *tls.Config
}

func NewTLSInboundTransport(u *url.URL, inner InboundTransport) (*tlsInboundTransport, error) {
	tInner, err := RequireTcpInboundTransport(u, inner)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(u.Query().Get("cert"), u.Query().Get("key"))
	if err != nil {
		return nil, err
	}

	return &tlsInboundTransport{
		inner: tInner,
		tlsConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
	}, nil
}

func (t *tlsInboundTransport) InboundTransportName() string {
	return tlsTransportName
}

func (t *tlsInboundTransport) Accept() (net.Conn, error) {
	conn, err := t.inner.Accept()
	if err != nil {
		return nil, err
	}

	return tls.Server(conn, t.tlsConfig), nil
}

func (t *tlsInboundTransport) Close() error {
	return t.inner.Close()
}

func (t *tlsInboundTransport) Addr() net.Addr {
	return t.inner.Addr()
}

func (t *tlsInboundTransport) TLSConfig() *tls.Config {
	return t.tlsConfig
}

type tlsOutboundTransport struct {
	inner     TcpOutboundTransport
	tlsConfig *tls.Config
}

func NewTLSOutboundTransport(u *url.URL, inner OutboundTransport) (*tlsOutboundTransport, error) {
	tInner, err := RequireTcpOutboundTransport(u, inner)
	if err != nil {
		return nil, err
	}

	serverName := u.Query().Get("host")
	if len(serverName) == 0 {
		serverName, _, _ = net.SplitHostPort(u.Host)
	}
	tlsConfig := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	alpn := u.Query().Get("alpn")
	if len(alpn) > 0 {
		tlsConfig.NextProtos = strings.Split(alpn, ",")
	}
	publicKey := u.Query().Get("public_key")
	if len(publicKey) > 0 {
		publicKeyBytes, err := hex.DecodeString(publicKey)
		if err != nil {
			return nil, err
		}

		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errNoCert
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errCertInvalid
			}
			if err := cert.VerifyHostname(serverName); err != nil {
				return err
			}

			var certPublicKeyBytes []byte
			switch pub := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				certPublicKeyBytes, err = asn1.Marshal(pub)
				if err != nil {
					return err
				}
			case *ecdsa.PublicKey:
				certPublicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
			case ed25519.PublicKey:
				certPublicKeyBytes = pub
			default:
				return errors.New("unknown public key type: " + reflect.TypeOf(pub).String())
			}

			if bytes.Compare(publicKeyBytes, certPublicKeyBytes) != 0 {
				return errors.New("server certificate public key validation failed, received public key: " + hex.EncodeToString(certPublicKeyBytes))
			}
			return nil
		}
	} else if global.TLSCertVerifier != nil {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if !global.TLSCertVerifier(serverName, rawCerts) {
				return errCertNotTrusted
			}
			return nil
		}
	}

	return &tlsOutboundTransport{
		inner:     tInner,
		tlsConfig: tlsConfig,
	}, nil
}

func (t *tlsOutboundTransport) OutboundTransportName() string {
	return tlsTransportName
}

func (t *tlsOutboundTransport) OpenConnection() (net.Conn, error) {
	conn, err := t.inner.OpenConnection()
	if err != nil {
		return nil, err
	}

	return tls.Client(conn, t.tlsConfig), nil
}

func (t *tlsOutboundTransport) TLSConfig() *tls.Config {
	return t.tlsConfig
}
