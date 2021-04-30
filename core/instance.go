package core

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/DeepAQ/mut/debug"
	"github.com/DeepAQ/mut/dns"
	"github.com/DeepAQ/mut/inbound"
	"github.com/DeepAQ/mut/outbound"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/util"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

type Instance interface {
	Start()
	Stop()
	Run()
}

type instance struct {
	ctx  context.Context
	stop context.CancelFunc

	debugPort int
	inAddr    string
	inbound   inbound.Inbound
	router    router.Router
	resolver  dns.Resolver
}

func createInstance(args []string) (*instance, error) {
	stdinFlag := flag.Bool("stdin", false, "receive other arguments from stdin")
	inFlag := flag.String("in", "", "inbound config, protocol://[username:password@]host:port[/?option=value...]")
	outFlag := flag.String("out", "", "outbound config, protocol://[username:password@]host:port[/?option=value...]")
	dnsFlag := flag.String("dns", "", "dns config, protocol://host:port[/path...]")
	rulesFlag := flag.String("rules", "", "router rules, rule1:action1[;rule2:action2...][;final:action]")
	debugFlag := flag.Int("debug", 0, "localhost debug port")
	flag.CommandLine.Parse(args)
	if *stdinFlag {
		fmt.Println("Receiving arguments from stdin")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		flag.CommandLine.Parse(strings.Split(strings.TrimSpace(line), " "))
	}

	var resolver dns.Resolver = dns.System
	if len(*dnsFlag) > 0 {
		dnsUrl, err := url.Parse(*dnsFlag)
		if err != nil {
			return nil, errors.New("failed to parse dns config: " + err.Error())
		}
		resolver, err = dns.CreateResolver(dnsUrl)
		if err != nil {
			return nil, errors.New("failed to initialize dns resolver: " + err.Error())
		}
	}
	debug.Dns = resolver

	outUrl, err := url.Parse(*outFlag)
	if err != nil {
		return nil, errors.New("failed to parse outbound config: " + err.Error())
	}
	out, err := outbound.CreateOutbound(outUrl, resolver)
	if err != nil {
		return nil, errors.New("failed to initialize outbound: " + err.Error())
	}

	rt, err := router.NewRouter(*rulesFlag, resolver, out)
	if err != nil {
		return nil, errors.New("failed to initialize router: " + err.Error())
	}

	inUrl, err := url.Parse(*inFlag)
	if err != nil {
		return nil, errors.New("failed to parse inbound config: " + err.Error())
	}
	in, err := inbound.CreateInbound(inUrl, rt)
	if err != nil {
		return nil, errors.New("failed to initialize inbound: " + err.Error())
	}

	ctx, stop := context.WithCancel(context.Background())
	instance := &instance{
		ctx:       ctx,
		stop:      stop,
		debugPort: *debugFlag,
		inAddr:    inUrl.Host,
		inbound:   in,
		router:    rt,
		resolver:  resolver,
	}
	return instance, nil
}

func (i *instance) Start() {
	go i.Run()
}

func (i *instance) Stop() {
	i.stop()
}

func (i *instance) Run() {
	if i.debugPort > 0 {
		debug.StartDebugServer(i.ctx, i.debugPort)
	}
	i.resolver.Start(i.ctx)

	listener, err := net.Listen("tcp", i.inAddr)
	if err != nil {
		util.Stderr.Println("[tcp] failed to listen on " + i.inAddr + ": " + err.Error())
		return
	}
	util.Stdout.Println("[" + i.inbound.Name() + "] listening on " + i.inAddr)

	cancelCtx, cancel := context.WithCancel(i.ctx)
	go func() {
		select {
		case <-cancelCtx.Done():
			listener.Close()
		}
		util.Stdout.Println("[" + i.inbound.Name() + "] listener on " + i.inAddr + " stopped")
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				util.Stderr.Println("[" + i.inbound.Name() + "] failed to accept new connection: " + err.Error())
			}
			cancel()
			return
		}

		go func() {
			err := i.inbound.ServeConn(conn, func(stream *inbound.TcpStream) {
				dConn, err, outName, realAddr := i.router.DialTcp(stream.TargetAddr)
				if err != nil {
					stream.Conn.Close()
					util.Stderr.Println("[" + stream.Protocol + "] " + stream.ClientAddr + " -" + outName + "-> " + realAddr + " error: " + err.Error())
					return
				}

				util.Stdout.Println("[" + stream.Protocol + "] " + stream.ClientAddr + " <-" + outName + "-> " + realAddr)
				go relay(stream.Conn, dConn)
				relay(dConn, stream.Conn)
				util.Stdout.Println("[" + stream.Protocol + "] " + stream.ClientAddr + " >-" + outName + "-< " + realAddr)
			})
			if err != nil {
				conn.Close()
				util.Stderr.Println("[" + i.inbound.Name() + "] failed to serve conn from " + conn.RemoteAddr().String() + ": " + err.Error())
			}
		}()
	}
}

func relay(src io.ReadCloser, dst io.WriteCloser) {
	defer src.Close()
	defer dst.Close()
	buf := util.BufPool.Get(4 * 1024)
	defer util.BufPool.Put(buf)
	io.CopyBuffer(dst, src, buf)
}
