package core

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/DeepAQ/mut/debug"
	"github.com/DeepAQ/mut/dns"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/inbound"
	"github.com/DeepAQ/mut/outbound"
	"github.com/DeepAQ/mut/router"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	stdinFlag = flag.Bool("stdin", false, "receive other arguments from stdin")
	inFlag    = flag.String("in", "", "inbound config, scheme://[username:password@]host:port[/?option=value...]")
	outFlag   = flag.String("out", "", "outbound config, scheme://[username:password@]host:port[/?option=value...]")
	dnsFlag   = flag.String("dns", "", "dns config, protocol://host:port[/path...]")
	rulesFlag = flag.String("rules", "", "router rules, rule1:action1[;rule2:action2...][;final:action]")
	debugFlag = flag.Int("debug", 0, "localhost debug port")
)

type instance struct {
	inbound   inbound.Inbound
	router    router.Router
	resolver  dns.Resolver
	debugPort int
}

func newInstance(args []string) (*instance, error) {
	fmt.Println("Mut [Multi-usage tunnel], a DeepAQ Labs project")
	flag.CommandLine.Parse(args)
	if *stdinFlag {
		fmt.Println("Receiving arguments from stdin")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		flag.CommandLine.Parse(strings.Split(strings.TrimSpace(line), " "))
	}

	var err error
	instance := &instance{
		debugPort: *debugFlag,
	}

	inUrl, err := url.Parse(*inFlag)
	if err != nil {
		return nil, errors.New("failed to parse inbound config: " + err.Error())
	}
	instance.inbound, err = inbound.CreateInbound(inUrl)
	if err != nil {
		return nil, errors.New("failed to initialize inbound: " + err.Error())
	}

	instance.resolver = dns.System
	if len(*dnsFlag) > 0 {
		dnsUrl, err := url.Parse(*dnsFlag)
		if err != nil {
			return nil, errors.New("failed to parse dns config: " + err.Error())
		}
		instance.resolver, err = dns.CreateResolver(dnsUrl)
		if err != nil {
			return nil, errors.New("failed to initialize dns resolver: " + err.Error())
		}
	}
	debug.Dns = instance.resolver

	outUrl, err := url.Parse(*outFlag)
	if err != nil {
		return nil, errors.New("failed to parse outbound config: " + err.Error())
	}
	out, err := outbound.CreateOutbound(outUrl, instance.resolver)
	if err != nil {
		return nil, errors.New("failed to initialize outbound: " + err.Error())
	}

	instance.router, err = router.NewRouter(*rulesFlag, instance.resolver, out)
	if err != nil {
		return nil, errors.New("failed to initialize router: " + err.Error())
	}

	return instance, nil
}

func (i *instance) Run() {
	if i.debugPort > 0 {
		debug.StartDebugServer(i.debugPort)
	}
	i.resolver.Start()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := i.inbound.Serve(i.router); err != nil {
			global.Stderr.Println("[" + i.inbound.Name() + "] failed to serve: " + err.Error())
		}
		wg.Done()
	}()
	wg.Wait()
}
