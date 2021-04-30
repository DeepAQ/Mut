package debug

import (
	"context"
	"errors"
	"github.com/DeepAQ/mut/util"
	"net/http"
	_ "net/http/pprof"
	"strconv"
)

type Debuggable interface {
	Debug() string
}

var (
	Dns Debuggable
)

func init() {
	registerDebugHandler("dns", &Dns)
}

func registerDebugHandler(name string, d *Debuggable) {
	http.HandleFunc("/debug/mut/"+name, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		var s string
		if *d == nil {
			s = name + " not initialized"
		} else {
			s = (*d).Debug()
		}
		w.Write([]byte(s))
	})
}

func StartDebugServer(ctx context.Context, port int) {
	go func() {
		addr := "localhost:" + strconv.Itoa(port)
		server := http.Server{Addr: addr}
		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-cancelCtx.Done():
				util.Stdout.Println("[debug] shutting down server")
				server.Shutdown(cancelCtx)
			}
		}()

		util.Stdout.Println("[debug] listening on " + addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			util.Stderr.Println("[debug] failed to serve: " + err.Error())
		}
		cancel()
	}()
}
