package debug

import (
	"github.com/DeepAQ/mut/global"
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

func StartDebugServer(port int) {
	go func() {
		addr := "localhost:" + strconv.Itoa(port)
		server := http.Server{Addr: addr}

		global.Stdout.Println("[debug] listening on " + addr)
		if err := server.ListenAndServe(); err != nil {
			global.Stderr.Println("[debug] failed to serve: " + err.Error())
		}
	}()
}
