package debug

import (
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
)

func init() {
	http.HandleFunc("/debug/heapdump", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.CreateTemp("", "heapdump")
		if err != nil {
			goto err
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()

		debug.FreeOSMemory()
		debug.WriteHeapDump(f.Fd())
		if _, err := f.Seek(0, 0); err != nil {
			goto err
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		io.Copy(w, f)
		return

	err:
		errBytes := []byte(err.Error())
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(errBytes)))
		w.WriteHeader(500)
		w.Write(errBytes)
		return
	})
}
