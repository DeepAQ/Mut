package main

import (
	"github.com/DeepAQ/mut/core"
	"github.com/DeepAQ/mut/global"
	"os"
)

func main() {
	launcher := core.Launcher{}
	launcher.AddArgs(os.Args[1:])
	if err := launcher.Run(); err != nil {
		global.Stderr.Fatalln("[mut] " + err.Error())
	}
}
