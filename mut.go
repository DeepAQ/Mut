package main

import (
	"fmt"
	"github.com/DeepAQ/mut/core"
	"github.com/DeepAQ/mut/util"
	"os"
)

func main() {
	fmt.Println("Mut [Multi-usage tunnel], a DeepAQ Labs project")
	builder := core.InstanceBuilder{}
	builder.AddArgs(os.Args[1:])
	instance, err := builder.Create()
	if err != nil {
		util.Stderr.Fatalln("[mut] " + err.Error())
	}
	instance.Run()
}
