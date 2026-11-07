package main

import (
	"os"

	"nodewall/internal/cli"
	nwruntime "nodewall/internal/runtime"
)

func main() {
	cli.SetRunners(nwruntime.RunServer, nwruntime.RunAgent)
	cli.MustRun(os.Args[1:])
}
