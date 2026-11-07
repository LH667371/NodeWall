package main

import nwruntime "nodewall/internal/runtime"

func main() {
	if err := nwruntime.RunServer(); err != nil {
		panic(err)
	}
}
