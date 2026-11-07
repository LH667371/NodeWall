package main

import nwruntime "nodewall/internal/runtime"

func main() {
	if err := nwruntime.RunAgent(); err != nil {
		panic(err)
	}
}
