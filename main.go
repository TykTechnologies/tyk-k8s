package main

import (
	"flag"
	"github.com/TykTechnologies/tyk-k8s/cmd"
)

func main() {
	flag.Parse()
	cmd.Execute()
}
