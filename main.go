package main

import (
	"flag"
	"github.com/TykTechnologies/tyk-k8s/cmd"
)

// TODO: replace glog, it's poo

func main() {
	flag.Parse()
	cmd.Execute()
}
