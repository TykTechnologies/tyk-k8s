package main

import (
	"flag"

	"github.com/TykTechnologies/tyk-k8s/cmd"
	"github.com/TykTechnologies/tyk-k8s/logger"
)

// TODO: replace glog, it's poo

func main() {
	flag.Parse()
	c := cmd.New(logger.GetLogger)
	c.Execute()
}
