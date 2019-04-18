package tyk

import (
	"bytes"
	"github.com/spf13/viper"
	"testing"
)

func TestInit(t *testing.T) {
	viper.SetConfigFile("./test.yaml")
	err := viper.ReadConfig(bytes.NewReader([]byte(sampleConf)))
	if err != nil {
		t.Fatal(err)
	}

	Init(nil)
	newClient()

}

var sampleConf = `
Server:
  addr: ":9595"
  certFile: ""
  keyFile: ""
Tyk:
  url: "https://localhost:9696"
  secret: "set-by-env"
  org: "set-by-env"
  isGateway: true
  insecureSkipVerify: true
Injector:
  createRoutes: false

`
