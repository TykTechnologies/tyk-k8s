package ca

import (
	"github.com/cloudflare/cfssl/csr"
	"os"
	"testing"
)

// Requires a CFFSL server to be running
func TestCA_GenerateSSLCert(t *testing.T) {
	host := os.Getenv("CFFSL_TEST_SERVER")
	key := os.Getenv("CFFSL_TEST_KEY")
	if host == "" || key == "" {
		log.Warn("CFFSL_TEST_SERVER or CFFSL_TEST_KEY unset, skipping TestCA_GenerateSSLCert")
		return
	}

	ca := Client{
		CA: &Config{
			Addr: host,
			Key:  key,
			DefaultKeyRequest: &csr.KeyRequest{
				A: "rsa",
				S: 4096,
			},
		},
	}

	_, err := ca.GenerateCert("Dingbat Boobledroog")
	if err != nil {
		t.Fatal(err)
	}
}
