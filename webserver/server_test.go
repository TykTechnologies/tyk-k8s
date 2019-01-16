package webserver

import (
	"net/http"
	"testing"
)

func TestServer(t *testing.T) {
	Server().Config(nil)
	Server().AddRoute("GET", "/hello", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	go Server().Start()

	res, err := http.Get("http://localhost:9797/hello")
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != 200 {
		t.Fatalf("expected code: %v got: %v", 200, res.StatusCode)
	}

	err = Server().Stop()
	if err != nil {
		t.Fatal(err)
	}

	res, err = http.Get("http://localhost:9797/hello")
	if err == nil {
		t.Fatal(err)
	}
}
