package webserver

import (
	"context"
	"crypto/sha256"
	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"time"
)

var server *WebServer

// WebServer config
type Config struct {
	Addr     string `yaml:"addr"`     // webhook server port
	CertFile string `yaml:"certFile"` // path to the x509 certificate for https
	KeyFile  string `yaml:"keyFile"`  // path to the x509 private key matching `CertFile`
}

type WebServer struct {
	stopCh chan struct{}
	mux    *mux.Router
	cfg    *Config
	srv    *http.Server
}

func newServer(cfg *Config) *WebServer {
	s := &WebServer{
		cfg:    cfg,
		mux:    mux.NewRouter(),
		stopCh: make(chan struct{}),
	}

	return s
}

func (s *WebServer) AddRoute(method string, route string, handler func(http.ResponseWriter, *http.Request)) {
	if s.mux == nil {
		s.mux = mux.NewRouter()
	}

	s.mux.HandleFunc(route, handler).Methods(method)
}

func (s *WebServer) Config(cfg *Config) {
	if cfg == nil {
		glog.Info("using default config on port 9797")
		s.cfg = &Config{
			Addr: ":9797",
		}
		return
	}

	s.cfg = cfg
}

func (s *WebServer) Start() {
	if s.srv != nil {
		glog.Warning("server already started")
		return
	}

	srv := &http.Server{
		Addr:    s.cfg.Addr,
		Handler: s.mux,
	}

	s.srv = srv

	if s.cfg.CertFile == "" {
		glog.Error(srv.ListenAndServe())
	} else {
		glog.Error(srv.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile))
	}

}

func (s *WebServer) Stop() error {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err := s.srv.Shutdown(ctx)
	if err != nil {
		return err
	}
	return nil
}

func Server() *WebServer {
	if server == nil {
		server = newServer(nil)
	}

	return server
}

func ReadConfigFile(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
