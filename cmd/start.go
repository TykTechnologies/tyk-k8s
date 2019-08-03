package cmd

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/TykTechnologies/tyk-k8s/ingress"
	"github.com/TykTechnologies/tyk-k8s/injector"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/webserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func (c Command) newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "starts the controller",
		Long:  `Starts the controller.`,
		Run: func(cmd *cobra.Command, args []string) {
			startController(c.log)
		},
	}
}

func startController(log logger.Entry) {
	sConf := &webserver.Config{}
	err := viper.UnmarshalKey("Server", sConf)
	if err != nil {
		log.Fatalf("no Server entry found in config file: %v", err)
	}

	// Web server mutating webhook
	whConf := &injector.Config{}
	err = viper.UnmarshalKey("Injector", whConf)
	if err != nil {
		log.Fatalf("couldn't read injector config: %v", err)
	}

	whs := &injector.WebhookServer{
		SidecarConfig: whConf,
	}

	webserver.Server().Config(sConf)
	webserver.Server().AddRoute("POST", "/inject", whs.Serve)

	// Ingress controller
	ingress.NewController()
	err = ingress.Controller().Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("ingress controller started")

	go webserver.Server().Start()
	log.Info("web server started")

	waitForSignal()

	err = webserver.Server().Stop()
	if err != nil {
		log.Error(err)
	}

	err = ingress.Controller().Stop()
	if err != nil {
		log.Error(err)
	}
}

func waitForSignal() {
	var wg sync.WaitGroup
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	wg.Add(1)
	go func() {
		<-signalCh
		wg.Done()
	}()

	wg.Wait()
}
