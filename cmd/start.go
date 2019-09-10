package cmd

import (
	"github.com/TykTechnologies/tyk-k8s/ca"
	"github.com/TykTechnologies/tyk-k8s/ingress"
	"github.com/TykTechnologies/tyk-k8s/injector"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/webserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"sync"
)

var log = logger.GetLogger("main")

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the controller",
	Long:  `Starts the controller.`,
	Run: func(cmd *cobra.Command, args []string) {
		sConf := &webserver.Config{}
		err := viper.UnmarshalKey("Server", sConf)
		if err != nil {
			log.Fatalf("no Server entry found in config file: %v", err)
		}
		webserver.Server().Config(sConf)

		// Web server mutating webhook
		whConf := &injector.Config{}
		err = viper.UnmarshalKey("Injector", whConf)
		if err != nil {
			log.Fatalf("couldn't read injector config: %v", err)
		}

		// CA configuration
		caConf := &ca.Config{}
		err = viper.UnmarshalKey("CA", caConf)
		if err != nil {
			log.Fatalf("couldn't read CA config: %v", err)
		}

		whs := &injector.WebhookServer{
			SidecarConfig: whConf,
			CAConfig:      caConf,
		}

		if whConf.EnableMeshTLS {
			caClient, err := ca.New(caConf)
			if err != nil {
				log.Fatal("failed to init CA client: ", err)
			}

			whs.CAClient = caClient
		}

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

		WaitForCtrlC()

		err = webserver.Server().Stop()
		if err != nil {
			log.Error(err)
		}

		err = ingress.Controller().Stop()
		if err != nil {
			log.Error(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()
}
