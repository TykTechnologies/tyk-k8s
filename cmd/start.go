package cmd

import (
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
	Long: `Starts the controller with the specified modules as arguments,
e.g. tyk-k8s start ingress injector.

Each argument starts a different module and operation for the controller, 
the above example starts the sidecar injector and the tyk k8s ingress controller.`,
	Run: func(cmd *cobra.Command, args []string) {
		sConf := &webserver.Config{}
		err := viper.UnmarshalKey("Server", sConf)
		if err != nil {
			log.Fatalf("no Server entry found in config file: %v", err)
		}

		// init config for the server
		webserver.Server().Config(sConf)
		ingressStarted := false
		for _, a := range args {
			switch a {
			case "inject", "injector", "sidecar":
				whConf := &injector.Config{}
				err := viper.UnmarshalKey("Injector", whConf)
				if err != nil {
					log.Fatalf("couldn't read injector config: %v", err)
				}
				whs := &injector.WebhookServer{
					SidecarConfig: whConf,
				}

				webserver.Server().AddRoute("POST", "/inject", whs.Serve)
			case "ingress", "ing":
				ingressStarted = true
				ingress.NewController()
				err := ingress.Controller().Start()
				if err != nil {
					log.Fatal(err)
				}
				log.Info("ingress controller started")
			default:
				log.Error("use arguments like 'inject' or 'ingress' to start services")
				return

			}
		}

		go webserver.Server().Start()
		log.Info("web server started")

		WaitForCtrlC()

		err = webserver.Server().Stop()
		if err != nil {
			log.Error(err)
		}

		if ingressStarted {
			err = ingress.Controller().Stop()
			if err != nil {
				log.Error(err)
			}
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
