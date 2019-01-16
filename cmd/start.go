package cmd

import (
	"github.com/TykTechnologies/tyk-k8s/injector"
	"github.com/TykTechnologies/tyk-k8s/webserver"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
			glog.Fatalf("no Server entry found in config file: %v", err)
		}

		// init config for the server
		webserver.Server().Config(sConf)

		for _, a := range args {
			switch a {
			case "inject", "injector", "sidecar":
				whConf := &injector.Config{}
				err := viper.UnmarshalKey("Injector", whConf)
				if err != nil {
					glog.Fatalf("couldn't read injector config: %v", err)
				}
				whs := &injector.WebhookServer{
					SidecarConfig: whConf,
				}

				webserver.Server().AddRoute("POST", "/inject", whs.Serve)
			case "ingress", "ing":
				glog.Fatal("not implemented")
				//TODO: add ingress controller
			default:
				glog.Error("use arguments like 'inject' or 'ingress' to start services")
				return

			}
		}

		webserver.Server().Start()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
