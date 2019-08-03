package cmd

import (
	"github.com/spf13/cobra"
)

func (c Command) newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tyk-k8s",
		Short: "Tyk controller utility for kubernetes",
		Long: `Provides a sidecar injector web service and an ingress
	controller service, start the controller with:

		tyk-k8s start

	or you can start both by chaining the arguments`,
	}
}
