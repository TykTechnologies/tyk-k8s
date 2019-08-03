package cmd

import (
	"strings"

	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Command contains a logger.
type Command struct {
	log logger.Entry
}

// New initializes a new Command.
func New(getLogger func(modName string) logger.Entry) Command {
	return Command{log: getLogger("main")}
}

// Execute the commands.
func (c Command) Execute() {
	var cfgFile string
	cobra.OnInitialize(c.initConfig(cfgFile))

	rootCmd := c.newRootCmd()
	startCmd := c.newStartCmd()

	rootCmd.AddCommand(startCmd)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tyk-k8s-controller.yaml)")

	if err := rootCmd.Execute(); err != nil {
		c.log.Fatal(err)
	}
}

// initConfig returns a func that reads in config file and ENV variables if set.
func (c Command) initConfig(cfgFile string) func() {
	return func() {
		if err := setConfig(cfgFile); err != nil {
			c.log.Fatal(err)
		}

		viper.SetEnvPrefix("tk8s")
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		viper.AutomaticEnv() // read in environment variables that match

		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err != nil {
			c.log.Fatal(err)
		}

		// workaround because viper does not treat env vars the same as other config
		for _, key := range viper.AllKeys() {
			val := viper.Get(key)
			viper.Set(key, val)
		}

		c.log.Infof("Using config file: %v", viper.ConfigFileUsed())
		tyk.Init(nil)
	}
}

func setConfig(cfgFile string) error {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		// Search config in home directory with name ".tyk-k8s-controller" (without extension).
		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.AddConfigPath("/etc/tyk-k8s")
		viper.SetConfigName("tyk-k8s")
	}

	return nil
}
