package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "credence",
		Short: "credence is a Kubernetes local credentials agent resistant to phishing and supply-chain attacks",
		Long:  "credence is a Kubernetes local credentials agent using system keychain and hardware token devices to achieve resistance against phishing and supply-chain attacks",
	}

	debugFlag bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debugFlag, "debug", "d", false, "provide verbose output for debugging")
}

func Execute() error {
	return rootCmd.Execute()
}
