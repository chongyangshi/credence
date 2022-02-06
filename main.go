package main

import (
	"log"

	"github.com/chongyangshi/credence/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalf("credence could not supply the credentials requested, error: %+v", err)
	}
}
