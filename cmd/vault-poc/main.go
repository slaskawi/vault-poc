package main

import (
	"fmt"

	"github.com/slaskawi/vault-poc/pkg/vault-poc/csi/provider"
)

var Quit = make(chan struct{})

func main() {
	fmt.Println("Hello world")
	server, err := provider.NewMocKCSIProviderServer("my-awesome-provider")
	if err != nil {
		panic(fmt.Sprintf("Could not create the server, %v", err))
	}
	server.SetObjects(map[string]string{"my-secret-key": "my-secret-value"})
	err = server.Start()
	if err != nil {
		panic(fmt.Sprintf("Could not start the server, %v", err))
	}
	<-Quit
}
