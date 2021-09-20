package main

import (
	"fmt"

	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/slaskawi/vault-poc/pkg/vault-poc/csi/provider"
)

var Quit = make(chan struct{})

func main() {
	fmt.Println("Hello world")
	server, err := provider.NewMocKCSIProviderServer("/provider/vault-poc.sock")
	if err != nil {
		panic(fmt.Sprintf("Could not create the server, %v", err))
	}
	server.SetObjects(map[string]string{"my-secret-key": "v1"})
	server.SetFiles([]*v1alpha1.File{
		{
			Path:     "my-secret-key",
			Mode:     0644,
			Contents: []byte("my-secret-value"),
		},
	})
	err = server.Start()
	if err != nil {
		panic(fmt.Sprintf("Could not start the server, %v", err))
	}
	<-Quit
}
