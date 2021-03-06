package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/config"
	v1 "github.com/slaskawi/vault-poc/pkg/kstash/v1"
)

var (
	log  logr.Logger
	conf *config.Config
)

func main() {
	zapLog, _ := zap.NewDevelopment()
	log = zapr.NewLogger(zapLog)
	conf = config.Get()

	if err := listenGRPC(); err != nil {
		log.Error(err, "listening on gRPC port")
	}

	if err := listenREST(); err != nil {
		log.Error(err, "listening on REST port")
	}

	// wait until interrupt signal
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	<-stopCh

	// give servers a chance to gracefully shutdown
	time.Sleep(100 * time.Millisecond)
}

func listenGRPC() error {
	// initialize service
	v1Service, err := v1.NewKStash(log, conf)
	if err != nil {
		return err
	}

	// initialize gRPC server
	opts := []grpc.ServerOption{
		v1.WithUnaryLogging(log),
		v1.WithStreamLogging(log),
	}
	server := grpc.NewServer(opts...)
	apiv1.RegisterKStashServer(server, v1Service)

	// handle graceful shutdown
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	go func() {
		<-stopCh
		log.Info("shutting down gRPC server")
		server.GracefulStop()
	}()

	listener, err := net.Listen("tcp", ":"+conf.GrpcPort)
	if err != nil {
		return err
	}

	// start listening
	go func() {
		log.Info("gRPC server listening", "port", conf.GrpcPort)
		server.Serve(listener)
	}()

	return nil
}

func listenREST() error {
	ctx := context.Background()

	// initialize gRPC client
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err := apiv1.RegisterKStashHandlerFromEndpoint(ctx, mux, "localhost:"+conf.GrpcPort, opts)
	if err != nil {
		return err
	}

	// initialize REST server
	server := http.Server{
		Addr:    ":" + conf.RestPort,
		Handler: mux,
	}

	// handle graceful shutdown
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	go func() {
		<-stopCh
		log.Info("shutting down REST server")
		server.Shutdown(ctx)
	}()

	// start listening
	go func() {
		log.Info("REST server listening", "port", conf.RestPort)
		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error(err, "listening on REST port")
			}
		}
	}()

	return nil
}
