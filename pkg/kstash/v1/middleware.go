package v1

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// WithUnaryLogging adds logging middleware for unary server requests.
func WithUnaryLogging(log logr.Logger) grpc.ServerOption {
	return grpc.UnaryInterceptor(UnaryServerLogger(log))
}

// WithStreamLogging adds logging middleware for stream server requests.
func WithStreamLogging(log logr.Logger) grpc.ServerOption {
	return grpc.StreamInterceptor(StreamServerLogger(log))
}

// UnaryServerLogger is the middleware for unary server logging.
func UnaryServerLogger(log logr.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		start := time.Now()
		resp, err = handler(ctx, req)
		duration := time.Since(start)
		code := status.Code(err)

		log.Info(
			"request",
			"method", info.FullMethod,
			"status", code.String(),
			"duration", duration,
		)

		return
	}
}

// StreamServerLogger is the middleware for stream server logging.
func StreamServerLogger(log logr.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		duration := time.Since(start)
		code := status.Code(err)

		log.Info(
			"stream",
			"method", info.FullMethod,
			"status", code.String(),
			"duration", duration,
		)

		return err
	}
}
