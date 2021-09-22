// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// KStashClient is the client API for KStash service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KStashClient interface {
	SystemRotate(ctx context.Context, in *SystemRotateRequest, opts ...grpc.CallOption) (*SystemRotateResponse, error)
	SystemStatus(ctx context.Context, in *SystemStatusRequest, opts ...grpc.CallOption) (*SystemStatusResponse, error)
}

type kStashClient struct {
	cc grpc.ClientConnInterface
}

func NewKStashClient(cc grpc.ClientConnInterface) KStashClient {
	return &kStashClient{cc}
}

func (c *kStashClient) SystemRotate(ctx context.Context, in *SystemRotateRequest, opts ...grpc.CallOption) (*SystemRotateResponse, error) {
	out := new(SystemRotateResponse)
	err := c.cc.Invoke(ctx, "/kstash.v1.KStash/SystemRotate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *kStashClient) SystemStatus(ctx context.Context, in *SystemStatusRequest, opts ...grpc.CallOption) (*SystemStatusResponse, error) {
	out := new(SystemStatusResponse)
	err := c.cc.Invoke(ctx, "/kstash.v1.KStash/SystemStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KStashServer is the server API for KStash service.
// All implementations must embed UnimplementedKStashServer
// for forward compatibility
type KStashServer interface {
	SystemRotate(context.Context, *SystemRotateRequest) (*SystemRotateResponse, error)
	SystemStatus(context.Context, *SystemStatusRequest) (*SystemStatusResponse, error)
	mustEmbedUnimplementedKStashServer()
}

// UnimplementedKStashServer must be embedded to have forward compatible implementations.
type UnimplementedKStashServer struct {
}

func (UnimplementedKStashServer) SystemRotate(context.Context, *SystemRotateRequest) (*SystemRotateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SystemRotate not implemented")
}
func (UnimplementedKStashServer) SystemStatus(context.Context, *SystemStatusRequest) (*SystemStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SystemStatus not implemented")
}
func (UnimplementedKStashServer) mustEmbedUnimplementedKStashServer() {}

// UnsafeKStashServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KStashServer will
// result in compilation errors.
type UnsafeKStashServer interface {
	mustEmbedUnimplementedKStashServer()
}

func RegisterKStashServer(s grpc.ServiceRegistrar, srv KStashServer) {
	s.RegisterService(&KStash_ServiceDesc, srv)
}

func _KStash_SystemRotate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SystemRotateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KStashServer).SystemRotate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kstash.v1.KStash/SystemRotate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KStashServer).SystemRotate(ctx, req.(*SystemRotateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KStash_SystemStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SystemStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KStashServer).SystemStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kstash.v1.KStash/SystemStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KStashServer).SystemStatus(ctx, req.(*SystemStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KStash_ServiceDesc is the grpc.ServiceDesc for KStash service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KStash_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kstash.v1.KStash",
	HandlerType: (*KStashServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SystemRotate",
			Handler:    _KStash_SystemRotate_Handler,
		},
		{
			MethodName: "SystemStatus",
			Handler:    _KStash_SystemStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kstash.proto",
}
