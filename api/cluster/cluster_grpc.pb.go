// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.27.1
// source: api/cluster/cluster.proto

package cluster

import (
	context "context"
	biz "github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ClusterInterface_Ping_FullMethodName                 = "/infrastructure.api.cluster.ClusterInterface/Ping"
	ClusterInterface_GetRegions_FullMethodName           = "/infrastructure.api.cluster.ClusterInterface/GetRegions"
	ClusterInterface_GetZones_FullMethodName             = "/infrastructure.api.cluster.ClusterInterface/GetZones"
	ClusterInterface_Start_FullMethodName                = "/infrastructure.api.cluster.ClusterInterface/Start"
	ClusterInterface_Stop_FullMethodName                 = "/infrastructure.api.cluster.ClusterInterface/Stop"
	ClusterInterface_MigrateToBostionHost_FullMethodName = "/infrastructure.api.cluster.ClusterInterface/MigrateToBostionHost"
	ClusterInterface_GetNodesSystemInfo_FullMethodName   = "/infrastructure.api.cluster.ClusterInterface/GetNodesSystemInfo"
	ClusterInterface_Install_FullMethodName              = "/infrastructure.api.cluster.ClusterInterface/Install"
	ClusterInterface_UnInstall_FullMethodName            = "/infrastructure.api.cluster.ClusterInterface/UnInstall"
	ClusterInterface_HandlerNodes_FullMethodName         = "/infrastructure.api.cluster.ClusterInterface/HandlerNodes"
)

// ClusterInterfaceClient is the client API for ClusterInterface service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ClusterInterfaceClient interface {
	Ping(ctx context.Context, in *PingMessage, opts ...grpc.CallOption) (grpc.ServerStreamingClient[PingMessage], error)
	GetRegions(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (*CloudResources, error)
	GetZones(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (*CloudResources, error)
	Start(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	Stop(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	MigrateToBostionHost(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	GetNodesSystemInfo(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	Install(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	UnInstall(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
	HandlerNodes(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error)
}

type clusterInterfaceClient struct {
	cc grpc.ClientConnInterface
}

func NewClusterInterfaceClient(cc grpc.ClientConnInterface) ClusterInterfaceClient {
	return &clusterInterfaceClient{cc}
}

func (c *clusterInterfaceClient) Ping(ctx context.Context, in *PingMessage, opts ...grpc.CallOption) (grpc.ServerStreamingClient[PingMessage], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[0], ClusterInterface_Ping_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[PingMessage, PingMessage]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_PingClient = grpc.ServerStreamingClient[PingMessage]

func (c *clusterInterfaceClient) GetRegions(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (*CloudResources, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CloudResources)
	err := c.cc.Invoke(ctx, ClusterInterface_GetRegions_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterInterfaceClient) GetZones(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (*CloudResources, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CloudResources)
	err := c.cc.Invoke(ctx, ClusterInterface_GetZones_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterInterfaceClient) Start(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[1], ClusterInterface_Start_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_StartClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) Stop(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[2], ClusterInterface_Stop_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_StopClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) MigrateToBostionHost(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[3], ClusterInterface_MigrateToBostionHost_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_MigrateToBostionHostClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) GetNodesSystemInfo(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[4], ClusterInterface_GetNodesSystemInfo_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_GetNodesSystemInfoClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) Install(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[5], ClusterInterface_Install_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_InstallClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) UnInstall(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[6], ClusterInterface_UnInstall_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_UnInstallClient = grpc.ServerStreamingClient[biz.Cluster]

func (c *clusterInterfaceClient) HandlerNodes(ctx context.Context, in *biz.Cluster, opts ...grpc.CallOption) (grpc.ServerStreamingClient[biz.Cluster], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClusterInterface_ServiceDesc.Streams[7], ClusterInterface_HandlerNodes_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[biz.Cluster, biz.Cluster]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_HandlerNodesClient = grpc.ServerStreamingClient[biz.Cluster]

// ClusterInterfaceServer is the server API for ClusterInterface service.
// All implementations must embed UnimplementedClusterInterfaceServer
// for forward compatibility.
type ClusterInterfaceServer interface {
	Ping(*PingMessage, grpc.ServerStreamingServer[PingMessage]) error
	GetRegions(context.Context, *biz.Cluster) (*CloudResources, error)
	GetZones(context.Context, *biz.Cluster) (*CloudResources, error)
	Start(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	Stop(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	MigrateToBostionHost(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	GetNodesSystemInfo(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	Install(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	UnInstall(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	HandlerNodes(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error
	mustEmbedUnimplementedClusterInterfaceServer()
}

// UnimplementedClusterInterfaceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedClusterInterfaceServer struct{}

func (UnimplementedClusterInterfaceServer) Ping(*PingMessage, grpc.ServerStreamingServer[PingMessage]) error {
	return status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedClusterInterfaceServer) GetRegions(context.Context, *biz.Cluster) (*CloudResources, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRegions not implemented")
}
func (UnimplementedClusterInterfaceServer) GetZones(context.Context, *biz.Cluster) (*CloudResources, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetZones not implemented")
}
func (UnimplementedClusterInterfaceServer) Start(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method Start not implemented")
}
func (UnimplementedClusterInterfaceServer) Stop(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method Stop not implemented")
}
func (UnimplementedClusterInterfaceServer) MigrateToBostionHost(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method MigrateToBostionHost not implemented")
}
func (UnimplementedClusterInterfaceServer) GetNodesSystemInfo(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method GetNodesSystemInfo not implemented")
}
func (UnimplementedClusterInterfaceServer) Install(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method Install not implemented")
}
func (UnimplementedClusterInterfaceServer) UnInstall(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method UnInstall not implemented")
}
func (UnimplementedClusterInterfaceServer) HandlerNodes(*biz.Cluster, grpc.ServerStreamingServer[biz.Cluster]) error {
	return status.Errorf(codes.Unimplemented, "method HandlerNodes not implemented")
}
func (UnimplementedClusterInterfaceServer) mustEmbedUnimplementedClusterInterfaceServer() {}
func (UnimplementedClusterInterfaceServer) testEmbeddedByValue()                          {}

// UnsafeClusterInterfaceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ClusterInterfaceServer will
// result in compilation errors.
type UnsafeClusterInterfaceServer interface {
	mustEmbedUnimplementedClusterInterfaceServer()
}

func RegisterClusterInterfaceServer(s grpc.ServiceRegistrar, srv ClusterInterfaceServer) {
	// If the following call pancis, it indicates UnimplementedClusterInterfaceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ClusterInterface_ServiceDesc, srv)
}

func _ClusterInterface_Ping_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(PingMessage)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).Ping(m, &grpc.GenericServerStream[PingMessage, PingMessage]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_PingServer = grpc.ServerStreamingServer[PingMessage]

func _ClusterInterface_GetRegions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(biz.Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterInterfaceServer).GetRegions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ClusterInterface_GetRegions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterInterfaceServer).GetRegions(ctx, req.(*biz.Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterInterface_GetZones_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(biz.Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterInterfaceServer).GetZones(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ClusterInterface_GetZones_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterInterfaceServer).GetZones(ctx, req.(*biz.Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterInterface_Start_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).Start(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_StartServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_Stop_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).Stop(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_StopServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_MigrateToBostionHost_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).MigrateToBostionHost(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_MigrateToBostionHostServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_GetNodesSystemInfo_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).GetNodesSystemInfo(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_GetNodesSystemInfoServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_Install_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).Install(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_InstallServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_UnInstall_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).UnInstall(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_UnInstallServer = grpc.ServerStreamingServer[biz.Cluster]

func _ClusterInterface_HandlerNodes_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(biz.Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterInterfaceServer).HandlerNodes(m, &grpc.GenericServerStream[biz.Cluster, biz.Cluster]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClusterInterface_HandlerNodesServer = grpc.ServerStreamingServer[biz.Cluster]

// ClusterInterface_ServiceDesc is the grpc.ServiceDesc for ClusterInterface service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ClusterInterface_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "infrastructure.api.cluster.ClusterInterface",
	HandlerType: (*ClusterInterfaceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetRegions",
			Handler:    _ClusterInterface_GetRegions_Handler,
		},
		{
			MethodName: "GetZones",
			Handler:    _ClusterInterface_GetZones_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Ping",
			Handler:       _ClusterInterface_Ping_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Start",
			Handler:       _ClusterInterface_Start_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Stop",
			Handler:       _ClusterInterface_Stop_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "MigrateToBostionHost",
			Handler:       _ClusterInterface_MigrateToBostionHost_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetNodesSystemInfo",
			Handler:       _ClusterInterface_GetNodesSystemInfo_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Install",
			Handler:       _ClusterInterface_Install_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "UnInstall",
			Handler:       _ClusterInterface_UnInstall_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "HandlerNodes",
			Handler:       _ClusterInterface_HandlerNodes_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "api/cluster/cluster.proto",
}
