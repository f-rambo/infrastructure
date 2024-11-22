package server

import (
	"time"

	cluster "github.com/f-rambo/cloud-copilot/infrastructure/api/cluster"
	logApi "github.com/f-rambo/cloud-copilot/infrastructure/api/log"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/interfaces"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(c *conf.Server, logInterface *interfaces.LogInterface, clusterInterface *interfaces.ClusterInterface, logger log.Logger) *grpc.Server {
	var opts = []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
		),
	}
	if c.GRPC.Network != "" {
		opts = append(opts, grpc.Network(c.GRPC.Network))
	}
	if c.GRPC.Addr != "" {
		opts = append(opts, grpc.Address(c.GRPC.Addr))
	}
	if c.GRPC.Timeout != 0 {
		opts = append(opts, grpc.Timeout(time.Duration(c.GRPC.Timeout)*time.Second))
	}
	srv := grpc.NewServer(opts...)
	cluster.RegisterClusterInterfaceServer(srv, clusterInterface)
	logApi.RegisterLogInterfaceServer(srv, logInterface)
	return srv
}
