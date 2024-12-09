package server

import (
	"time"

	cluster "github.com/f-rambo/cloud-copilot/infrastructure/api/cluster"
	logApi "github.com/f-rambo/cloud-copilot/infrastructure/api/log"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/interfaces"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/metadata"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(c *conf.Server, logInterface *interfaces.LogInterface, clusterInterface *interfaces.ClusterInterface, logger log.Logger) *grpc.Server {
	var opts = []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
			metadata.Server(),
		),
	}
	netWork := c.Grpc.GetNetwork()
	if netWork != "" {
		opts = append(opts, grpc.Network(netWork))
	}
	addr := c.Grpc.GetAddr()
	if addr != "" {
		opts = append(opts, grpc.Address(addr))
	}
	timeoutsecond := c.Grpc.GetTimeout()
	if timeoutsecond != 0 {
		opts = append(opts, grpc.Timeout(time.Duration(timeoutsecond)*time.Second))
	}
	srv := grpc.NewServer(opts...)
	cluster.RegisterClusterInterfaceServer(srv, clusterInterface)
	logApi.RegisterLogInterfaceServer(srv, logInterface)
	return srv
}
