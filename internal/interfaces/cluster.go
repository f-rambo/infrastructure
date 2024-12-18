package interfaces

import (
	"context"
	"fmt"
	"time"

	clusterApi "github.com/f-rambo/cloud-copilot/infrastructure/api/cluster"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/pkg/errors"
)

type ClusterInterface struct {
	clusterApi.UnimplementedClusterInterfaceServer
	awsUc     *biz.AwsCloudUsecase
	aliUc     *biz.AliCloudUsecase
	clusterUc *biz.ClusterUsecase
	log       *log.Helper
	c         *conf.Server
}

func NewClusterInterface(awsUc *biz.AwsCloudUsecase, aliUc *biz.AliCloudUsecase, clusterUc *biz.ClusterUsecase, logger log.Logger, c *conf.Server) *ClusterInterface {
	return &ClusterInterface{
		awsUc:     awsUc,
		aliUc:     aliUc,
		clusterUc: clusterUc,
		log:       log.NewHelper(logger),
		c:         c,
	}
}

func (c *ClusterInterface) Ping(args *clusterApi.PingMessage, stream clusterApi.ClusterInterface_PingServer) error {
	fmt.Printf("Received request: %s \n", args.Message)
	for i := 0; i < 1; i++ {
		if stream.Context().Err() != nil {
			fmt.Println(stream.Context().Err())
		}
		response := &clusterApi.PingMessage{
			Message: fmt.Sprintf("Message %d: Hello from server", i),
		}
		if err := stream.Send(response); err != nil {
			return err
		}
		time.Sleep(time.Second * 5)
	}
	return nil
}

func (c *ClusterInterface) permissionChecking(_ *biz.Cluster) error {
	return nil
}

func (c *ClusterInterface) GetZones(ctx context.Context, cluster *biz.Cluster) (*clusterApi.CloudResources, error) {
	response := &clusterApi.CloudResources{Resources: make([]*biz.CloudResource, 0)}
	if !cluster.Type.IsCloud() {
		return response, nil
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.awsUc.GetAvailabilityZones(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.aliUc.CheckAccessIdAndKey(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.aliUc.GetAvailabilityZones(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}
	response.Resources = cluster.GetCloudResource(biz.ResourceType_AVAILABILITY_ZONES)
	return response, nil
}

func (c *ClusterInterface) GetRegions(ctx context.Context, cluster *biz.Cluster) (*clusterApi.CloudResources, error) {
	response := &clusterApi.CloudResources{Resources: make([]*biz.CloudResource, 0)}
	if !cluster.Type.IsCloud() {
		return response, nil
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.awsUc.GetAvailabilityRegions(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.aliUc.GetAvailabilityRegions(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}
	response.Resources = cluster.GetCloudResource(biz.ResourceType_REGION)
	return response, nil
}
func (c *ClusterInterface) Start(cluster *biz.Cluster, stream clusterApi.ClusterInterface_StartServer) error {
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	if !cluster.Type.IsCloud() {
		return errors.New("not support cloud provider")
	}
	if len(cluster.GetCloudResource(biz.ResourceType_AVAILABILITY_ZONES)) == 0 {
		return errors.New("availability zones is empty")
	}
	defer stream.Send(cluster)
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.ImportKeyPair,
			c.awsUc.CreateNetwork,
			c.awsUc.ManageInstance,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.ImportKeyPair,
			c.aliUc.CreateNetwork,
			c.aliUc.ManageInstance,
		}
	}
	for _, f := range funcs {
		err := f(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterInterface) Stop(cluster *biz.Cluster, stream clusterApi.ClusterInterface_StopServer) error {
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	if !cluster.Type.IsCloud() {
		return errors.New("not support cloud provider")
	}
	defer stream.Send(cluster)
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.ManageInstance,
			c.awsUc.DeleteKeyPair,
			c.awsUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.ManageInstance,
			c.aliUc.DeleteKeyPair,
			c.aliUc.DeleteNetwork,
		}
	}
	for _, f := range funcs {
		err := f(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterInterface) MigrateToBostionHost(cluster *biz.Cluster, stream clusterApi.ClusterInterface_MigrateToBostionHostServer) error {
	defer func() {
		stream.Send(cluster)
		if cluster.Type == biz.ClusterType_ALICLOUD {
			c.aliUc.Connections(stream.Context(), cluster)
			c.aliUc.CloseSSh(stream.Context(), cluster)
		}
		if cluster.Type == biz.ClusterType_AWS {
			c.awsUc.Connections(stream.Context(), cluster)
			c.awsUc.CloseSSh(stream.Context(), cluster)
		}
	}()
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.OpenSSh(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.OpenSSh(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	err := c.clusterUc.MigrateToBostionHost(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterInterface) GetNodesSystemInfo(cluster *biz.Cluster, stream clusterApi.ClusterInterface_GetNodesSystemInfoServer) error {
	defer stream.Send(cluster)
	err := c.clusterUc.GetNodesSystemInfo(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterInterface) Install(cluster *biz.Cluster, stream clusterApi.ClusterInterface_InstallServer) error {
	defer stream.Send(cluster)
	err := c.clusterUc.Install(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterInterface) UnInstall(cluster *biz.Cluster, stream clusterApi.ClusterInterface_UnInstallServer) error {
	defer stream.Send(cluster)
	err := c.clusterUc.UnInstall(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterInterface) HandlerNodes(cluster *biz.Cluster, stream clusterApi.ClusterInterface_HandlerNodesServer) error {
	defer stream.Send(cluster)
	err := c.clusterUc.HandlerNodes(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return nil
}
