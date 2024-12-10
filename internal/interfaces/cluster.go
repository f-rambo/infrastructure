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
	gcpUc     *biz.GoogleCloudUsecase
	aliUc     *biz.AliCloudUsecase
	clusterUc *biz.ClusterUsecase
	log       *log.Helper
	c         *conf.Server
}

func NewClusterInterface(awsUc *biz.AwsCloudUsecase, gcpUc *biz.GoogleCloudUsecase, aliUc *biz.AliCloudUsecase, clusterUc *biz.ClusterUsecase, logger log.Logger, c *conf.Server) *ClusterInterface {
	return &ClusterInterface{
		awsUc:     awsUc,
		gcpUc:     gcpUc,
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

func (c *ClusterInterface) GetRegions(ctx context.Context, cluster *biz.Cluster) (*clusterApi.CloudResources, error) {
	response := &clusterApi.CloudResources{Resources: make([]*biz.CloudResource, 0)}
	if !cluster.Type.IsCloud() {
		return response, nil
	}
	if cluster.Type == biz.ClusterType_AWS_EC2 || cluster.Type == biz.ClusterType_AWS_EKS {
		err := c.awsUc.Connections(ctx, cluster)
		if err != nil {
			return nil, err
		}
		err = c.awsUc.GetAvailabilityZones(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS || cluster.Type == biz.ClusterType_ALICLOUD_AKS {
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
func (c *ClusterInterface) Start(cluster *biz.Cluster, stream clusterApi.ClusterInterface_StartServer) error {
	if !cluster.Type.IsCloud() {
		return errors.New("not support cloud provider")
	}
	if len(cluster.GetCloudResource(biz.ResourceType_AVAILABILITY_ZONES)) == 0 {
		return errors.New("availability zones is empty")
	}
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS_EC2 {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.CreateNetwork,
			c.awsUc.SetByNodeGroups,
			c.awsUc.ImportKeyPair,
			c.awsUc.ManageInstance,
			c.awsUc.ManageBostionHost,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.CreateNetwork,
			c.aliUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.aliUc.ManageInstance,
			c.aliUc.ManageBostionHost,
		}
	}
	if cluster.Type == biz.ClusterType_AWS_EKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.CreateNetwork,
			c.awsUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.awsUc.ManageKubernetesCluster,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_AKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.CreateNetwork,
			c.aliUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.aliUc.ManageKubernetesCluster,
		}
	}
	for _, f := range funcs {
		err := f(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	return stream.Send(cluster)
}

func (c *ClusterInterface) Stop(cluster *biz.Cluster, stream clusterApi.ClusterInterface_StopServer) error {
	if !cluster.Type.IsCloud() {
		return errors.New("not support cloud provider")
	}
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS_EC2 {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.ManageInstance,
			c.awsUc.ManageBostionHost,
			c.awsUc.DeleteKeyPair,
			c.awsUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.ManageInstance,
			c.aliUc.ManageBostionHost,
			c.aliUc.DeleteKeyPair,
			c.aliUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_AWS_EKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.ManageKubernetesCluster,
			c.awsUc.DeleteKeyPair,
			c.awsUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_AKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.Connections,
			c.aliUc.ManageKubernetesCluster,
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
	return stream.Send(cluster)
}

func (c *ClusterInterface) MigrateToBostionHost(cluster *biz.Cluster, stream clusterApi.ClusterInterface_MigrateToBostionHostServer) error {
	err := c.clusterUc.MigrateToBostionHost(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return stream.Send(cluster)
}

func (c *ClusterInterface) GetNodesSystemInfo(cluster *biz.Cluster, stream clusterApi.ClusterInterface_GetNodesSystemInfoServer) error {
	err := c.clusterUc.GetNodesSystemInfo(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return stream.Send(cluster)
}

func (c *ClusterInterface) Install(cluster *biz.Cluster, stream clusterApi.ClusterInterface_InstallServer) error {
	err := c.clusterUc.Install(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return stream.Send(cluster)
}

func (c *ClusterInterface) UnInstall(cluster *biz.Cluster, stream clusterApi.ClusterInterface_UnInstallServer) error {
	err := c.clusterUc.UnInstall(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return stream.Send(cluster)
}

func (c *ClusterInterface) HandlerNodes(cluster *biz.Cluster, stream clusterApi.ClusterInterface_HandlerNodesServer) error {
	err := c.clusterUc.HandlerNodes(stream.Context(), cluster)
	if err != nil {
		return err
	}
	return stream.Send(cluster)
}
