package interfaces

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alibabacloud-go/tea/tea"
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

func (c *ClusterInterface) permissionChecking(cluster *biz.Cluster) error {
	if !cluster.Type.IsCloud() {
		return nil
	}
	if cluster.Type == biz.ClusterType_AWS {
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
	}
	return nil
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

func (c *ClusterInterface) CreateCloudBasicResource(cluster *biz.Cluster, stream clusterApi.ClusterInterface_CreateCloudBasicResourceServer) error {
	defer stream.Send(cluster)
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.CreateNetwork(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.ImportKeyPair(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.CreateNetwork(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.ImportKeyPair(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterInterface) DeleteCloudBasicResource(cluster *biz.Cluster, stream clusterApi.ClusterInterface_DeleteCloudBasicResourceServer) error {
	defer stream.Send(cluster)
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.DeleteNetwork(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.DeleteKeyPair(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.DeleteNetwork(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.DeleteKeyPair(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterInterface) ManageNodeResource(cluster *biz.Cluster, stream clusterApi.ClusterInterface_ManageNodeResourceServer) error {
	defer stream.Send(cluster)
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.ManageSecurityGroup(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.ManageInstance(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.ManageSLB(stream.Context(), cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.ManageSecurityGroup(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.ManageInstance(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.ManageSLB(stream.Context(), cluster)
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
	if !cluster.Type.IsCloud() {
		err := c.clusterUc.GetNodesSystemInfo(stream.Context(), cluster)
		if err != nil {
			return err
		}
		return nil
	}
	if err := c.permissionChecking(cluster); err != nil {
		return err
	}
	for _, nodeGroup := range cluster.NodeGroups {
		isFindNode := false
		for _, node := range cluster.Nodes {
			if node.NodeGroupId != nodeGroup.Id {
				continue
			}
			if node.Status == biz.NodeStatus_NODE_FINDING {
				isFindNode = true
				break
			}
		}
		if !isFindNode {
			continue
		}
		if cluster.Type == biz.ClusterType_AWS {
			err := c.awsUc.Connections(stream.Context(), cluster)
			if err != nil {
				return err
			}
		}
		if cluster.Type == biz.ClusterType_ALICLOUD {
			err := c.aliUc.Connections(stream.Context(), cluster)
			if err != nil {
				return err
			}
			image, err := c.aliUc.FindImage(cluster.Region, nodeGroup.Arch)
			if err != nil {
				return err
			}
			instanceTypes, err := c.aliUc.FindInstanceType(biz.FindInstanceTypeParam{
				CPU:           nodeGroup.Cpu,
				Memory:        nodeGroup.Memory,
				Arch:          nodeGroup.Arch,
				GPU:           nodeGroup.Gpu,
				GPUSpec:       nodeGroup.GpuSpec,
				NodeGroupType: nodeGroup.Type,
			})
			if err != nil {
				return err
			}
			if len(instanceTypes) == 0 {
				return errors.New("Not found instance type")
			}
			instanceTypeId := ""
			backupInstanceTypeIds := make([]string, 0)
			for _, v := range instanceTypes {
				if nodeGroup.Memory != int32(tea.Float32Value(v.MemorySize)) {
					nodeGroup.Memory = int32(tea.Float32Value(v.MemorySize))
				}
				if instanceTypeId == "" {
					instanceTypeId = tea.StringValue(v.InstanceTypeId)
					continue
				}
				backupInstanceTypeIds = append(backupInstanceTypeIds, tea.StringValue(v.InstanceTypeId))
			}
			for _, node := range cluster.Nodes {
				if node.NodeGroupId != nodeGroup.Id {
					continue
				}
				node.ImageId = tea.StringValue(image.ImageId)
				node.InstanceType = instanceTypeId
				node.BackupInstanceIds = strings.Join(backupInstanceTypeIds, ",")
			}
		}
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
