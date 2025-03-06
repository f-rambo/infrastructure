package interfaces

import (
	"context"
	"strings"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aws/aws-sdk-go-v2/aws"
	clusterApi "github.com/f-rambo/cloud-copilot/infrastructure/api/cluster"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	"github.com/go-kratos/kratos/v2/log"
)

type ClusterInterface struct {
	clusterApi.UnimplementedClusterInterfaceServer
	awsUc     *biz.AwsCloudUsecase
	aliUc     *biz.AliCloudUsecase
	clusterUc *biz.ClusterUsecase
	log       *log.Helper
}

func NewClusterInterface(awsUc *biz.AwsCloudUsecase, aliUc *biz.AliCloudUsecase, clusterUc *biz.ClusterUsecase, logger log.Logger) *ClusterInterface {
	return &ClusterInterface{
		awsUc:     awsUc,
		aliUc:     aliUc,
		clusterUc: clusterUc,
		log:       log.NewHelper(logger),
	}
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
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.CreateNetwork(stream.Context(), cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.ImportKeyPair(stream.Context(), cluster)
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

func (c *ClusterInterface) GetNodesSystemInfo(cluster *biz.Cluster, stream clusterApi.ClusterInterface_GetNodesSystemInfoServer) error {
	defer stream.Send(cluster)
	if !cluster.Type.IsCloud() {
		err := c.clusterUc.GetNodesSystemInfo(stream.Context(), cluster)
		if err != nil {
			return err
		}
		return nil
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
		imageId := ""
		systemDiskName := ""
		instanceTypeId := ""
		nodeUser := "root"
		backupInstanceTypeIds := make([]string, 0)
		if cluster.Type == biz.ClusterType_AWS {
			err := c.awsUc.Connections(stream.Context(), cluster)
			if err != nil {
				return err
			}
			image, err := c.awsUc.FindImage(stream.Context(), nodeGroup.Arch)
			if err != nil {
				return err
			}
			imageId = aws.ToString(image.ImageId)
			nodeUser = biz.DetermineUsername(aws.ToString(image.Name), aws.ToString(image.Description))
			systemDiskName = aws.ToString(image.RootDeviceName)
			instanceTypes, err := c.awsUc.FindInstanceType(stream.Context(), biz.FindInstanceTypeParam{
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
			for _, v := range instanceTypes {
				memSize := int32(aws.ToInt64(v.MemoryInfo.SizeInMiB) / 1024)
				if nodeGroup.Memory != memSize {
					nodeGroup.Memory = memSize
				}
				if instanceTypeId == "" {
					instanceTypeId = string(v.InstanceType)
					continue
				}
				backupInstanceTypeIds = append(backupInstanceTypeIds, string(v.InstanceType))
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
			imageId = tea.StringValue(image.ImageId)
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
		}
		for _, node := range cluster.Nodes {
			if node.NodeGroupId != nodeGroup.Id {
				continue
			}
			node.User = nodeUser
			node.ImageId = imageId
			node.SystemDiskName = systemDiskName
			node.InstanceType = instanceTypeId
			node.BackupInstanceIds = strings.Join(backupInstanceTypeIds, ",")
		}
	}
	return nil
}

func (c *ClusterInterface) Install(cluster *biz.Cluster, stream clusterApi.ClusterInterface_InstallServer) error {
	defer stream.Send(cluster)
	err := c.openSsh(stream.Context(), cluster)
	if err != nil {
		return err
	}
	err = c.clusterUc.MigrateResources(stream.Context(), cluster)
	if err != nil {
		return err
	}
	err = c.clusterUc.Install(stream.Context(), cluster)
	if err != nil {
		return err
	}
	err = c.clusterUc.ApplyServices(stream.Context(), cluster)
	if err != nil {
		return err
	}
	err = c.closeSsh(stream.Context(), cluster)
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

func (c *ClusterInterface) openSsh(ctx context.Context, cluster *biz.Cluster) error {
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(ctx, cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.OpenSSh(ctx, cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(ctx, cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.OpenSSh(ctx, cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterInterface) closeSsh(ctx context.Context, cluster *biz.Cluster) error {
	if cluster.Type == biz.ClusterType_ALICLOUD {
		err := c.aliUc.Connections(ctx, cluster)
		if err != nil {
			return err
		}
		err = c.aliUc.CloseSSh(ctx, cluster)
		if err != nil {
			return err
		}
	}
	if cluster.Type == biz.ClusterType_AWS {
		err := c.awsUc.Connections(ctx, cluster)
		if err != nil {
			return err
		}
		err = c.awsUc.CloseSSh(ctx, cluster)
		if err != nil {
			return err
		}
	}
	return nil
}
