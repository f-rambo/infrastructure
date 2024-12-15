package biz

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	cs20151215 "github.com/alibabacloud-go/cs-20151215/v5/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs20140526 "github.com/alibabacloud-go/ecs-20140526/v4/client"
	slb20140515 "github.com/alibabacloud-go/slb-20140515/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	vpc20160428 "github.com/alibabacloud-go/vpc-20160428/v6/client"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

const (
	alicloudDefaultRegion = "cn-hangzhou"

	ALICLOUD_ACCESS_KEY     = "ALICLOUD_ACCESS_KEY"
	ALICLOUD_SECRET_KEY     = "ALICLOUD_SECRET_KEY"
	ALICLOUD_REGION         = "ALICLOUD_REGION"
	ALICLOUD_DEFAULT_REGION = "ALICLOUD_DEFAULT_REGION"

	TimeOutCountNumber = 10
	TimeOutSecond      = 5
)

type AliCloudUsecase struct {
	log       *log.Helper
	vpcClient *vpc20160428.Client
	ecsClient *ecs20140526.Client
	slbClient *slb20140515.Client
	csClient  *cs20151215.Client
}

func NewAliCloudUseCase(logger log.Logger) *AliCloudUsecase {
	c := &AliCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}

func (a *AliCloudUsecase) Connections(ctx context.Context, cluster *Cluster) (err error) {
	if cluster.Region == "" {
		cluster.Region = alicloudDefaultRegion
	}
	os.Setenv(ALICLOUD_ACCESS_KEY, cluster.AccessId)
	os.Setenv(ALICLOUD_SECRET_KEY, cluster.AccessKey)
	os.Setenv(ALICLOUD_REGION, cluster.Region)
	os.Setenv(ALICLOUD_DEFAULT_REGION, cluster.Region)
	config := &openapi.Config{
		AccessKeyId:     tea.String(cluster.AccessId),
		AccessKeySecret: tea.String(cluster.AccessKey),
		RegionId:        tea.String(cluster.Region),
	}
	a.vpcClient, err = vpc20160428.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create vpc client")
	}
	a.ecsClient, err = ecs20140526.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create ecs client")
	}
	a.slbClient, err = slb20140515.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create slb client")
	}
	a.csClient, err = cs20151215.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create cs client")
	}
	return nil
}

func (a *AliCloudUsecase) CheckAccessIdAndKey(ctx context.Context, cluster *Cluster) error {
	_, err := a.vpcClient.DescribeVpcs(&vpc20160428.DescribeVpcsRequest{
		RegionId:   tea.String(cluster.Region),
		PageNumber: tea.Int32(1),
		PageSize:   tea.Int32(50),
	})
	if err != nil {
		return errors.Wrapf(err, "invalid access id or key")
	}
	return nil
}

func (a *AliCloudUsecase) GetAvailabilityZones(ctx context.Context, cluster *Cluster) error {
	zonesRes, err := a.ecsClient.DescribeZones(&ecs20140526.DescribeZonesRequest{
		AcceptLanguage:     tea.String("zh-CN"),
		RegionId:           tea.String(os.Getenv(ALICLOUD_REGION)),
		InstanceChargeType: tea.String("PostPaid"),
		SpotStrategy:       tea.String("NoSpot"),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe zones")
	}
	if len(zonesRes.Body.Zones.Zone) == 0 {
		return errors.New("no availability zones found")
	}
	for _, zone := range zonesRes.Body.Zones.Zone {
		if tea.StringValue(zone.ZoneType) != "AvailabilityZone" {
			continue
		}
		zoneResourceType := tea.StringSliceValue(zone.AvailableResourceCreation.ResourceTypes)
		if !utils.InArray("VSwitch", zoneResourceType) {
			continue
		}
		if !utils.InArray("IoOptimized", zoneResourceType) {
			continue
		}
		if !utils.InArray("Instance", zoneResourceType) {
			continue
		}
		if !utils.InArray("Disk", zoneResourceType) {
			continue
		}
		if !utils.InArray("DedicatedHost", zoneResourceType) {
			continue
		}
		cluster.AddCloudResource(&CloudResource{
			RefId: tea.StringValue(zone.ZoneId),
			Name:  tea.StringValue(zone.LocalName),
			Type:  ResourceType_AVAILABILITY_ZONES,
			Value: os.Getenv(ALICLOUD_REGION),
		})
	}
	return nil
}

func (a *AliCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	fs := []func(context.Context, *Cluster) error{
		a.createVPC,
		a.createSubnets,
		a.createEips,
		a.createNatGateways,
		a.createRouteTables,
		a.createSecurityGroup,
		a.createSLB,
	}
	for _, f := range fs {
		if err := f(ctx, cluster); err != nil {
			return err
		}
	}
	return nil
}

func (a *AliCloudUsecase) SetByNodeGroups(ctx context.Context, cluster *Cluster) error {
	// instance type
	for _, nodeGroup := range cluster.NodeGroups {
		if nodeGroup.InstanceType != "" {
			continue
		}
		instanceTypeFamiliy := a.getIntanceTypeFamilies(nodeGroup.Type)
		findInstanceTypeParam := FindInstanceTypeParam{
			InstanceTypeFamiliy: instanceTypeFamiliy,
			CPU:                 nodeGroup.Cpu,
			Memory:              nodeGroup.Memory,
			GPU:                 nodeGroup.Gpu,
			GPUSpec:             nodeGroup.GpuSpec,
			Arch:                nodeGroup.Arch,
		}
		instanceInfo, err := a.findInstanceType(cluster, findInstanceTypeParam)
		if err != nil {
			return err
		}
		nodeGroup.InstanceType = tea.StringValue(instanceInfo.InstanceTypeId)
		nodeGroup.Cpu = tea.Int32Value(instanceInfo.CpuCoreCount)
		nodeGroup.Memory = int32(tea.Float32Value(instanceInfo.MemorySize))
		if nodeGroup.Gpu > 0 {
			nodeGroup.Gpu = tea.Int32Value(instanceInfo.GPUAmount)
		}
		a.log.Info("instance type found: ", nodeGroup.InstanceType)
	}

	// image
	for _, nodeGroup := range cluster.NodeGroups {
		if nodeGroup.InstanceType == "" {
			return errors.New("instance type not found")
		}
		image, err := a.findImage(cluster.Region, nodeGroup.InstanceType)
		if err != nil {
			return err
		}
		a.log.Infof("image found: %s", tea.StringValue(image.Description))
		if tea.Int32Value(image.Size) != 0 {
			nodeGroup.SystemDiskSize = tea.Int32Value(image.Size)
		}
		nodeGroup.Os = tea.StringValue(image.OSName)
		nodeGroup.Image = tea.StringValue(image.ImageId)
		nodeGroup.ImageDescription = tea.StringValue(image.Description)
		for _, disk := range image.DiskDeviceMappings.DiskDeviceMapping {
			if tea.StringValue(disk.Type) == "system" {
				nodeGroup.RootDeviceName = tea.StringValue(disk.Device)
			}
			if nodeGroup.DataDeviceName == "" && tea.StringValue(disk.Type) == "system" {
				nodeGroup.DataDeviceName = tea.StringValue(disk.Device)
			}
		}
	}
	return nil
}

func (a *AliCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	// Check if key pair already exists
	keyPairName := a.getkeyPairName(cluster.Name)
	if cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName) != nil {
		a.log.Infof("key pair %s already exists", keyPairName)
		return nil
	}

	// List existing key pairs
	var pageNumber int32 = 1
	for {
		keyPairs, err := a.ecsClient.DescribeKeyPairs(&ecs20140526.DescribeKeyPairsRequest{
			RegionId:    tea.String(cluster.Region),
			PageNumber:  tea.Int32(pageNumber),
			PageSize:    tea.Int32(50),
			KeyPairName: tea.String(keyPairName),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe key pairs")
		}

		for _, kp := range keyPairs.Body.KeyPairs.KeyPair {
			if tea.StringValue(kp.KeyPairName) == keyPairName {
				if cluster.GetCloudResourceByRefID(ResourceType_KEY_PAIR, tea.StringValue(kp.KeyPairName)) != nil {
					continue
				}
				cluster.AddCloudResource(&CloudResource{
					Name:  tea.StringValue(kp.KeyPairName),
					RefId: tea.StringValue(kp.KeyPairName),
					Type:  ResourceType_KEY_PAIR,
				})
				a.log.Infof("key pair %s already exists", keyPairName)
				return nil
			}
		}

		if len(keyPairs.Body.KeyPairs.KeyPair) < 50 {
			break
		}
		pageNumber++
	}

	// Import key pair
	importReq := &ecs20140526.ImportKeyPairRequest{
		RegionId:      tea.String(cluster.Region),
		KeyPairName:   tea.String(keyPairName),
		PublicKeyBody: tea.String(cluster.PublicKey),
	}

	importRes, err := a.ecsClient.ImportKeyPair(importReq)
	if err != nil {
		return errors.Wrap(err, "failed to import key pair")
	}

	// Add tags to key pair
	err = a.createEcsTag(cluster.Region, tea.StringValue(importRes.Body.KeyPairName), "keypair", map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: keyPairName})
	if err != nil {
		return errors.Wrap(err, "failed to tag key pair")
	}

	// Add to cluster resources
	cluster.AddCloudResource(&CloudResource{
		Name:  keyPairName,
		RefId: tea.StringValue(importRes.Body.KeyPairName),
		Type:  ResourceType_KEY_PAIR,
		Tags:  cluster.EncodeTags(map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: keyPairName}),
	})

	a.log.Infof("key pair %s imported successfully", keyPairName)
	return nil
}

func (a *AliCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	// Get key pair from cluster resources
	keyPairName := a.getkeyPairName(cluster.Name)
	keyPair := cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName)
	if keyPair == nil {
		a.log.Infof("key pair %s not found", keyPairName)
		return nil
	}

	res, err := a.ecsClient.DescribeKeyPairs(&ecs20140526.DescribeKeyPairsRequest{
		RegionId:    tea.String(cluster.Region),
		KeyPairName: tea.String(keyPairName),
		PageNumber:  tea.Int32(1),
		PageSize:    tea.Int32(1),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe key pairs")
	}
	if tea.Int32Value(res.Body.TotalCount) == 0 {
		cluster.DeleteCloudResource(ResourceType_KEY_PAIR)
		a.log.Infof("key pair %s deleted successfully", keyPairName)
		return nil
	}

	// Delete key pair
	_, err = a.ecsClient.DeleteKeyPairs(&ecs20140526.DeleteKeyPairsRequest{
		RegionId:     tea.String(cluster.Region),
		KeyPairNames: tea.String(fmt.Sprintf("[\"%s\"]", keyPairName)),
	})
	if err != nil {
		return errors.Wrap(err, "failed to delete key pair")
	}

	// Remove from cluster resources
	cluster.DeleteCloudResource(ResourceType_KEY_PAIR)
	a.log.Infof("key pair %s deleted successfully", keyPairName)
	return nil
}

func (a *AliCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	sg := cluster.GetSingleCloudResource(ResourceType_SECURITY_GROUP)
	if sg == nil {
		return errors.New("security group not found")
	}
	keyPair := cluster.GetSingleCloudResource(ResourceType_KEY_PAIR)
	if keyPair == nil {
		return errors.New("key pair not found")
	}
	// find all instances in the current vpc
	instances := make([]*ecs20140526.DescribeInstancesResponseBodyInstancesInstance, 0)
	pageNumber := 1
	for {
		instancesRes, err := a.ecsClient.DescribeInstances(&ecs20140526.DescribeInstancesRequest{
			RegionId:   tea.String(cluster.Region),
			VpcId:      tea.String(vpc.RefId),
			PageNumber: tea.Int32(1),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe instances")
		}
		instances = append(instances, instancesRes.Body.Instances.Instance...)
		if len(instancesRes.Body.Instances.Instance) < 50 {
			break
		}
		pageNumber++
	}
	// clear history nodes
	for _, node := range cluster.Nodes {
		nodeExits := false
		for _, instance := range instances {
			if node.InstanceId == tea.StringValue(instance.InstanceId) {
				nodeExits = true
				break
			}
		}
		if !nodeExits && (node.Status == NodeStatus_NODE_RUNNING || node.Status == NodeStatus_NODE_PENDING) {
			node.InstanceId = ""
		}
	}

	// handler need delete instances
	needDeleteInstanceIDs := make([]string, 0)
	for _, node := range cluster.Nodes {
		if node.Status == NodeStatus_NODE_DELETING && node.InstanceId != "" {
			needDeleteInstanceIDs = append(needDeleteInstanceIDs, node.InstanceId)
		}
	}
	deleteInstanceIDs := make([]string, 0)
	for _, instance := range instances {
		if utils.InArray(tea.StringValue(instance.InstanceId), needDeleteInstanceIDs) {
			deleteInstanceIDs = append(deleteInstanceIDs, tea.StringValue(instance.InstanceId))
		}
	}
	if len(deleteInstanceIDs) > 0 {
		_, err := a.ecsClient.DeleteInstances(&ecs20140526.DeleteInstancesRequest{
			RegionId:   tea.String(cluster.Region),
			InstanceId: tea.StringSlice(deleteInstanceIDs),
			Force:      tea.Bool(true),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete instances")
		}
		for _, node := range cluster.Nodes {
			if utils.InArray(node.InstanceId, deleteInstanceIDs) {
				a.log.Infof("instance %s deleted successfully", node.InstanceId)
				node.InstanceId = ""
			}
		}
	}

	// Create instances
	instanceIds := make([]string, 0)
	for _, nodeGroup := range cluster.NodeGroups {
		createInstanceReq := &ecs20140526.CreateInstanceRequest{
			InstanceChargeType: tea.String("PostPaid"),
			RegionId:           tea.String(cluster.Region),
			ImageId:            tea.String(nodeGroup.Image),
			InstanceType:       tea.String(nodeGroup.InstanceType),
			KeyPairName:        tea.String(keyPair.Name),
			SecurityGroupId:    tea.String(sg.RefId),
			SystemDisk: &ecs20140526.CreateInstanceRequestSystemDisk{
				Category: tea.String("cloud_ssd"),
				Size:     tea.Int32(nodeGroup.SystemDiskSize),
			},
		}
		for index, node := range cluster.Nodes {
			if node.Status != NodeStatus_NODE_CREATING || node.NodeGroupId != nodeGroup.Id {
				continue
			}
			privateSubnet := cluster.DistributeNodePrivateSubnets(index)
			if privateSubnet == nil {
				return errors.New("no private subnet found")
			}
			createInstanceReq.VSwitchId = tea.String(privateSubnet.RefId)
			createInstanceRes, err := a.ecsClient.CreateInstance(createInstanceReq)
			if err != nil {
				return errors.Wrap(err, "failed to create instance")
			}
			a.log.Infof("instance %s creating", tea.StringValue(createInstanceRes.Body.InstanceId))
			instanceIds = append(instanceIds, tea.StringValue(createInstanceRes.Body.InstanceId))
			node.InstanceId = tea.StringValue(createInstanceRes.Body.InstanceId)
			if nodeGroup.DataDiskSize != 0 {
				dataDiskName := fmt.Sprintf("%s-%s-data-disk", cluster.Name, node.Name)
				dataDiskRes, err := a.ecsClient.CreateDisk(&ecs20140526.CreateDiskRequest{
					RegionId:     tea.String(cluster.Region),
					Size:         tea.Int32(nodeGroup.DataDiskSize),
					DiskCategory: tea.String("cloud_ssd"),
					InstanceId:   createInstanceRes.Body.InstanceId,
					DiskName:     tea.String(dataDiskName),
				})
				if err != nil {
					return errors.Wrap(err, "failed to create data disk")
				}
				cluster.AddCloudResource(&CloudResource{
					Name:         dataDiskName,
					RefId:        tea.StringValue(dataDiskRes.Body.DiskId),
					AssociatedId: node.InstanceId,
					Type:         ResourceType_DATA_DEVICE,
				})
			}
		}
	}

	timeOutNumber := 0
	instanceFinishNumber := 0
	instanceCount := len(instanceIds)
	if instanceCount == 0 {
		return nil
	}
	for {
		if instanceFinishNumber >= instanceCount {
			break
		}
		if timeOutNumber > (TimeOutCountNumber * instanceCount) {
			return errors.New("timeout")
		}
		time.Sleep(time.Second * TimeOutSecond)
		timeOutNumber++

		var pageNumber int32 = 1
		instanceStatus := make([]*ecs20140526.DescribeInstanceStatusResponseBodyInstanceStatusesInstanceStatus, 0)
		for {
			instancesStatus, err := a.ecsClient.DescribeInstanceStatus(&ecs20140526.DescribeInstanceStatusRequest{
				RegionId:   tea.String(cluster.Region),
				InstanceId: tea.StringSlice(instanceIds),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(50),
			})
			if err != nil {
				return errors.Wrap(err, "failed to describe instance status")
			}
			instanceStatus = append(instanceStatus, instancesStatus.Body.InstanceStatuses.InstanceStatus...)
			if len(instancesStatus.Body.InstanceStatuses.InstanceStatus) < 50 {
				break
			}
			pageNumber++
		}
		for _, instanceStatus := range instanceStatus {
			if tea.StringValue(instanceStatus.Status) == "Stopped" {
				_, err := a.ecsClient.StartInstance(&ecs20140526.StartInstanceRequest{
					InstanceId: instanceStatus.InstanceId,
				})
				if err != nil {
					return errors.Wrap(err, "failed to start instance")
				}
				a.log.Infof("instance %s starting", tea.StringValue(instanceStatus.InstanceId))
				time.Sleep(time.Second)
			}
			if tea.StringValue(instanceStatus.Status) == "Running" {
				instanceFinishNumber++
				a.log.Infof("instance %s created successfully", tea.StringValue(instanceStatus.InstanceId))
			}
		}
	}
	for _, node := range cluster.Nodes {
		if node.Status != NodeStatus_NODE_CREATING || node.InstanceId == "" {
			continue
		}
		netWorkInterface, err := a.ecsClient.DescribeNetworkInterfaces(&ecs20140526.DescribeNetworkInterfacesRequest{
			RegionId:   tea.String(cluster.Region),
			InstanceId: tea.String(node.InstanceId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe instance attribute")
		}
		if len(netWorkInterface.Body.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
			return errors.New("network interface not found")
		}
		node.Ip = tea.StringValue(netWorkInterface.Body.NetworkInterfaceSets.NetworkInterfaceSet[0].PrivateIpAddress)
		node.User = "root"
		time.Sleep(time.Second)
	}
	return nil
}

func (a *AliCloudUsecase) ManageBostionHost(ctx context.Context, cluster *Cluster) error {
	if cluster.BostionHost == nil {
		return nil
	}
	if cluster.BostionHost.Status == NodeStatus_NODE_DELETING {
		if cluster.BostionHost.InstanceId == "" {
			return nil
		}
		_, err := a.ecsClient.DeleteInstance(&ecs20140526.DeleteInstanceRequest{
			InstanceId:            tea.String(cluster.BostionHost.InstanceId),
			Force:                 tea.Bool(true),
			TerminateSubscription: tea.Bool(true),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete instance")
		}
		cluster.BostionHost.InstanceId = ""
		return nil
	}
	if cluster.BostionHost.Status != NodeStatus_NODE_CREATING {
		return nil
	}
	// Get key pair
	keyPair := cluster.GetSingleCloudResource(ResourceType_KEY_PAIR)
	if keyPair == nil {
		return errors.New("key pair not found")
	}

	// sg
	sg := cluster.GetSingleCloudResource(ResourceType_SECURITY_GROUP)
	if sg == nil {
		return errors.New("security group not found in the ManageBostionHost")
	}
	// subnet
	publicVSwitch := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
		ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PUBLIC,
	})
	if publicVSwitch == nil {
		return errors.New("public subnet not found in the ManageBostionHost")
	}
	instanceType := ""
	imageId := ""
	for _, ng := range cluster.NodeGroups {
		if ng.Type == NodeGroupType_NORMAL {
			instanceType = ng.InstanceType
			imageId = ng.Image
			cluster.BostionHost.Arch = ng.Arch
			cluster.BostionHost.Image = ng.Image
			break
		}
	}
	bastionName := fmt.Sprintf("%s-bastion", cluster.Name)
	bastionHostRes, err := a.ecsClient.CreateInstance(&ecs20140526.CreateInstanceRequest{
		RegionId:                tea.String(cluster.Region),
		InstanceName:            tea.String(bastionName),
		InstanceType:            tea.String(instanceType),
		SecurityGroupId:         tea.String(sg.RefId),
		VSwitchId:               tea.String(publicVSwitch.RefId),
		KeyPairName:             tea.String(keyPair.RefId),
		ImageId:                 tea.String(imageId),
		InstanceChargeType:      tea.String("PostPaid"),
		SpotStrategy:            tea.String("NoSpot"),
		InternetMaxBandwidthIn:  tea.Int32(10),
		InternetMaxBandwidthOut: tea.Int32(5),
		SystemDisk: &ecs20140526.CreateInstanceRequestSystemDisk{
			Size:     tea.Int32(30),
			Category: tea.String("cloud_ssd"),
		},
		Tag: []*ecs20140526.CreateInstanceRequestTag{
			{
				Key:   tea.String(ResourceTypeKeyValue_NAME.String()),
				Value: tea.String(bastionName),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create bastion host")
	}
	cluster.BostionHost.InstanceId = tea.StringValue(bastionHostRes.Body.InstanceId)
	timeOutNumber := 0
	bostionHostRuning := false
	for {
		if timeOutNumber > TimeOutCountNumber || bostionHostRuning {
			break
		}
		time.Sleep(time.Second * TimeOutSecond)
		timeOutNumber++
		instanceStatus, err := a.ecsClient.DescribeInstanceStatus(&ecs20140526.DescribeInstanceStatusRequest{
			RegionId: tea.String(cluster.Region),
			InstanceId: tea.StringSlice([]string{
				cluster.BostionHost.InstanceId,
			}),
			PageNumber: tea.Int32(1),
			PageSize:   tea.Int32(1),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe instance status")
		}
		for _, status := range instanceStatus.Body.InstanceStatuses.InstanceStatus {
			if tea.StringValue(status.Status) == "Stopped" {
				_, err := a.ecsClient.StartInstance(&ecs20140526.StartInstanceRequest{
					InstanceId: status.InstanceId,
				})
				if err != nil {
					return errors.Wrap(err, "failed to start instance")
				}
			}
			if tea.StringValue(status.Status) == "Running" {
				bostionHostRuning = true
				break
			}
		}
	}
	if !bostionHostRuning {
		return errors.New("bastion host create failed")
	}
	// eip
	ipaddressRes, err := a.ecsClient.AllocatePublicIpAddress(&ecs20140526.AllocatePublicIpAddressRequest{
		InstanceId: tea.String(cluster.BostionHost.InstanceId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to allocate public ip address")
	}
	cluster.BostionHost.ExternalIp = tea.StringValue(ipaddressRes.Body.IpAddress)
	netWorkInterface, err := a.ecsClient.DescribeNetworkInterfaces(&ecs20140526.DescribeNetworkInterfacesRequest{
		RegionId:   tea.String(cluster.Region),
		InstanceId: tea.String(cluster.BostionHost.InstanceId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe instance attribute")
	}
	if len(netWorkInterface.Body.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
		return errors.New("network interface not found")
	}
	cluster.BostionHost.InternalIp = tea.StringValue(netWorkInterface.Body.NetworkInterfaceSets.NetworkInterfaceSet[0].PrivateIpAddress)
	instanceRes, err := a.ecsClient.DescribeInstanceAttribute(&ecs20140526.DescribeInstanceAttributeRequest{
		InstanceId: tea.String(cluster.BostionHost.InstanceId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe instance attribute")
	}
	cluster.BostionHost.User = "root"
	cluster.BostionHost.Os = "Linux"
	cluster.BostionHost.Cpu = tea.Int32Value(instanceRes.Body.Cpu)
	cluster.BostionHost.Memory = int32(math.Ceil(float64(tea.Int32Value(instanceRes.Body.Memory)) / float64(1024)))
	a.log.Infof("bastion host %s created successfully", bastionName)
	return nil
}

func (a *AliCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	// Delete SLB
	for _, v := range cluster.GetCloudResource(ResourceType_LOAD_BALANCER) {
		res, err := a.slbClient.DescribeLoadBalancers(&slb20140515.DescribeLoadBalancersRequest{
			RegionId:       tea.String(cluster.Region),
			LoadBalancerId: tea.String(v.RefId),
			PageNumber:     tea.Int32(1),
			PageSize:       tea.Int32(1),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe load balancers")
		}
		if tea.Int32Value(res.Body.TotalCount) == 0 {
			cluster.DeleteCloudResourceByID(ResourceType_LOAD_BALANCER, v.Id)
			continue
		}
		_, err = a.slbClient.DeleteLoadBalancer(&slb20140515.DeleteLoadBalancerRequest{
			RegionId:       tea.String(cluster.Region),
			LoadBalancerId: tea.String(v.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete SLB")
		}
		cluster.DeleteCloudResourceByID(ResourceType_LOAD_BALANCER, v.Id)
	}
	// delete sg
	for _, sg := range cluster.GetCloudResource(ResourceType_SECURITY_GROUP) {
		res, err := a.ecsClient.DescribeSecurityGroups(&ecs20140526.DescribeSecurityGroupsRequest{
			RegionId:        tea.String(cluster.Region),
			SecurityGroupId: tea.String(sg.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe security group")
		}
		if tea.Int32Value(res.Body.TotalCount) == 0 {
			cluster.DeleteCloudResourceByID(ResourceType_SECURITY_GROUP, sg.Id)
			continue
		}
		_, err = a.ecsClient.DeleteSecurityGroup(&ecs20140526.DeleteSecurityGroupRequest{
			RegionId:        tea.String(cluster.Region),
			SecurityGroupId: tea.String(sg.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete security group")
		}
		cluster.DeleteCloudResourceByID(ResourceType_SECURITY_GROUP, sg.Id)
	}
	// delete eip
	eipIds := make([]string, 0)
	for _, eip := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
		res, err := a.vpcClient.DescribeEipAddresses(&vpc20160428.DescribeEipAddressesRequest{
			RegionId:     tea.String(cluster.Region),
			AllocationId: tea.String(eip.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe eip")
		}
		if tea.Int32Value(res.Body.TotalCount) == 0 {
			cluster.DeleteCloudResourceByID(ResourceType_ELASTIC_IP, eip.Id)
			continue
		}

		_, err = a.vpcClient.UnassociateEipAddress(&vpc20160428.UnassociateEipAddressRequest{
			RegionId:     tea.String(cluster.Region),
			AllocationId: tea.String(eip.RefId),
			InstanceId:   res.Body.EipAddresses.EipAddress[0].InstanceId,
			Force:        tea.Bool(true),
		})
		if err != nil {
			a.log.Warnf("failed to disassociate EIP %s: %v", eip.RefId, err)
		}
		eipIds = append(eipIds, eip.RefId)
	}
	// wait eip status to be available
	timeOutNumber := 0
	eipsOk := false
	for {
		time.Sleep(time.Second * TimeOutSecond)
		if timeOutNumber > TimeOutCountNumber || eipsOk {
			break
		}
		timeOutNumber++
		res, err := a.vpcClient.DescribeEipAddresses(&vpc20160428.DescribeEipAddressesRequest{
			RegionId:     tea.String(cluster.Region),
			Status:       tea.String("Available"),
			AllocationId: tea.String(strings.Join(eipIds, ",")),
			PageNumber:   tea.Int32(1),
			PageSize:     tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe nat gateway")
		}
		if tea.Int32Value(res.Body.TotalCount) == int32(len(eipIds)) {
			eipsOk = true
			break
		}
	}
	if !eipsOk {
		return errors.New("eip delete failed")
	}

	// Release EIP
	for _, eipid := range eipIds {
		_, err := a.vpcClient.ReleaseEipAddress(&vpc20160428.ReleaseEipAddressRequest{
			RegionId:     tea.String(cluster.Region),
			AllocationId: tea.String(eipid),
		})
		if err != nil {
			a.log.Warnf("failed to release EIP %s: %v", eipid, err)
		}
	}
	cluster.DeleteCloudResource(ResourceType_ELASTIC_IP)
	time.Sleep(time.Second * TimeOutSecond)

	// Delete NAT Gateways
	for _, nat := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
		// Delete NAT Gateway
		_, err := a.vpcClient.DeleteNatGateway(&vpc20160428.DeleteNatGatewayRequest{
			RegionId:     tea.String(cluster.Region),
			NatGatewayId: tea.String(nat.RefId),
			Force:        tea.Bool(true),
		})
		if err != nil {
			a.log.Warnf("failed to delete NAT Gateway %s: %v", nat.RefId, err)
		}
		time.Sleep(time.Second * 5 * TimeOutSecond)
		cluster.DeleteCloudResourceByID(ResourceType_NAT_GATEWAY, nat.Id)
	}

	// Delete Route Tables
	for _, rt := range cluster.GetCloudResource(ResourceType_ROUTE_TABLE) {
		routeTables, err := a.vpcClient.DescribeRouteTableList(&vpc20160428.DescribeRouteTableListRequest{
			RegionId:     tea.String(cluster.Region),
			RouteTableId: tea.String(rt.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe route table")
		}
		for _, v := range routeTables.Body.RouterTableList.RouterTableListType {
			if v.VSwitchIds == nil {
				continue
			}
			for _, vs := range v.VSwitchIds.VSwitchId {
				_, err = a.vpcClient.UnassociateRouteTable(&vpc20160428.UnassociateRouteTableRequest{
					RegionId:     tea.String(cluster.Region),
					RouteTableId: tea.String(rt.RefId),
					VSwitchId:    vs,
				})
				if err != nil {
					return errors.Wrap(err, "failed to unassociate route table")
				}
			}
		}
		_, err = a.vpcClient.DeleteRouteTable(&vpc20160428.DeleteRouteTableRequest{
			RegionId:     tea.String(cluster.Region),
			RouteTableId: tea.String(rt.RefId),
		})
		if err != nil {
			a.log.Warnf("failed to delete route table %s: %v", rt.RefId, err)
		}
		cluster.DeleteCloudResourceByID(ResourceType_ROUTE_TABLE, rt.Id)
	}

	// Delete VSwitches (Subnets)
	vswitches := cluster.GetCloudResource(ResourceType_SUBNET)
	for _, vsw := range vswitches {
		_, err := a.vpcClient.DeleteVSwitch(&vpc20160428.DeleteVSwitchRequest{
			RegionId:  tea.String(cluster.Region),
			VSwitchId: tea.String(vsw.RefId),
		})
		if err != nil {
			a.log.Warnf("failed to delete VSwitch %s: %v", vsw.RefId, err)
		}
		time.Sleep(time.Second)
		cluster.DeleteCloudResourceByID(ResourceType_SUBNET, vsw.Id)
	}

	// Delete VPC
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc != nil {
		_, err := a.vpcClient.DeleteVpc(&vpc20160428.DeleteVpcRequest{
			RegionId: tea.String(cluster.Region),
			VpcId:    tea.String(vpc.RefId),
		})
		if err != nil {
			a.log.Warnf("failed to delete VPC %s: %v", vpc.RefId, err)
		}
		cluster.DeleteCloudResource(ResourceType_VPC)
	}
	return nil
}

func (a *AliCloudUsecase) createVPC(ctx context.Context, cluster *Cluster) error {
	vpcs := make([]*vpc20160428.DescribeVpcsResponseBodyVpcsVpc, 0)
	pageNumber := 1
	for {
		vpcsRes, err := a.vpcClient.DescribeVpcs(&vpc20160428.DescribeVpcsRequest{
			RegionId:   tea.String(cluster.Region),
			PageNumber: tea.Int32(int32(pageNumber)),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe VPCs")
		}
		vpcs = append(vpcs, vpcsRes.Body.Vpcs.Vpc...)
		if len(vpcsRes.Body.Vpcs.Vpc) < 50 {
			break
		}
		pageNumber++
	}
	for _, vpc := range vpcs {
		if v := cluster.GetCloudResourceByRefID(ResourceType_VPC, tea.StringValue(vpc.VpcId)); v != nil {
			a.log.Info("vpc already exists ", "vpc ", v.Name)
			return nil
		}
	}
	if len(cluster.GetCloudResource(ResourceType_VPC)) > 0 {
		cluster.DeleteCloudResource(ResourceType_VPC)
	}

	vpcName := cluster.Name + "-vpc"
	vpcTags := GetTags()
	vpcTags[ResourceTypeKeyValue_NAME] = vpcName
	for _, vpc := range vpcs {
		if len(cluster.GetCloudResource(ResourceType_VPC)) > 0 {
			return nil
		}
		if tea.StringValue(vpc.CidrBlock) != VpcCIDR {
			continue
		}
		a.createVpcTags(cluster.Region, tea.StringValue(vpc.VpcId), "VPC", vpcTags)
		cluster.AddCloudResource(&CloudResource{
			RefId: tea.StringValue(vpc.VpcId),
			Name:  vpcName,
			Type:  ResourceType_VPC,
			Tags:  cluster.EncodeTags(vpcTags),
		})
		a.log.Infof("vpc %s already exists", vpcName)
	}
	if len(cluster.GetCloudResource(ResourceType_VPC)) > 0 {
		return nil
	}
	vpcResponce, err := a.vpcClient.CreateVpc(&vpc20160428.CreateVpcRequest{
		VpcName:   tea.String(cluster.Name + "-vpc"),
		RegionId:  tea.String(cluster.Region),
		CidrBlock: tea.String(VpcCIDR),
	})
	if err := a.handlerError(err); err != nil {
		return err
	}
	// wait vpc status to be available
	timeOutNumber := 0
	vpcOk := false
	for {
		time.Sleep(time.Second * TimeOutSecond)
		if timeOutNumber > TimeOutCountNumber || vpcOk {
			break
		}
		timeOutNumber++
		res, err := a.vpcClient.DescribeVpcs(&vpc20160428.DescribeVpcsRequest{
			RegionId:   tea.String(cluster.Region),
			VpcId:      vpcResponce.Body.VpcId,
			PageNumber: tea.Int32(1),
			PageSize:   tea.Int32(10),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe nat gateway")
		}
		for _, v := range res.Body.Vpcs.Vpc {
			if tea.StringValue(v.Status) == "Available" {
				vpcOk = true
				break
			}
		}
	}
	if !vpcOk {
		return errors.New("vpc not available")
	}
	cluster.AddCloudResource(&CloudResource{
		RefId: tea.StringValue(vpcResponce.Body.VpcId),
		Name:  vpcName,
		Type:  ResourceType_VPC,
	})
	a.log.Infof("vpc %s created", vpcName)
	return nil
}

func (a *AliCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	subnets := make([]*vpc20160428.DescribeVSwitchesResponseBodyVSwitchesVSwitch, 0)
	pageNumber := 1
	for {
		existingSubnetRes, err := a.vpcClient.DescribeVSwitches(&vpc20160428.DescribeVSwitchesRequest{
			VpcId:      tea.String(vpc.RefId),
			PageNumber: tea.Int32(int32(pageNumber)),
			PageSize:   tea.Int32(50),
		})
		if err != nil || tea.Int32Value(existingSubnetRes.StatusCode) != http.StatusOK {
			return err
		}
		subnets = append(subnets, existingSubnetRes.Body.VSwitches.VSwitch...)
		if len(existingSubnetRes.Body.VSwitches.VSwitch) < 50 {
			break
		}
		pageNumber++
	}

	// clear history subnet
	for _, subnetCloudResource := range cluster.GetCloudResource(ResourceType_SUBNET) {
		subnetCloudResourceExits := false
		for _, subnet := range subnets {
			if subnetCloudResource.RefId == tea.StringValue(subnet.VSwitchId) {
				subnetCloudResourceExits = true
				break
			}
		}
		if !subnetCloudResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_SUBNET, subnetCloudResource.RefId)
		}
	}

	// One subnet for one available zone
	subnetExitsCidrs := make([]string, 0)
	zoneSubnets := make(map[string]*vpc20160428.DescribeVSwitchesResponseBodyVSwitchesVSwitch)
	for _, subnet := range subnets {
		if subnet.CidrBlock == nil || subnet.VSwitchId == nil {
			continue
		}
		subnetExitsCidrs = append(subnetExitsCidrs, tea.StringValue(subnet.CidrBlock))
		if subnet.ZoneId == nil {
			continue
		}
		if _, ok := zoneSubnets[tea.StringValue(subnet.ZoneId)]; ok {
			continue
		}
		zoneSubnets[tea.StringValue(subnet.ZoneId)] = subnet
	}
	for zoneId, subnet := range zoneSubnets {
		if cluster.GetCloudResourceByRefID(ResourceType_SUBNET, tea.StringValue(subnet.VSwitchId)) != nil {
			a.log.Infof("subnet %s already exists", tea.StringValue(subnet.VSwitchId))
			continue
		}
		name := a.getSubnetName(cluster.Name, zoneId)
		tags := GetTags()
		tags[ResourceTypeKeyValue_ZONE] = zoneId
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_NAME] = name
		a.createVpcTags(cluster.Region, tea.StringValue(subnet.VSwitchId), "VSWITCH", tags)
		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: tea.StringValue(subnet.VSwitchId),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_SUBNET,
			Value: tea.StringValue(subnet.CidrBlock),
		})
		a.log.Infof("subnet %s already exists", name)
	}

	// Create private subnets
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		name := a.getSubnetName(cluster.Name, az.RefId)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_ZONE] = az.RefId
		if cluster.GetCloudResourceByTags(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: name}) != nil {
			continue
		}
		cidr, err := utils.GenerateSubnet(VpcCIDR, subnetExitsCidrs)
		if err != nil {
			return err
		}
		subnetExitsCidrs = append(subnetExitsCidrs, cidr)
		privateSubnetTags := make([]*vpc20160428.CreateVSwitchRequestTag, 0)
		for k, v := range tags {
			privateSubnetTags = append(privateSubnetTags, &vpc20160428.CreateVSwitchRequestTag{
				Key:   tea.String(k.String()),
				Value: tea.String(cast.ToString(v)),
			})
		}
		subnetOutput, err := a.vpcClient.CreateVSwitch(&vpc20160428.CreateVSwitchRequest{
			VSwitchName: tea.String(name),
			RegionId:    tea.String(cluster.Region),
			VpcId:       tea.String(vpc.RefId),
			CidrBlock:   tea.String(cidr),
			ZoneId:      tea.String(az.RefId),
			Tag:         privateSubnetTags,
		})
		if err != nil {
			return errors.Wrap(err, "failed to create private subnet")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(subnetOutput.Body.VSwitchId),
			AssociatedId: vpc.RefId,
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SUBNET,
			Value:        cidr,
		})
		a.log.Infof("private subnet %s created", name)
		time.Sleep(time.Second * TimeOutSecond)
	}
	if cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PUBLIC}) == nil {
		name := fmt.Sprintf("%s-public", cluster.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
		cidr, err := utils.GenerateSubnet(VpcCIDR, subnetExitsCidrs)
		if err != nil {
			return err
		}
		zone := cluster.GetSingleCloudResource(ResourceType_AVAILABILITY_ZONES)
		subnetOutput, err := a.vpcClient.CreateVSwitch(&vpc20160428.CreateVSwitchRequest{
			VSwitchName: tea.String(name),
			RegionId:    tea.String(cluster.Region),
			VpcId:       tea.String(vpc.RefId),
			CidrBlock:   tea.String(cidr),
			ZoneId:      tea.String(zone.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to create private subnet")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(subnetOutput.Body.VSwitchId),
			AssociatedId: vpc.RefId,
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SUBNET,
		})
		a.log.Infof("public subnet %s created", name)
		time.Sleep(time.Second * TimeOutSecond)
	}
	return nil
}

func (a *AliCloudUsecase) createEips(_ context.Context, cluster *Cluster) error {
	// Get Elastic IP
	eips := make([]*vpc20160428.DescribeEipAddressesResponseBodyEipAddressesEipAddress, 0)
	var pageNumber int32 = 1
	for {
		eipRes, err := a.vpcClient.DescribeEipAddresses(&vpc20160428.DescribeEipAddressesRequest{
			RegionId:   tea.String(cluster.Region),
			Status:     tea.String("Available"),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe eip addresses")
		}
		if eipRes.Body.EipAddresses == nil {
			break
		}
		eips = append(eips, eipRes.Body.EipAddresses.EipAddress...)
		if len(eipRes.Body.EipAddresses.EipAddress) < 50 {
			break
		}
		pageNumber++
	}
	// one zone one eip for nat gateway
	eipIds := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		name := a.getEipName(cluster.Name, az.RefId)
		tags := GetTags()
		tags[ResourceTypeKeyValue_ZONE] = az.RefId
		tags[ResourceTypeKeyValue_NAME] = name
		for _, eip := range eips {
			if tea.StringValue(eip.InstanceId) != "" {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, tea.StringValue(eip.AllocationId)) != nil {
				a.log.Infof("eip %s already exists", tea.StringValue(eip.AllocationId))
				continue
			}
			if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE: az.RefId}) != nil {
				break
			}
			cluster.AddCloudResource(&CloudResource{
				Name:  name,
				RefId: tea.StringValue(eip.AllocationId),
				Type:  ResourceType_ELASTIC_IP,
				Value: tea.StringValue(eip.IpAddress),
				Tags:  cluster.EncodeTags(tags),
			})
			eipIds = append(eipIds, tea.StringValue(eip.AllocationId))
			a.log.Infof("elastic ip %s already exists", tea.StringValue(eip.IpAddress))
			break
		}
		if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE: az.RefId}) != nil {
			continue
		}
		// Allocate new EIP
		eipRes, err := a.vpcClient.AllocateEipAddress(&vpc20160428.AllocateEipAddressRequest{
			RegionId:           tea.String(cluster.Region),
			Bandwidth:          tea.String("5"),
			InternetChargeType: tea.String("PayByTraffic"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to allocate eip address")
		}
		eipIds = append(eipIds, tea.StringValue(eipRes.Body.AllocationId))
		// Add tags to EIP
		err = a.createVpcTags(cluster.Region, tea.StringValue(eipRes.Body.AllocationId), "EIP", tags)
		if err != nil {
			return errors.Wrap(err, "failed to tag eip")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: tea.StringValue(eipRes.Body.AllocationId),
			Type:  ResourceType_ELASTIC_IP,
			Value: tea.StringValue(eipRes.Body.EipAddress),
			Tags:  cluster.EncodeTags(tags),
		})
		a.log.Infof("elastic ip %s allocated for zone %s", tea.StringValue(eipRes.Body.EipAddress), az.RefId)
	}
	// wait eip status to be available
	timeOutNumber := 0
	eipsOk := false
	for {
		time.Sleep(time.Second * TimeOutSecond)
		if timeOutNumber > TimeOutCountNumber || eipsOk {
			break
		}
		timeOutNumber++
		res, err := a.vpcClient.DescribeEipAddresses(&vpc20160428.DescribeEipAddressesRequest{
			RegionId:     tea.String(cluster.Region),
			Status:       tea.String("Available"),
			AllocationId: tea.String(strings.Join(eipIds, ",")),
			PageNumber:   tea.Int32(1),
			PageSize:     tea.Int32(100),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe nat gateway")
		}
		if tea.Int32Value(res.Body.TotalCount) == int32(len(eipIds)) {
			eipsOk = true
			break
		}
	}
	if !eipsOk {
		return errors.New("eips not ready")
	}
	return nil
}

func (a *AliCloudUsecase) createNatGateways(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingNatGateways := make([]*vpc20160428.DescribeNatGatewaysResponseBodyNatGatewaysNatGateway, 0)
	var pageNumber int32 = 1
	for {
		existingNatGatewayRes, err := a.vpcClient.DescribeNatGateways(&vpc20160428.DescribeNatGatewaysRequest{
			VpcId:       tea.String(vpc.RefId),
			Status:      tea.String("Available"),
			RegionId:    tea.String(cluster.Region),
			PageNumber:  tea.Int32(pageNumber),
			PageSize:    tea.Int32(50),
			NetworkType: tea.String("internet"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe nat gateways")
		}
		existingNatGateways = append(existingNatGateways, existingNatGatewayRes.Body.NatGateways.NatGateway...)
		if len(existingNatGatewayRes.Body.NatGateways.NatGateway) < 50 {
			break
		}
		pageNumber++
	}
	for _, natGateway := range existingNatGateways {
		if cluster.GetCloudResourceByID(ResourceType_NAT_GATEWAY, tea.StringValue(natGateway.NatGatewayId)) != nil {
			a.log.Infof("nat gateway %s already exists", tea.StringValue(natGateway.NatGatewayId))
			continue
		}
		// check public subnet
		if natGateway.NatGatewayPrivateInfo == nil || natGateway.NatGatewayPrivateInfo.VswitchId == nil {
			continue
		}
		subnetCloudResource := cluster.GetCloudResourceByRefID(ResourceType_SUBNET, tea.StringValue(natGateway.NatGatewayPrivateInfo.VswitchId))
		if subnetCloudResource == nil {
			continue
		}
		subnetCloudResourceMapTags := cluster.DecodeTags(subnetCloudResource.Tags)
		if val, ok := subnetCloudResourceMapTags[ResourceTypeKeyValue_ACCESS]; !ok || cast.ToInt32(val) != int32(ResourceTypeKeyValue_ACCESS_PRIVATE.Number()) {
			continue
		}
		// eip
		eipId := ""
		for _, eip := range natGateway.IpLists.IpList {
			eipId = tea.StringValue(eip.AllocationId)
		}
		if eipId != "" {
			if cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, eipId) == nil {
				continue
			}
		}
		tags := GetTags()
		name := a.getNatgatewayName(cluster.Name, cast.ToString(subnetCloudResourceMapTags[ResourceTypeKeyValue_ZONE]))
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ZONE] = subnetCloudResourceMapTags[ResourceTypeKeyValue_ZONE]
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(natGateway.NatGatewayId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: subnetCloudResource.RefId,
			Value:        eipId,
		})
		a.log.Infof("nat gateway %s already exists", tea.StringValue(natGateway.Name))
	}

	// create NAT Gateways for each AZ
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natgatewayResource := cluster.GetCloudResourceByTagsSingle(ResourceType_NAT_GATEWAY, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE: az.RefId})
		// value is the eip id
		if natgatewayResource != nil && natgatewayResource.Value != "" {
			continue
		}
		// Get private subnet for the AZ
		privateSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
			ResourceTypeKeyValue_ZONE:   az.RefId,
		})
		if privateSubnet == nil {
			return errors.New("no private subnet found for AZ " + az.RefId)
		}
		// Get Elastic IP
		eip := cluster.GetCloudResourceByTagsSingle(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE: az.RefId})
		if eip == nil {
			return errors.New("no eip found for AZ " + az.RefId)
		}
		if natgatewayResource != nil && natgatewayResource.Value == "" {
			// Associate EIP with NAT Gateway
			_, err := a.vpcClient.AssociateEipAddress(&vpc20160428.AssociateEipAddressRequest{
				RegionId:     tea.String(cluster.Region),
				AllocationId: tea.String(eip.RefId),
				InstanceId:   tea.String(natgatewayResource.RefId),
				InstanceType: tea.String("Nat"),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate eip with nat gateway")
			}
			natgatewayResource.Value = eip.RefId
			continue
		}

		// Create NAT Gateway
		natGatewayName := a.getNatgatewayName(cluster.Name, az.RefId)
		natRes, err := a.vpcClient.CreateNatGateway(&vpc20160428.CreateNatGatewayRequest{
			RegionId:           tea.String(cluster.Region),
			VpcId:              tea.String(vpc.RefId),
			VSwitchId:          tea.String(privateSubnet.RefId),
			NatType:            tea.String("Enhanced"),
			NetworkType:        tea.String("internet"),
			Name:               tea.String(natGatewayName),
			InternetChargeType: tea.String("PayByLcu"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to create nat gateway")
		}
		a.log.Infof("nat gateway %s createing", tea.StringValue(natRes.Body.NatGatewayId))
		// wait nategateway status to be available
		timeOutNumber := 0
		natgatewayOk := false
		for {
			time.Sleep(time.Second * 3 * TimeOutSecond)
			if timeOutNumber > TimeOutCountNumber || natgatewayOk {
				break
			}
			timeOutNumber++
			res, err := a.vpcClient.DescribeNatGateways(&vpc20160428.DescribeNatGatewaysRequest{
				RegionId:     tea.String(cluster.Region),
				VpcId:        tea.String(vpc.RefId),
				NatGatewayId: natRes.Body.NatGatewayId,
				Name:         tea.String(natGatewayName),
				PageNumber:   tea.Int32(1),
				PageSize:     tea.Int32(10),
			})
			if err != nil {
				return errors.Wrap(err, "failed to describe nat gateway")
			}
			for _, v := range res.Body.NatGateways.NatGateway {
				if tea.StringValue(v.Status) == "Available" {
					natgatewayOk = true
					break
				}
			}
		}
		if !natgatewayOk {
			return errors.New("nat gateway " + tea.StringValue(natRes.Body.NatGatewayId) + " creation failed")
		}
		a.log.Infof("nat gateway %s created", tea.StringValue(natRes.Body.NatGatewayId))
		// Associate EIP with NAT Gateway
		_, err = a.vpcClient.AssociateEipAddress(&vpc20160428.AssociateEipAddressRequest{
			RegionId:     tea.String(cluster.Region),
			AllocationId: tea.String(eip.RefId),
			InstanceId:   natRes.Body.NatGatewayId,
			InstanceType: tea.String("Nat"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to associate eip with nat gateway")
		}
		// wait eip bind to natgateway
		time.Sleep(time.Second * 3 * TimeOutSecond)
		snatTableId := ""
		for _, v := range natRes.Body.SnatTableIds.SnatTableId {
			if tea.StringValue(v) != "" {
				snatTableId = tea.StringValue(v)
				break
			}
		}
		// Create natgateway SNAT
		_, err = a.vpcClient.CreateSnatEntry(&vpc20160428.CreateSnatEntryRequest{
			RegionId:        tea.String(cluster.Region),
			SourceVSwitchId: tea.String(privateSubnet.RefId),
			SnatIp:          tea.String(eip.Value),
			SnatEntryName:   tea.String(natGatewayName + "-snat"),
			SnatTableId:     tea.String(snatTableId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to create nat gateway snat")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         natGatewayName,
			RefId:        tea.StringValue(natRes.Body.NatGatewayId),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: privateSubnet.RefId,
			Value:        eip.RefId,
			Tags: cluster.EncodeTags(map[ResourceTypeKeyValue]any{
				ResourceTypeKeyValue_NAME:   natGatewayName,
				ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
				ResourceTypeKeyValue_ZONE:   az.RefId,
			}),
		})
	}

	return nil
}

func (a *AliCloudUsecase) createRouteTables(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	// List existing route tables
	var pageNumber int32 = 1
	existingRouteTables := make([]*vpc20160428.DescribeRouteTableListResponseBodyRouterTableListRouterTableListType, 0)
	for {
		routeTablesRes, err := a.vpcClient.DescribeRouteTableList(&vpc20160428.DescribeRouteTableListRequest{
			RegionId:   tea.String(cluster.Region),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe route tables")
		}
		existingRouteTables = append(existingRouteTables, routeTablesRes.Body.RouterTableList.RouterTableListType...)
		if len(routeTablesRes.Body.RouterTableList.RouterTableListType) < 50 {
			break
		}
		pageNumber++
	}

	// clear history route table
	for _, routeTableCloudResource := range cluster.GetCloudResource(ResourceType_ROUTE_TABLE) {
		routeTableCloudResourceExits := false
		for _, routeTable := range existingRouteTables {
			if routeTableCloudResource.RefId == tea.StringValue(routeTable.RouteTableId) {
				routeTableCloudResourceExits = true
				break
			}
		}
		if !routeTableCloudResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_ROUTE_TABLE, routeTableCloudResource.RefId)
		}
	}

	// Create private route tables (one per AZ)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		if cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE: az.RefId}) != nil {
			continue
		}
		privateRouteTableName := a.getPrivateRouteTableName(cluster.Name, az.RefId)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = privateRouteTableName
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_ZONE] = az.RefId
		// Create private route table
		privateRouteTableRes, err := a.vpcClient.CreateRouteTable(&vpc20160428.CreateRouteTableRequest{
			RegionId:       tea.String(cluster.Region),
			VpcId:          tea.String(vpc.RefId),
			RouteTableName: tea.String(privateRouteTableName),
			AssociateType:  tea.String("VSwitch"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to create private route table for AZ "+az.RefId)
		}
		cluster.AddCloudResource(&CloudResource{
			Name:  privateRouteTableName,
			RefId: tea.StringValue(privateRouteTableRes.Body.RouteTableId),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("private route table %s createing for AZ %s", tea.StringValue(privateRouteTableRes.Body.RouteTableId), az.RefId)
		// wait nategateway status to be available
		timeOutNumber := 0
		routeTableOk := false
		for {
			time.Sleep(time.Second * TimeOutSecond)
			if timeOutNumber > TimeOutCountNumber || routeTableOk {
				break
			}
			timeOutNumber++
			res, err := a.vpcClient.DescribeRouteTableList(&vpc20160428.DescribeRouteTableListRequest{
				RegionId:     tea.String(cluster.Region),
				VpcId:        tea.String(vpc.RefId),
				RouteTableId: privateRouteTableRes.Body.RouteTableId,
				PageNumber:   tea.Int32(1),
				PageSize:     tea.Int32(10),
			})
			if err != nil {
				return errors.Wrap(err, "failed to describe nat gateway")
			}
			for _, v := range res.Body.RouterTableList.RouterTableListType {
				if tea.StringValue(v.Status) == "Available" {
					routeTableOk = true
					break
				}
			}
		}
		if !routeTableOk {
			return errors.New("route table create timeout")
		}
		a.log.Infof("private route table %s created for AZ %s", tea.StringValue(privateRouteTableRes.Body.RouteTableId), az.RefId)
	}

	routeTables := cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, map[ResourceTypeKeyValue]any{
		ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
	})

	// Associate private subnets with private route table
	for _, routeTable := range routeTables {
		if len(routeTable.SubResources) != 0 {
			continue
		}
		routeTableTags := cluster.DecodeTags(routeTable.Tags)
		privateSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
			ResourceTypeKeyValue_ZONE:   routeTableTags[ResourceTypeKeyValue_ZONE],
		})
		res, err := a.vpcClient.AssociateRouteTable(&vpc20160428.AssociateRouteTableRequest{
			RegionId:     tea.String(cluster.Region),
			RouteTableId: tea.String(routeTable.RefId),
			VSwitchId:    tea.String(privateSubnet.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to associate private subnet")
		}
		cluster.AddSubCloudResource(ResourceType_SUBNET, routeTable.Id, &CloudResource{
			Type:  ResourceType_SUBNET,
			Name:  privateSubnet.Name,
			RefId: privateSubnet.RefId,
			Value: tea.StringValue(res.Body.RequestId),
		})
	}

	// wait
	time.Sleep(time.Second * 3 * TimeOutSecond)

	// Add route to NAT Gateway in private route table
	for _, routeTable := range routeTables {
		if routeTable.Value != "" {
			continue
		}
		routeTableTags := cluster.DecodeTags(routeTable.Tags)
		natGateway := cluster.GetCloudResourceByTagsSingle(ResourceType_NAT_GATEWAY, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ZONE: routeTableTags[ResourceTypeKeyValue_ZONE],
		})
		if natGateway == nil {
			return errors.New("nat gateway not found in route table tags")
		}
		privateSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
			ResourceTypeKeyValue_ZONE:   routeTableTags[ResourceTypeKeyValue_ZONE],
		})
		if privateSubnet == nil {
			return errors.New("private subnet not found in route table tags")
		}
		res, err := a.vpcClient.CreateRouteEntry(&vpc20160428.CreateRouteEntryRequest{
			RegionId:             tea.String(cluster.Region),
			RouteTableId:         tea.String(routeTable.RefId),
			DestinationCidrBlock: tea.String("0.0.0.0/0"),
			NextHopType:          tea.String("NatGateway"),
			NextHopId:            tea.String(natGateway.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add route to NAT Gateway")
		}
		routeTable.Value = tea.StringValue(res.Body.RouteEntryId)
	}
	return nil
}

func (a *AliCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	if len(cluster.SecurityGroups) == 0 {
		return nil
	}
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// List existing security groups
	var pageNumber int32 = 1
	existingSecurityGroups := make([]*ecs20140526.DescribeSecurityGroupsResponseBodySecurityGroupsSecurityGroup, 0)
	for {
		securityGroupsRes, err := a.ecsClient.DescribeSecurityGroups(&ecs20140526.DescribeSecurityGroupsRequest{
			RegionId:   tea.String(cluster.Region),
			VpcId:      tea.String(vpc.RefId),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe security groups")
		}
		existingSecurityGroups = append(existingSecurityGroups, securityGroupsRes.Body.SecurityGroups.SecurityGroup...)
		if len(securityGroupsRes.Body.SecurityGroups.SecurityGroup) < 50 {
			break
		}
		pageNumber++
	}

	// clear history security group
	for _, securityGroupCloudResource := range cluster.GetCloudResource(ResourceType_SECURITY_GROUP) {
		securityGroupCloudResourceExits := false
		for _, securityGroup := range existingSecurityGroups {
			if securityGroupCloudResource.RefId == tea.StringValue(securityGroup.SecurityGroupId) {
				securityGroupCloudResourceExits = true
				break
			}
		}
		if !securityGroupCloudResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_SECURITY_GROUP, securityGroupCloudResource.RefId)
		}
	}

	// Process existing security groups
	for _, securityGroup := range existingSecurityGroups {
		if cluster.GetCloudResourceByRefID(ResourceType_SECURITY_GROUP, tea.StringValue(securityGroup.SecurityGroupId)) != nil {
			a.log.Infof("security group %s already exists", tea.StringValue(securityGroup.SecurityGroupId))
			continue
		}
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = tea.StringValue(securityGroup.SecurityGroupName)
		cluster.AddCloudResource(&CloudResource{
			Name:         tea.StringValue(securityGroup.SecurityGroupName),
			RefId:        tea.StringValue(securityGroup.SecurityGroupId),
			Tags:         cluster.EncodeTags(tags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_SECURITY_GROUP,
		})
		a.log.Infof("security group %s already exists", tea.StringValue(securityGroup.SecurityGroupId))
	}

	sgName := a.getSgName(cluster.Name)
	sgCloudResource := cluster.GetCloudResourceByName(ResourceType_SECURITY_GROUP, sgName)
	if sgCloudResource == nil {
		// Create security group
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = sgName
		tags[ResourceTypeKeyValue_SECURITY_GROUP_TYPE] = ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER
		createSGReq := &ecs20140526.CreateSecurityGroupRequest{
			RegionId:          tea.String(cluster.Region),
			VpcId:             tea.String(vpc.RefId),
			SecurityGroupName: tea.String(sgName),
			SecurityGroupType: tea.String("normal"),
			Description:       tea.String(sgName),
		}
		sgRes, err := a.ecsClient.CreateSecurityGroup(createSGReq)
		if err != nil {
			return errors.Wrap(err, "failed to create security group")
		}
		sgCloudResource = &CloudResource{
			Name:         sgName,
			RefId:        tea.StringValue(sgRes.Body.SecurityGroupId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SECURITY_GROUP,
			AssociatedId: vpc.RefId,
		}
		cluster.AddCloudResource(sgCloudResource)
		a.log.Infof("security group %s created", tea.StringValue(sgRes.Body.SecurityGroupId))
	}

	// Add security group rules
	sgRuleRes, err := a.ecsClient.DescribeSecurityGroupAttribute(&ecs20140526.DescribeSecurityGroupAttributeRequest{
		RegionId:        tea.String(cluster.Region),
		SecurityGroupId: tea.String(sgCloudResource.RefId),
		MaxResults:      tea.Int32(1000),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe security group attribute")
	}
	// clear not exits rules
	needClearRuleIds := make([]string, 0)
	exitsRules := make([]string, 0)
	for _, sgRule := range sgRuleRes.Body.Permissions.Permission {
		exits := false
		for _, clusterSgRule := range cluster.SecurityGroups {
			clusterSgRuelVals := strings.Join([]string{
				clusterSgRule.Protocol, clusterSgRule.IpCidr,
				fmt.Sprintf("%d/%d", clusterSgRule.StartPort, clusterSgRule.EndPort)},
				"-")
			sgRuleVals := strings.Join([]string{
				tea.StringValue(sgRule.IpProtocol), tea.StringValue(sgRule.SourceCidrIp),
				tea.StringValue(sgRule.PortRange)},
				"-")
			if clusterSgRuelVals == sgRuleVals {
				exits = true
				exitsRules = append(exitsRules, sgRuleVals)
				break
			}
		}
		if !exits {
			needClearRuleIds = append(needClearRuleIds, tea.StringValue(sgRule.SecurityGroupRuleId))
		}
	}
	if len(needClearRuleIds) != 0 {
		_, err = a.ecsClient.RevokeSecurityGroup(&ecs20140526.RevokeSecurityGroupRequest{
			RegionId:            tea.String(cluster.Region),
			SecurityGroupId:     tea.String(sgCloudResource.RefId),
			SecurityGroupRuleId: tea.StringSlice(needClearRuleIds),
		})
		if err != nil {
			return errors.Wrap(err, "failed to clear security group rule")
		}
	}

	for _, sgRule := range cluster.SecurityGroups {
		sgRuelVals := strings.Join([]string{
			sgRule.Protocol, sgRule.IpCidr,
			fmt.Sprintf("%d/%d", sgRule.StartPort, sgRule.EndPort)},
			"-")
		if utils.InArray(sgRuelVals, exitsRules) {
			continue
		}
		_, err = a.ecsClient.AuthorizeSecurityGroup(&ecs20140526.AuthorizeSecurityGroupRequest{
			RegionId:        tea.String(cluster.Region),
			SecurityGroupId: tea.String(sgCloudResource.RefId),
			IpProtocol:      tea.String(sgRule.Protocol),
			PortRange:       tea.String(fmt.Sprintf("%d/%d", sgRule.StartPort, sgRule.EndPort)),
			SourceCidrIp:    tea.String(sgRule.IpCidr),
			Description:     tea.String(fmt.Sprintf("Allow %s access", sgRule.Protocol)),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add security group rule")
		}
		cluster.AddSubCloudResource(ResourceType_SECURITY_GROUP, sgCloudResource.Id, &CloudResource{
			Type:  ResourceType_SECURITY_GROUP,
			Value: sgRuelVals,
		})
	}
	return nil
}

func (a *AliCloudUsecase) createSLB(_ context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	// Check if SLB already exists
	name := fmt.Sprintf("%s-slb", cluster.Name)
	if cluster.GetCloudResourceByName(ResourceType_LOAD_BALANCER, name) != nil {
		a.log.Infof("slb %s already exists", name)
		return nil
	}
	// List existing SLBs
	var pageNumber int32 = 1
	for {
		loadBalancers, err := a.slbClient.DescribeLoadBalancers(&slb20140515.DescribeLoadBalancersRequest{
			RegionId:   tea.String(cluster.Region),
			VpcId:      tea.String(vpc.RefId),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe load balancers")
		}
		for _, lb := range loadBalancers.Body.LoadBalancers.LoadBalancer {
			if tea.StringValue(lb.LoadBalancerName) == name {
				if cluster.GetCloudResourceByRefID(ResourceType_LOAD_BALANCER, tea.StringValue(lb.LoadBalancerId)) != nil {
					continue
				}
				cluster.AddCloudResource(&CloudResource{
					Name:  tea.StringValue(lb.LoadBalancerName),
					RefId: tea.StringValue(lb.LoadBalancerId),
					Type:  ResourceType_LOAD_BALANCER,
				})
				a.log.Infof("slb %s already exists", tea.StringValue(lb.LoadBalancerName))
				return nil
			}
		}

		if len(loadBalancers.Body.LoadBalancers.LoadBalancer) < 50 {
			break
		}
		pageNumber++
	}

	// Create SLB
	slbRes, err := a.slbClient.CreateLoadBalancer(&slb20140515.CreateLoadBalancerRequest{
		RegionId:           tea.String(cluster.Region),
		VpcId:              tea.String(vpc.RefId),
		LoadBalancerName:   tea.String(name),
		PayType:            tea.String("PayOnDemand"),
		AddressType:        tea.String("internet"),
		InternetChargeType: tea.String("paybytraffic"),
		InstanceChargeType: tea.String("PayByCLCU"),
	})
	if err != nil {
		return errors.Wrap(err, "failed to create SLB")
	}
	cluster.AddCloudResource(&CloudResource{
		Name:  name,
		RefId: tea.StringValue(slbRes.Body.LoadBalancerId),
		Type:  ResourceType_LOAD_BALANCER,
		Value: tea.StringValue(slbRes.Body.Address),
	})
	return nil
}

func (a *AliCloudUsecase) getIntanceTypeFamilies(nodeGroupType NodeGroupType) string {
	switch nodeGroupType {
	case NodeGroupType_NORMAL:
		return "ecs.g6"
	case NodeGroupType_HIGH_COMPUTATION:
		return "ecs.c6"
	case NodeGroupType_GPU_ACCELERATERD:
		return "ecs.gn6i"
	case NodeGroupType_HIGH_MEMORY:
		return "ecs.r6"
	case NodeGroupType_LARGE_HARD_DISK:
		return "ecs.g6"
	default:
		return "ecs.g6"
	}
}

func (a *AliCloudUsecase) findImage(regionId, instanceType string) (*ecs20140526.DescribeImagesResponseBodyImagesImage, error) {
	images, err := a.ecsClient.DescribeImages(&ecs20140526.DescribeImagesRequest{
		RegionId:        tea.String(regionId),
		Status:          tea.String("Available"),
		OSType:          tea.String("Linux"),
		ImageOwnerAlias: tea.String("system"),
		InstanceType:    tea.String(instanceType),
		PageNumber:      tea.Int32(1),
		PageSize:        tea.Int32(100),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to describe images")
	}
	if images.Body.Images == nil || tea.Int32Value(images.Body.TotalCount) == 0 {
		return nil, errors.New("no images found")
	}
	for _, v := range images.Body.Images.Image {
		if tea.StringValue(v.Status) != "Available" {
			continue
		}
		if strings.ToLower(tea.StringValue(v.Platform)) == "ubuntu" {
			return v, nil
		}
	}
	return nil, errors.New("failed to find image")
}

type InstanceTypes []*ecs20140526.DescribeInstanceTypesResponseBodyInstanceTypesInstanceType

// sort by cpu and memory
func (a InstanceTypes) Len() int {
	return len(a)
}

func (a InstanceTypes) Less(i, j int) bool {
	if a[i].CpuCoreCount == a[j].CpuCoreCount {
		return tea.Float32Value(a[i].MemorySize) < tea.Float32Value(a[j].MemorySize)
	}
	return tea.Int32Value(a[i].CpuCoreCount) < tea.Int32Value(a[j].CpuCoreCount)
}

func (a InstanceTypes) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type FindInstanceTypeParam struct {
	InstanceTypeFamiliy string
	CPU                 int32
	GPU                 int32
	Memory              int32
	GPUSpec             NodeGPUSpec
	Arch                NodeArchType
}

var NodeArchToAlicloudType = map[NodeArchType]string{
	NodeArchType_NodeArchType_UNSPECIFIED: "X86",
	NodeArchType_AMD64:                    "X86",
	NodeArchType_ARM64:                    "ARM",
}

var NodeGPUSpecToAlicloudSpec = map[NodeGPUSpec]string{
	NodeGPUSpec_NodeGPUSpec_UNSPECIFIED: "NVIDIA",
	NodeGPUSpec_NVIDIA_A10:              "NVIDIA A10",
	NodeGPUSpec_NVIDIA_P100:             "NVIDIA P100",
	NodeGPUSpec_NVIDIA_P4:               "NVIDIA P4",
	NodeGPUSpec_NVIDIA_V100:             "NVIDIA V100",
	NodeGPUSpec_NVIDIA_T4:               "NVIDIA T4",
}

func (a *AliCloudUsecase) findInstanceType(cluster *Cluster, param FindInstanceTypeParam) (*ecs20140526.DescribeInstanceTypesResponseBodyInstanceTypesInstanceType, error) {
	allInstanceTypes := make(InstanceTypes, 0)
	nexttoken := ""
	for {
		instancesReq := &ecs20140526.DescribeInstanceTypesRequest{
			InstanceTypeFamily:  tea.String(param.InstanceTypeFamiliy),
			CpuArchitecture:     tea.String(NodeArchToAlicloudType[param.Arch]),
			MinimumCpuCoreCount: tea.Int32(param.CPU),
			MinimumMemorySize:   tea.Float32(float32(param.Memory)),
			NextToken:           tea.String(nexttoken),
		}
		if param.GPU > 0 {
			instancesReq.MinimumGPUAmount = tea.Int32(param.GPU)
			instancesReq.GPUSpec = tea.String(NodeGPUSpecToAlicloudSpec[param.GPUSpec])
		}
		instancesRes, err := a.ecsClient.DescribeInstanceTypes(instancesReq)
		if err != nil {
			return nil, errors.Wrap(err, "failed to describe instance types")
		}
		allInstanceTypes = append(allInstanceTypes, instancesRes.Body.InstanceTypes.InstanceType...)
		if len(instancesRes.Body.InstanceTypes.InstanceType) == 0 || tea.StringValue(instancesRes.Body.NextToken) == "" {
			break
		}
		nexttoken = tea.StringValue(instancesRes.Body.NextToken)
	}
	// DescribeAvailableResource
	instanceTypes := make(InstanceTypes, 0)
	zones := cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES)
	for index, instanceType := range allInstanceTypes {
		res, err := a.ecsClient.DescribeAvailableResource(&ecs20140526.DescribeAvailableResourceRequest{
			RegionId:            tea.String(cluster.Region),
			InstanceChargeType:  tea.String("PostPaid"),
			InstanceType:        instanceType.InstanceTypeId,
			DestinationResource: tea.String("Zone"),
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to describe available resource")
		}
		instanceTypeOk := 0
		for _, zone := range zones {
			for _, v := range res.Body.AvailableZones.AvailableZone {
				if zone.RefId == tea.StringValue(v.ZoneId) {
					if tea.StringValue(v.Status) == "Available" {
						instanceTypeOk += 1
					}
					break
				}
			}
		}
		if len(zones) == instanceTypeOk {
			instanceTypes = append(instanceTypes, instanceType)
		}
		if index%2 == 0 {
			time.Sleep(time.Second)
		}
	}
	sort.Sort(instanceTypes)
	var instanceTypeInfo *ecs20140526.DescribeInstanceTypesResponseBodyInstanceTypesInstanceType
	for _, instanceType := range instanceTypes {
		if tea.Float32Value(instanceType.MemorySize) == 0 {
			continue
		}
		if tea.Float32Value(instanceType.MemorySize) >= float32(param.Memory) && tea.Int32Value(instanceType.CpuCoreCount) >= param.CPU {
			instanceTypeInfo = instanceType
		}
		if instanceTypeInfo == nil {
			continue
		}
		if param.GPU == 0 {
			break
		}
		if tea.Int32Value(instanceType.GPUAmount) >= param.GPU {
			break
		}
	}
	if instanceTypeInfo == nil {
		return nil, errors.New("no instance type found")
	}
	return instanceTypeInfo, nil
}

func (a *AliCloudUsecase) createVpcTags(regionID, resourceID, resourceType string, tags map[ResourceTypeKeyValue]any) error {
	vpcTags := make([]*vpc20160428.TagResourcesRequestTag, 0)
	for key, value := range tags {
		vpcTags = append(vpcTags, &vpc20160428.TagResourcesRequestTag{
			Key:   tea.String(key.String()),
			Value: tea.String(cast.ToString(value)),
		})
	}
	_, err := a.vpcClient.TagResources(&vpc20160428.TagResourcesRequest{
		RegionId:     tea.String(regionID),
		ResourceType: tea.String(resourceType),
		ResourceId:   tea.StringSlice([]string{resourceID}),
		Tag:          vpcTags,
	})
	if err != nil {
		return errors.Wrap(err, "failed to tag vpc")
	}
	return nil
}

func (a *AliCloudUsecase) createEcsTag(regionID, resourceID, resourceType string, tags map[ResourceTypeKeyValue]any) error {
	ecsTags := make([]*ecs20140526.TagResourcesRequestTag, 0)
	for key, value := range tags {
		ecsTags = append(ecsTags, &ecs20140526.TagResourcesRequestTag{
			Key:   tea.String(key.String()),
			Value: tea.String(cast.ToString(value)),
		})
	}
	_, err := a.ecsClient.TagResources(&ecs20140526.TagResourcesRequest{
		RegionId:     tea.String(regionID),
		ResourceType: tea.String(resourceType),
		ResourceId:   tea.StringSlice([]string{resourceID}),
		Tag:          ecsTags,
	})
	if err != nil {
		return errors.Wrap(err, "failed to tag ecs")
	}
	return nil
}

func (a *AliCloudUsecase) handlerError(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*tea.SDKError); ok && e.Code != nil && tea.StringValue(e.Code) == "DryRunOperation" {
		return nil
	}
	return err
}

func (a *AliCloudUsecase) getSubnetName(clusterName, zoneId string) string {
	return fmt.Sprintf("%s-%s-subnet", clusterName, zoneId)
}

func (a *AliCloudUsecase) getEipName(clusterName, zoneId string) string {
	return fmt.Sprintf("%s-%s-eip", clusterName, zoneId)
}

func (a *AliCloudUsecase) getNatgatewayName(clusterName, zoneId string) string {
	return fmt.Sprintf("%s-%s-natgateway", clusterName, zoneId)
}

func (a *AliCloudUsecase) getSgName(clusterName string) string {
	return fmt.Sprintf("%s-sg", clusterName)
}

func (a *AliCloudUsecase) getPrivateRouteTableName(clusterName, zoneId string) string {
	return fmt.Sprintf("%s-%s-private-route-table", clusterName, zoneId)
}

func (a *AliCloudUsecase) getkeyPairName(clusterName string) string {
	return fmt.Sprintf("%s-key", clusterName)
}
