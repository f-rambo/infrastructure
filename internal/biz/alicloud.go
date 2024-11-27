package biz

import (
	"context"
	"fmt"
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
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	alicloudDefaultRegion = "cn-hangzhou"

	ALICLOUD_ACCESS_KEY     = "ALICLOUD_ACCESS_KEY"
	ALICLOUD_SECRET_KEY     = "ALICLOUD_SECRET_KEY"
	ALICLOUD_REGION         = "ALICLOUD_REGION"
	ALICLOUD_DEFAULT_REGION = "ALICLOUD_DEFAULT_REGION"

	ALICLOUD_TAG_KEY_NAME = "Name"
	ALICLOUD_TAG_KEY_TYPE = "Type"
	ALICLOUD_TAG_KEY_ZONE = "Zone"
	ALICLOUD_TAG_KEY_VPC  = "Vpc"

	AlicloudResourcePublic        = "Public"
	AlicloudResourcePrivate       = "Private"
	AlicloudResourceUnBind        = "false"
	AlicloudResourceBostionHostSG = "bostionHost"
	AlicloudResourceHttpSG        = "http"
	AlicloudResourceBastionHost   = "bastionHost"
)

type AliCloudUsecase struct {
	log       *log.Helper
	vpcClient *vpc20160428.Client
	ecsClient *ecs20140526.Client
	slbClient *slb20140515.Client
	csClient  *cs20151215.Client
	dryRun    bool
}

func NewAliCloudUseCase(logger log.Logger) *AliCloudUsecase {
	c := &AliCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}

func (a *AliCloudUsecase) SetDryRun(dryRun bool) {
	a.dryRun = dryRun
}

func (a *AliCloudUsecase) Connections(cluster *Cluster) {
	if cluster.Region == "" {
		cluster.Region = alicloudDefaultRegion
	}
	os.Setenv(ALICLOUD_ACCESS_KEY, cluster.AccessId)
	os.Setenv(ALICLOUD_SECRET_KEY, cluster.AccessKey)
	os.Setenv(ALICLOUD_REGION, cluster.Region)
	os.Setenv(ALICLOUD_DEFAULT_REGION, cluster.Region)
}

func (a *AliCloudUsecase) createVpcClient() (err error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(os.Getenv(ALICLOUD_ACCESS_KEY)),
		AccessKeySecret: tea.String(os.Getenv(ALICLOUD_SECRET_KEY)),
		RegionId:        tea.String(os.Getenv(ALICLOUD_REGION)),
		Endpoint:        tea.String(os.Getenv(fmt.Sprintf("vpc.%s.aliyuncs.com", os.Getenv(ALICLOUD_REGION)))),
	}
	a.vpcClient, err = vpc20160428.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create vpc client")
	}
	return nil
}

func (a *AliCloudUsecase) createEcsClient() (err error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(os.Getenv(ALICLOUD_ACCESS_KEY)),
		AccessKeySecret: tea.String(os.Getenv(ALICLOUD_SECRET_KEY)),
		RegionId:        tea.String(os.Getenv(ALICLOUD_REGION)),
		Endpoint:        tea.String(os.Getenv(fmt.Sprintf("ecs.%s.aliyuncs.com", os.Getenv(ALICLOUD_REGION)))),
	}
	a.ecsClient, err = ecs20140526.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create ecs client")
	}
	return nil
}

func (a *AliCloudUsecase) createSlbClient() (err error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(os.Getenv(ALICLOUD_ACCESS_KEY)),
		AccessKeySecret: tea.String(os.Getenv(ALICLOUD_SECRET_KEY)),
		RegionId:        tea.String(os.Getenv(ALICLOUD_REGION)),
		Endpoint:        tea.String(os.Getenv(fmt.Sprintf("slb.%s.aliyuncs.com", os.Getenv(ALICLOUD_REGION)))),
	}
	a.slbClient, err = slb20140515.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create slb client")
	}
	return nil
}

func (a *AliCloudUsecase) createCsClient() (err error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(os.Getenv(ALICLOUD_ACCESS_KEY)),
		AccessKeySecret: tea.String(os.Getenv(ALICLOUD_SECRET_KEY)),
		RegionId:        tea.String(os.Getenv(ALICLOUD_REGION)),
		Endpoint:        tea.String(os.Getenv(fmt.Sprintf("cs.%s.aliyuncs.com", os.Getenv(ALICLOUD_REGION)))),
	}
	a.csClient, err = cs20151215.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "failed to create cs client")
	}
	return nil
}

func (a *AliCloudUsecase) GetAvailabilityZones(ctx context.Context, cluster *Cluster) error {
	err := a.createEcsClient()
	if err != nil {
		return err
	}
	zonesRes, err := a.ecsClient.DescribeZones(&ecs20140526.DescribeZonesRequest{
		AcceptLanguage: tea.String("zh-CN"),
		RegionId:       tea.String(os.Getenv(ALICLOUD_REGION)),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe zones")
	}
	if len(zonesRes.Body.Zones.Zone) == 0 {
		return errors.New("no availability zones found")
	}
	for _, zone := range zonesRes.Body.Zones.Zone {
		cluster.AddCloudResource(&CloudResource{
			RefId: tea.StringValue(zone.ZoneId),
			Name:  tea.StringValue(zone.LocalName),
			Type:  ResourceType_AVAILABILITY_ZONES,
			Value: os.Getenv(ALICLOUD_REGION),
		})
	}
	return err
}

func (a *AliCloudUsecase) ManageKubernetesCluster(ctx context.Context, cluster *Cluster) error {
	// Initialize CS (Container Service) client
	err := a.createCsClient()
	if err != nil {
		return err
	}

	// Get VPC and VSwitches
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// Get worker node VSwitches
	workerVSwitches := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		vsw := cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_ZONE, az.Name)
		if len(vsw) > 0 {
			workerVSwitches = append(workerVSwitches, vsw[0].RefId)
		}
	}
	if len(workerVSwitches) == 0 {
		return errors.New("no vswitches found for worker nodes")
	}

	// Get security groups
	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, ALICLOUD_TAG_KEY_TYPE, AlicloudResourceHttpSG)
	if len(sgs) == 0 {
		return errors.New("security group not found")
	}

	// Get key pair
	keyPairName := fmt.Sprintf("%s-key", cluster.Name)
	keyPair := cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName)
	if keyPair == nil {
		return errors.New("key pair not found")
	}

	// Check if cluster already exists
	clusters, err := a.csClient.DescribeClustersV1(&cs20151215.DescribeClustersV1Request{
		Name: tea.String(cluster.Name),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe clusters")
	}
	for _, c := range clusters.Body.Clusters {
		if tea.StringValue(c.Name) == cluster.Name {
			a.log.Infof("cluster %s already exists", cluster.Name)
			return nil
		}
	}

	// Prepare worker nodes configuration
	workerNodes := make([]*cs20151215.CreateClusterRequestWorkerDataDisks, 0)
	for _, nodeGroup := range cluster.NodeGroups {
		workerNodes = append(workerNodes, &cs20151215.CreateClusterRequestWorkerDataDisks{
			Category: tea.String("cloud_essd"),
			Size:     tea.String(string(nodeGroup.DataDisk)),
		})

	}

	// Create cluster request
	createReq := &cs20151215.CreateClusterRequest{
		KubernetesVersion:        tea.String(cluster.Version),
		LoadBalancerId:           nil,
		LoadBalancerSpec:         nil,
		Name:                     tea.String(cluster.Name),
		RegionId:                 tea.String(cluster.Region),
		ClusterType:              tea.String("ManagedKubernetes"), // Managed Kubernetes cluster
		Vpcid:                    tea.String(vpc.RefId),
		VswitchIds:               []*string{},
		SecurityGroupId:          tea.String(sgs[0].RefId),
		ContainerCidr:            tea.String("172.20.0.0/16"),
		ServiceCidr:              tea.String("172.21.0.0/20"),
		KeyPair:                  tea.String(keyPair.RefId),
		WorkerSystemDiskCategory: tea.String("cloud_essd"),
		WorkerSystemDiskSize:     tea.Int64(120),
		WorkerDataDisks:          workerNodes,
		MasterInstanceTypes:      []*string{tea.String("ecs.n4.large")},
		WorkerInstanceTypes:      []*string{tea.String("ecs.n4.large")},
		NumOfNodes:               tea.Int64(int64(1)),
		CloudMonitorFlags:        tea.Bool(true),
		Platform:                 tea.String("AliyunLinux"),
		OsType:                   tea.String("Linux"),
		CpuPolicy:                tea.String("none"),
		NodePortRange:            tea.String("30000-32767"),
		ProxyMode:                tea.String("ipvs"),
		Tags: []*cs20151215.Tag{
			{
				Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
				Value: tea.String(cluster.Name),
			},
		},
	}

	// Create cluster
	_, err = a.csClient.CreateCluster(createReq)
	if err != nil {
		return errors.Wrap(err, "failed to create kubernetes cluster")
	}

	a.log.Infof("kubernetes cluster %s created successfully", cluster.Name)
	return nil
}

func (a *AliCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	err := a.createVpcClient()
	if err != nil {
		return err
	}
	err = a.createSlbClient()
	if err != nil {
		return err
	}
	fs := []func(context.Context, *Cluster) error{
		a.createVPC,
		a.createSubnets,
		a.createInternetGateway,
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
	image, err := a.findImage(cluster.Region)
	if err != nil {
		return err
	}
	for _, nodeGroup := range cluster.NodeGroups {
		nodeGroup.Os = tea.StringValue(image.OSName)
		nodeGroup.Image = tea.StringValue(image.ImageId)
		nodeGroup.ImageDescription = tea.StringValue(image.Description)
		nodeGroup.Arch = tea.StringValue(image.Architecture)
		for _, disk := range image.DiskDeviceMappings.DiskDeviceMapping {
			if tea.StringValue(disk.Type) == "system" {
				nodeGroup.RootDeviceName = tea.StringValue(disk.Device)
			}
			if nodeGroup.DataDeviceName == "" && tea.StringValue(disk.Type) == "system" {
				nodeGroup.DataDeviceName = tea.StringValue(disk.Device)
			}
		}

		if nodeGroup.InstanceType != "" {
			continue
		}
		instanceTypeFamiliy := a.getIntanceTypeFamilies(nodeGroup)
		instanceInfo, err := a.findInstanceType(instanceTypeFamiliy, nodeGroup.Cpu, nodeGroup.Gpu, nodeGroup.Memory)
		if err != nil {
			return err
		}
		nodeGroup.InstanceType = tea.StringValue(instanceInfo.InstanceTypeId)
		nodeGroup.Cpu = tea.Int32Value(instanceInfo.CpuCoreCount)
		nodeGroup.Memory = int32(tea.Float32Value(instanceInfo.MemorySize))
		if nodeGroup.Gpu > 0 {
			nodeGroup.Gpu = tea.Int32Value(instanceInfo.GPUAmount)
			nodeGroup.GpuSpec = tea.StringValue(instanceInfo.GPUSpec)
		}
		a.log.Info("instance type found: ", nodeGroup.InstanceType)
	}
	return nil
}

func (a *AliCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	err := a.createEcsClient()
	if err != nil {
		return err
	}

	// Check if key pair already exists
	keyPairName := fmt.Sprintf("%s-key", cluster.Name)
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
	err = a.createEcsTag(cluster.Region, tea.StringValue(importRes.Body.KeyPairName), "keypair", map[string]string{ALICLOUD_TAG_KEY_NAME: keyPairName})
	if err != nil {
		return errors.Wrap(err, "failed to tag key pair")
	}

	// Add to cluster resources
	cluster.AddCloudResource(&CloudResource{
		Name:  keyPairName,
		RefId: tea.StringValue(importRes.Body.KeyPairName),
		Type:  ResourceType_KEY_PAIR,
		Tags:  cluster.EncodeTags(map[string]string{ALICLOUD_TAG_KEY_NAME: keyPairName}),
	})

	a.log.Infof("key pair %s imported successfully", keyPairName)
	return nil
}

func (a *AliCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	err := a.createEcsClient()
	if err != nil {
		return err
	}

	// Get key pair from cluster resources
	keyPairName := fmt.Sprintf("%s-key", cluster.Name)
	keyPair := cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName)
	if keyPair == nil {
		a.log.Infof("key pair %s not found", keyPairName)
		return nil
	}

	// Delete key pair
	deleteReq := &ecs20140526.DeleteKeyPairsRequest{
		RegionId:     tea.String(cluster.Region),
		KeyPairNames: tea.String(fmt.Sprintf("[\"%s\"]", keyPair.RefId)),
	}

	_, err = a.ecsClient.DeleteKeyPairs(deleteReq)
	if err != nil {
		return errors.Wrap(err, "failed to delete key pair")
	}

	// Remove from cluster resources
	cluster.DeleteCloudResource(ResourceType_KEY_PAIR)
	a.log.Infof("key pair %s deleted successfully", keyPairName)
	return nil
}

func (a *AliCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	// Get VPC and security groups
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, ALICLOUD_TAG_KEY_TYPE, AlicloudResourceHttpSG)
	if len(sgs) == 0 {
		return errors.New("security group not found")
	}

	// Get key pair
	keyPairName := fmt.Sprintf("%s-key", cluster.Name)
	keyPair := cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName)
	if keyPair == nil {
		return errors.New("key pair not found")
	}

	// Get VSwitches for each node group
	for _, nodeGroup := range cluster.NodeGroups {

		// Get VSwitches for the node group's availability zones
		vSwitches := make([]*CloudResource, 0)
		for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
			vsw := cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_ZONE, az.Name)
			if len(vsw) == 0 {
				return fmt.Errorf("vswitch not found for availability zone %s", az.Name)
			}
			vSwitches = append(vSwitches, vsw...)
		}
		if len(vSwitches) == 0 {
			return errors.New("no vswitches found for node group")
		}

		// List existing instances for this node group
		var pageNumber int32 = 1
		existingInstances := make([]*ecs20140526.DescribeInstancesResponseBodyInstancesInstance, 0)
		for {
			instances, err := a.ecsClient.DescribeInstances(&ecs20140526.DescribeInstancesRequest{
				RegionId:   tea.String(cluster.Region),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(50),
				Tag: []*ecs20140526.DescribeInstancesRequestTag{
					{
						Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
						Value: tea.String(fmt.Sprintf("%s-%s", cluster.Name, nodeGroup.Name)),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "failed to describe instances")
			}

			existingInstances = append(existingInstances, instances.Body.Instances.Instance...)
			if len(instances.Body.Instances.Instance) < 50 {
				break
			}
			pageNumber++
		}

		// Calculate how many instances we need to create or delete
		currentCount := len(existingInstances)
		desiredCount := 1 // tood :???
		if currentCount == desiredCount {
			continue
		}

		if currentCount < desiredCount {
			// Create instances
			for i := 0; i < desiredCount-currentCount; i++ {
				vswIndex := i % len(vSwitches)
				instanceName := fmt.Sprintf("%s-%s-%d", cluster.Name, nodeGroup.Name, currentCount+i+1)

				createReq := &ecs20140526.RunInstancesRequest{
					RegionId:           tea.String(cluster.Region),
					InstanceName:       tea.String(instanceName),
					InstanceType:       tea.String(nodeGroup.InstanceType),
					SecurityGroupId:    tea.String(sgs[0].RefId),
					VSwitchId:          tea.String(vSwitches[vswIndex].RefId),
					KeyPairName:        tea.String(keyPair.RefId),
					SystemDisk:         &ecs20140526.RunInstancesRequestSystemDisk{},
					DataDisk:           []*ecs20140526.RunInstancesRequestDataDisk{},
					ImageId:            tea.String(nodeGroup.Image),
					InstanceChargeType: tea.String("PostPaid"),
					SpotStrategy:       tea.String("NoSpot"),
					Tag: []*ecs20140526.RunInstancesRequestTag{
						{
							Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
							Value: tea.String(fmt.Sprintf("%s-%s", cluster.Name, nodeGroup.Name)),
						},
					},
				}

				_, err := a.ecsClient.RunInstances(createReq)
				if err != nil {
					return errors.Wrap(err, "failed to create instance")
				}

				// a.log.Infof("instance %s created successfully", runRes.Body.InstanceId)
			}
		} else {
			// Delete excess instances
		}
	}

	return nil
}

func (a *AliCloudUsecase) ManageBostionHost(ctx context.Context, cluster *Cluster) error {
	err := a.createEcsClient()
	if err != nil {
		return err
	}

	// Skip if basic cluster
	if cluster.Level == ClusterLevel_BASIC {
		a.log.Info("skip create bastion host for basic cluster")
		return nil
	}

	// Get VPC and security groups
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, ALICLOUD_TAG_KEY_TYPE, AlicloudResourceHttpSG)
	if len(sgs) == 0 {
		return errors.New("bastion security group not found")
	}

	// Get key pair
	keyPairName := fmt.Sprintf("%s-key", cluster.Name)
	keyPair := cluster.GetCloudResourceByName(ResourceType_KEY_PAIR, keyPairName)
	if keyPair == nil {
		return errors.New("key pair not found")
	}

	// Get public VSwitch
	var publicVSwitch *CloudResource
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		vsw := cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_ZONE, az.Name)
		if len(vsw) > 0 {
			publicVSwitch = vsw[0]
			break
		}
	}
	if publicVSwitch == nil {
		return errors.New("no public vswitch found")
	}

	// Check existing bastion host
	var pageNumber int32 = 1
	bastionName := fmt.Sprintf("%s-bastion", cluster.Name)
	var existingInstance *ecs20140526.DescribeInstancesResponseBodyInstancesInstance

	for {
		instances, err := a.ecsClient.DescribeInstances(&ecs20140526.DescribeInstancesRequest{
			RegionId:   tea.String(cluster.Region),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
			Tag: []*ecs20140526.DescribeInstancesRequestTag{
				{
					Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
					Value: tea.String(bastionName),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe instances")
		}

		for _, instance := range instances.Body.Instances.Instance {
			if tea.StringValue(instance.InstanceName) == bastionName {
				existingInstance = instance
				break
			}
		}

		if existingInstance != nil || len(instances.Body.Instances.Instance) < 50 {
			break
		}
		pageNumber++
	}

	if existingInstance != nil {
		// Update existing instance if needed
		return nil
	}

	// Create bastion host
	createReq := &ecs20140526.RunInstancesRequest{
		RegionId:        tea.String(cluster.Region),
		InstanceName:    tea.String(bastionName),
		InstanceType:    tea.String("ecs.t6-c1m1.large"), // Small instance type for bastion
		SecurityGroupId: tea.String(sgs[0].RefId),
		VSwitchId:       tea.String(publicVSwitch.RefId),
		KeyPairName:     tea.String(keyPair.RefId),
		SystemDisk: &ecs20140526.RunInstancesRequestSystemDisk{
			Size:     tea.String("40"),
			Category: tea.String("cloud_essd"),
		},
		ImageId:            tea.String("ubuntu_22_04_x64_20G_alibase_20230208.vhd"), // Ubuntu 22.04
		InstanceChargeType: tea.String("PostPaid"),
		SpotStrategy:       tea.String("NoSpot"),
		Tag: []*ecs20140526.RunInstancesRequestTag{
			{
				Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
				Value: tea.String(bastionName),
			},
			{
				Key:   tea.String(ALICLOUD_TAG_KEY_TYPE),
				Value: tea.String(AlicloudResourceBastionHost),
			},
		},
	}

	_, err = a.ecsClient.RunInstances(createReq)
	if err != nil {
		return errors.Wrap(err, "failed to create bastion host")
	}

	a.log.Infof("bastion host %s created successfully", bastionName)
	return nil
}

func (a *AliCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	// Initialize clients
	if err := a.createVpcClient(); err != nil {
		return err
	}

	// Delete NAT Gateways first (and associated EIPs)
	nats := cluster.GetCloudResource(ResourceType_NAT_GATEWAY)
	for _, nat := range nats {
		// Delete EIP associations first
		eips := cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, ALICLOUD_TAG_KEY_NAME, nat.Name)
		for _, eip := range eips {
			// Disassociate EIP
			_, err := a.vpcClient.UnassociateEipAddress(&vpc20160428.UnassociateEipAddressRequest{
				RegionId:     tea.String(cluster.Region),
				AllocationId: tea.String(eip.RefId),
				InstanceId:   tea.String(nat.RefId),
			})
			if err != nil {
				a.log.Warnf("failed to disassociate EIP %s: %v", eip.RefId, err)
			}

			// Release EIP
			_, err = a.vpcClient.ReleaseEipAddress(&vpc20160428.ReleaseEipAddressRequest{
				RegionId:     tea.String(cluster.Region),
				AllocationId: tea.String(eip.RefId),
			})
			if err != nil {
				a.log.Warnf("failed to release EIP %s: %v", eip.RefId, err)
			}
		}
		cluster.DeleteCloudResource(ResourceType_ELASTIC_IP)

		// Delete NAT Gateway
		_, err := a.vpcClient.DeleteNatGateway(&vpc20160428.DeleteNatGatewayRequest{
			RegionId:     tea.String(cluster.Region),
			NatGatewayId: tea.String(nat.RefId),
			Force:        tea.Bool(true),
		})
		if err != nil {
			a.log.Warnf("failed to delete NAT Gateway %s: %v", nat.RefId, err)
		}
	}
	cluster.DeleteCloudResource(ResourceType_NAT_GATEWAY)

	// Delete Route Tables
	routeTables := cluster.GetCloudResource(ResourceType_ROUTE_TABLE)
	for _, rt := range routeTables {
		// Delete route table
		_, err := a.vpcClient.DeleteRouteTable(&vpc20160428.DeleteRouteTableRequest{
			RegionId:     tea.String(cluster.Region),
			RouteTableId: tea.String(rt.RefId),
		})
		if err != nil {
			a.log.Warnf("failed to delete route table %s: %v", rt.RefId, err)
		}
	}
	cluster.DeleteCloudResource(ResourceType_ROUTE_TABLE)

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
	}
	cluster.DeleteCloudResource(ResourceType_SUBNET)

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
	if cluster.GetSingleCloudResource(ResourceType_VPC) != nil {
		a.log.Info("vpc already exists ", "vpc ", cluster.GetSingleCloudResource(ResourceType_VPC).Name)
		return nil
	}
	vpcName := cluster.Name + "-vpc"
	existingVpcs, err := a.vpcClient.DescribeVpcs(&vpc20160428.DescribeVpcsRequest{
		VpcName: tea.String(vpcName),
	})
	if err != nil || tea.Int32Value(existingVpcs.StatusCode) != http.StatusOK {
		return errors.Wrap(err, "failed to describe VPCs")
	}
	if tea.Int32Value(existingVpcs.Body.TotalCount) != 0 {
		for _, vpc := range existingVpcs.Body.Vpcs.Vpc {
			cluster.AddCloudResource(&CloudResource{
				RefId: tea.StringValue(vpc.VpcId),
				Name:  tea.StringValue(vpc.VpcName),
				Type:  ResourceType_VPC,
			})
			a.log.Infof("vpc %s already exists", cluster.GetSingleCloudResource(ResourceType_VPC).RefId)
			break
		}
		return nil
	}
	vpcResponce, err := a.vpcClient.CreateVpc(&vpc20160428.CreateVpcRequest{
		VpcName:   tea.String(cluster.Name + "-vpc"),
		RegionId:  tea.String(cluster.Region),
		CidrBlock: tea.String(cluster.IpCidr),
		DryRun:    tea.Bool(a.dryRun),
	})
	if err := a.handlerError(err); err != nil {
		return err
	}
	vpcCloudResource := &CloudResource{
		Name: vpcName,
		Type: ResourceType_VPC,
	}
	if a.dryRun {
		vpcCloudResource.RefId = uuid.New().String()
	} else {
		vpcCloudResource.RefId = tea.StringValue(vpcResponce.Body.VpcId)
	}
	cluster.AddCloudResource(vpcCloudResource)
	a.log.Infof("vpc %s created", vpcName)
	return nil
}

func (a *AliCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingSubnets := make([]*vpc20160428.DescribeVSwitchesResponseBodyVSwitchesVSwitch, 0)
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
		existingSubnets = append(existingSubnets, existingSubnetRes.Body.VSwitches.VSwitch...)
		if tea.Int32Value(existingSubnetRes.Body.TotalCount) == 0 || len(existingSubnetRes.Body.VSwitches.VSwitch) < 50 {
			break
		}
		pageNumber++
	}

	zoneSubnets := make(map[string][]*vpc20160428.DescribeVSwitchesResponseBodyVSwitchesVSwitch)
	subbetTotalCount := len(existingSubnets)
	if subbetTotalCount != 0 {
		for _, subnet := range existingSubnets {
			if subnet.ZoneId == nil {
				continue
			}
			_, ok := zoneSubnets[tea.StringValue(subnet.ZoneId)]
			if ok && len(zoneSubnets[tea.StringValue(subnet.ZoneId)]) >= 3 {
				continue
			}
			zoneSubnets[tea.StringValue(subnet.ZoneId)] = append(zoneSubnets[tea.StringValue(subnet.ZoneId)], subnet)
		}
	}
	for zoneName, subzoneSubnets := range zoneSubnets {
		for i, subnet := range subzoneSubnets {
			if subnet.VSwitchId == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_SUBNET, tea.StringValue(subnet.VSwitchId)) != nil {
				a.log.Infof("subnet %s already exists", tea.StringValue(subnet.VSwitchId))
				continue
			}
			tags := make(map[string]string)
			name := ""
			for _, tag := range subnet.Tags.Tag {
				tags[tea.StringValue(tag.Key)] = tea.StringValue(tag.Value)
			}
			tags[ALICLOUD_TAG_KEY_ZONE] = zoneName
			if i < 2 {
				name = fmt.Sprintf("%s-private-subnet-%s-%d", cluster.Name, zoneName, i+1)
				tags[ALICLOUD_TAG_KEY_TYPE] = AlicloudResourcePrivate
			} else {
				name = fmt.Sprintf("%s-public-subnet-%s", cluster.Name, zoneName)
				tags[ALICLOUD_TAG_KEY_TYPE] = AlicloudResourcePublic
			}
			tags[ALICLOUD_TAG_KEY_NAME] = name
			err := a.createVpcTags(cluster.Region, tea.StringValue(subnet.VSwitchId), "VSWITCH", tags)
			if err != nil {
				return err
			}
			cluster.AddCloudResource(&CloudResource{
				Name:  name,
				RefId: tea.StringValue(subnet.VSwitchId),
				Tags:  cluster.EncodeTags(tags),
				Type:  ResourceType_SUBNET,
			})
			a.log.Infof("subnet %s already exists", name)
		}
	}

	// get subnet cidr
	privateSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES)) * 2
	publicSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES))
	subnetCidrRes, err := utils.GenerateSubnets(cluster.IpCidr, privateSubnetCount+publicSubnetCount+int(subbetTotalCount))
	if err != nil {
		return errors.Wrap(err, "failed to generate subnet CIDRs")
	}
	subnetCidrs := make([]string, 0)
	existingSubnetCird := make(map[string]bool)
	for _, subnet := range existingSubnets {
		existingSubnetCird[tea.StringValue(subnet.CidrBlock)] = true
	}
	for _, subnetCidr := range subnetCidrRes {
		subnetCidrDecode := utils.DecodeCidr(subnetCidr)
		if subnetCidrDecode == "" {
			continue
		}
		ok := true
		for _, subnet := range existingSubnets {
			existingSubnetCirdDecode := utils.DecodeCidr(tea.StringValue(subnet.CidrBlock))
			if existingSubnetCirdDecode == "" {
				continue
			}
			if subnetCidrDecode == existingSubnetCirdDecode {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		subnetCidrs = append(subnetCidrs, subnetCidr)
	}

	for i, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		// Create private subnets
		for j := 0; j < 2; j++ {
			name := fmt.Sprintf("%s-private-subnet-%s-%d", cluster.Name, az.Name, j+1)
			tags := map[string]string{
				ALICLOUD_TAG_KEY_NAME: name,
				ALICLOUD_TAG_KEY_TYPE: AlicloudResourcePrivate,
				ALICLOUD_TAG_KEY_ZONE: az.Name,
			}
			if cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_NAME, name) != nil {
				continue
			}
			cidr := subnetCidrs[i*2+j]
			privateSubnetTags := make([]*vpc20160428.CreateVSwitchRequestTag, 0)
			for k, v := range tags {
				privateSubnetTags = append(privateSubnetTags, &vpc20160428.CreateVSwitchRequestTag{
					Key:   tea.String(k),
					Value: tea.String(v),
				})
			}
			subnetOutput, err := a.vpcClient.CreateVSwitch(&vpc20160428.CreateVSwitchRequest{
				VpcId:     tea.String(vpc.RefId),
				CidrBlock: tea.String(cidr),
				ZoneId:    tea.String(az.RefId),
				Tag:       privateSubnetTags,
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
			a.log.Infof("private subnet %s created", name)
		}

		// Create public subnet
		name := fmt.Sprintf("%s-public-subnet-%s", cluster.Name, az.Name)
		tags := map[string]string{
			ALICLOUD_TAG_KEY_NAME: name,
			ALICLOUD_TAG_KEY_TYPE: AlicloudResourcePublic,
			ALICLOUD_TAG_KEY_ZONE: az.Name,
		}
		if cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_NAME, name) != nil {
			continue
		}
		// Create public subnet
		cidr := subnetCidrs[privateSubnetCount+i]
		publicSubnetTags := make([]*vpc20160428.CreateVSwitchRequestTag, 0)
		for k, v := range tags {
			publicSubnetTags = append(publicSubnetTags, &vpc20160428.CreateVSwitchRequestTag{
				Key:   tea.String(k),
				Value: tea.String(v),
			})
		}
		subnetOutput, err := a.vpcClient.CreateVSwitch(&vpc20160428.CreateVSwitchRequest{
			VpcId:     tea.String(vpc.RefId),
			CidrBlock: tea.String(cidr),
			ZoneId:    tea.String(az.RefId),
			Tag:       publicSubnetTags,
		})
		if err != nil {
			return errors.Wrap(err, "failed to create public subnet")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(subnetOutput.Body.VSwitchId),
			AssociatedId: vpc.RefId,
			Tags:         cluster.EncodeTags(tags),
		})
		a.log.Infof("public subnet %s created", name)
	}
	return nil
}

func (a *AliCloudUsecase) createInternetGateway(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	nextToken := ""
	gateways := make([]*vpc20160428.ListIpv4GatewaysResponseBodyIpv4GatewayModels, 0)
	for {
		gatewayRes, err := a.vpcClient.ListIpv4Gateways(&vpc20160428.ListIpv4GatewaysRequest{
			VpcId:     tea.String(vpc.RefId),
			NextToken: tea.String(nextToken),
		})
		if err != nil {
			return errors.Wrap(err, "failed to list internet gateways")
		}
		gateways = append(gateways, gatewayRes.Body.Ipv4GatewayModels...)
		if gatewayRes.Body.NextToken == nil {
			break
		}
		nextToken = tea.StringValue(gatewayRes.Body.NextToken)
	}
	for _, gateway := range gateways {
		if gateway.Ipv4GatewayId == nil {
			continue
		}
		if cluster.GetCloudResourceByRefID(ResourceType_INTERNET_GATEWAY, tea.StringValue(gateway.Ipv4GatewayId)) != nil {
			a.log.Infof("internet gateway %s already exists", tea.StringValue(gateway.Ipv4GatewayId))
			continue
		}
		name := ""
		tags := make(map[string]string)
		for _, tag := range gateway.Tags {
			tags[tea.StringValue(tag.Key)] = tea.StringValue(tag.Value)
		}
		if name == "" {
			name = fmt.Sprintf("%s-igw", cluster.Name)
		}
		tags[ALICLOUD_TAG_KEY_NAME] = name
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(gateway.Ipv4GatewayId),
			Tags:         cluster.EncodeTags(tags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_INTERNET_GATEWAY,
		})
		a.log.Infof("internet gateway %s already exists", name)
		return nil
	}
	// Create Internet Gateway if it doesn't exist
	name := fmt.Sprintf("%s-igw", cluster.Name)
	tags := map[string]string{ALICLOUD_TAG_KEY_NAME: name}
	gatewayRes, err := a.vpcClient.CreateIpv4Gateway(&vpc20160428.CreateIpv4GatewayRequest{
		RegionId:        tea.String(cluster.Region),
		VpcId:           tea.String(vpc.RefId),
		Ipv4GatewayName: tea.String(name),
		Tag: []*vpc20160428.CreateIpv4GatewayRequestTag{
			{
				Key:   tea.String(ALICLOUD_TAG_KEY_NAME),
				Value: tea.String(name),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create internet gateway")
	}
	cluster.AddCloudResource(&CloudResource{
		Name:         name,
		RefId:        tea.StringValue(gatewayRes.Body.Ipv4GatewayId),
		Tags:         cluster.EncodeTags(tags),
		AssociatedId: vpc.RefId,
		Type:         ResourceType_INTERNET_GATEWAY,
	})
	a.log.Infof("internet gateway %s created", name)
	return nil
}

func (a *AliCloudUsecase) createNatGateways(ctx context.Context, cluster *Cluster) error {
	if cluster.Level == ClusterLevel_BASIC {
		return nil
	}
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
		if natGateway.NatGatewayPrivateInfo == nil {
			continue
		}
		subnetCloudResource := cluster.GetCloudResourceByRefID(ResourceType_NAT_GATEWAY, tea.StringValue(natGateway.NatGatewayPrivateInfo.VswitchId))
		if subnetCloudResource == nil {
			continue
		}
		subnetCloudResourceMapTags := cluster.DecodeTags(subnetCloudResource.Tags)
		if val, ok := subnetCloudResourceMapTags[ALICLOUD_TAG_KEY_TYPE]; !ok || val != AlicloudResourcePublic {
			continue
		}
		tags := make(map[string]string)
		for _, tag := range natGateway.Tags.Tag {
			tags[tea.StringValue(tag.TagKey)] = tea.StringValue(tag.TagValue)
		}
		name := fmt.Sprintf("%s-nat-gateway-%s", cluster.Name, subnetCloudResourceMapTags[ALICLOUD_TAG_KEY_ZONE])
		tags[ALICLOUD_TAG_KEY_NAME] = name
		tags[ALICLOUD_TAG_KEY_ZONE] = subnetCloudResourceMapTags[ALICLOUD_TAG_KEY_ZONE]
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(natGateway.NatGatewayId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: subnetCloudResource.RefId,
		})
		a.log.Infof("nat gateway %s already exists", tea.StringValue(natGateway.Name))
	}

	// Get Elastic IP
	eipRes, err := a.vpcClient.DescribeEipAddresses(&vpc20160428.DescribeEipAddressesRequest{
		RegionId:   tea.String(cluster.Region),
		Status:     tea.String("Available"),
		PageNumber: tea.Int32(1),
		PageSize:   tea.Int32(50),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe eip addresses")
	}
	for i, eip := range eipRes.Body.EipAddresses.EipAddress {
		if eip.InstanceId != nil {
			continue
		}
		if cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, tea.StringValue(eip.AllocationId)) != nil {
			a.log.Infof("eip %s already exists", tea.StringValue(eip.AllocationId))
			continue
		}
		name := fmt.Sprintf("%s-%d-eip", cluster.Name, i)
		tags := make(map[string]string)
		for _, tag := range eip.Tags.Tag {
			tags[tea.StringValue(tag.Key)] = tea.StringValue(tag.Value)
		}
		tags[ALICLOUD_TAG_KEY_NAME] = name
		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: tea.StringValue(eip.AllocationId),
			Type:  ResourceType_ELASTIC_IP,
			Value: tea.StringValue(eip.IpAddress),
			Tags:  cluster.EncodeTags(tags),
		})
		a.log.Infof("elastic ip %s already exists", tea.StringValue(eip.IpAddress))
	}

	// Allocate Elastic IP and create NAT Gateways for each AZ
	usedEipID := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natGatewayName := fmt.Sprintf("%s-nat-gateway-%s", cluster.Name, az.Name)
		if cluster.GetCloudResourceByName(ResourceType_NAT_GATEWAY, natGatewayName) != nil {
			continue
		}

		// Create EIP if not exists
		eipName := fmt.Sprintf("%s-eip-%s", cluster.Name, az.Name)
		eipTags := map[string]string{ALICLOUD_TAG_KEY_NAME: eipName, ALICLOUD_TAG_KEY_ZONE: az.Name}
		var eipResource *CloudResource
		for _, eip := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
			if utils.InArray(eip.RefId, usedEipID) {
				continue
			}
			eipResource = eip
			usedEipID = append(usedEipID, eip.RefId)
			break
		}

		if eipResource == nil {
			// Allocate new EIP
			eipReq := &vpc20160428.AllocateEipAddressRequest{
				RegionId:           tea.String(cluster.Region),
				Bandwidth:          tea.String("5"),
				InternetChargeType: tea.String("PayByTraffic"),
			}
			eipRes, err := a.vpcClient.AllocateEipAddress(eipReq)
			if err != nil {
				return errors.Wrap(err, "failed to allocate eip address")
			}

			// Add tags to EIP
			err = a.createVpcTags(cluster.Region, tea.StringValue(eipRes.Body.AllocationId), "EIP", eipTags)
			if err != nil {
				return errors.Wrap(err, "failed to tag eip")
			}

			eipResource = &CloudResource{
				Name:  eipName,
				RefId: tea.StringValue(eipRes.Body.AllocationId),
				Type:  ResourceType_ELASTIC_IP,
				Value: tea.StringValue(eipRes.Body.EipAddress),
				Tags:  cluster.EncodeTags(eipTags),
			}
			cluster.AddCloudResource(eipResource)
			a.log.Infof("elastic ip %s allocated", tea.StringValue(eipRes.Body.EipAddress))
		}

		// Get public subnet for the AZ
		publicSubnets := cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_ZONE, az.Name, ALICLOUD_TAG_KEY_TYPE, AlicloudResourcePublic)
		if len(publicSubnets) == 0 {
			return errors.New("no public subnet found for AZ " + az.Name)
		}

		// Create NAT Gateway
		natGatewayTags := map[string]string{
			ALICLOUD_TAG_KEY_NAME: natGatewayName,
			ALICLOUD_TAG_KEY_TYPE: AlicloudResourcePublic,
			ALICLOUD_TAG_KEY_ZONE: az.Name,
		}

		createNatReq := &vpc20160428.CreateNatGatewayRequest{
			RegionId:           tea.String(cluster.Region),
			VpcId:              tea.String(vpc.RefId),
			VSwitchId:          tea.String(publicSubnets[0].RefId),
			NatType:            tea.String("Enhanced"),
			NetworkType:        tea.String("internet"),
			Name:               tea.String(natGatewayName),
			InternetChargeType: tea.String("PayByLcu"),
		}

		natRes, err := a.vpcClient.CreateNatGateway(createNatReq)
		if err != nil {
			return errors.Wrap(err, "failed to create nat gateway")
		}

		// Add tags to NAT Gateway
		err = a.createVpcTags(cluster.Region, tea.StringValue(natRes.Body.NatGatewayId), "NAT_GATEWAY", natGatewayTags)
		if err != nil {
			return errors.Wrap(err, "failed to tag nat gateway")
		}

		// Associate EIP with NAT Gateway
		_, err = a.vpcClient.AssociateEipAddress(&vpc20160428.AssociateEipAddressRequest{
			RegionId:     tea.String(cluster.Region),
			AllocationId: tea.String(eipResource.RefId),
			InstanceId:   natRes.Body.NatGatewayId,
			InstanceType: tea.String("Nat"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to associate eip with nat gateway")
		}

		cluster.AddCloudResource(&CloudResource{
			Name:         natGatewayName,
			RefId:        tea.StringValue(natRes.Body.NatGatewayId),
			Tags:         cluster.EncodeTags(natGatewayTags),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: publicSubnets[0].RefId,
		})
		a.log.Infof("nat gateway %s created", tea.StringValue(natRes.Body.NatGatewayId))

		// Wait for NAT Gateway to be available
		for i := 0; i < 60; i++ {
			natStatus, err := a.vpcClient.DescribeNatGateways(&vpc20160428.DescribeNatGatewaysRequest{
				RegionId:     tea.String(cluster.Region),
				NatGatewayId: natRes.Body.NatGatewayId,
			})
			if err != nil {
				return errors.Wrap(err, "failed to get nat gateway status")
			}
			if len(natStatus.Body.NatGateways.NatGateway) > 0 && tea.StringValue(natStatus.Body.NatGateways.NatGateway[0].Status) == "Available" {
				break
			}
			time.Sleep(30 * time.Second)
		}
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
	existingRouteTables := make([]*vpc20160428.DescribeRouteTablesResponseBodyRouteTablesRouteTable, 0)
	for {
		routeTablesRes, err := a.vpcClient.DescribeRouteTables(&vpc20160428.DescribeRouteTablesRequest{
			RegionId:   tea.String(cluster.Region),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(50),
		})
		if err != nil {
			return errors.Wrap(err, "failed to describe route tables")
		}
		existingRouteTables = append(existingRouteTables, routeTablesRes.Body.RouteTables.RouteTable...)
		if len(routeTablesRes.Body.RouteTables.RouteTable) < 50 {
			break
		}
		pageNumber++
	}

	// Process existing route tables
	for _, routeTable := range existingRouteTables {
		if cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, tea.StringValue(routeTable.RouteTableId)) != nil {
			a.log.Infof("route table %s already exists", tea.StringValue(routeTable.RouteTableId))
			continue
		}

		tags := make(map[string]string)

		if val, ok := tags[ALICLOUD_TAG_KEY_TYPE]; !ok || (val != AlicloudResourcePublic && val != AlicloudResourcePrivate) {
			continue
		}

		name := tags[ALICLOUD_TAG_KEY_NAME]
		if tags[ALICLOUD_TAG_KEY_TYPE] == AlicloudResourcePublic && name != fmt.Sprintf("%s-public-rt", cluster.Name) {
			continue
		}
		if tags[ALICLOUD_TAG_KEY_TYPE] == AlicloudResourcePrivate {
			privateZoneName, ok := tags[ALICLOUD_TAG_KEY_ZONE]
			if !ok {
				continue
			}
			if name != fmt.Sprintf("%s-private-rt-%s", cluster.Name, privateZoneName) {
				continue
			}
		}

		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        tea.StringValue(routeTable.RouteTableId),
			Tags:         cluster.EncodeTags(tags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("route table %s already exists", tea.StringValue(routeTable.RouteTableId))
	}

	// Create public route table
	publicRouteTableName := fmt.Sprintf("%s-public-rt", cluster.Name)
	publicRouteTableTags := map[string]string{
		ALICLOUD_TAG_KEY_NAME: publicRouteTableName,
		ALICLOUD_TAG_KEY_TYPE: AlicloudResourcePublic,
	}

	if cluster.GetCloudResourceByName(ResourceType_ROUTE_TABLE, publicRouteTableName) == nil {
		// Create public route table
		publicRouteTableReq := &vpc20160428.CreateRouteTableRequest{
			RegionId:       tea.String(cluster.Region),
			VpcId:          tea.String(vpc.RefId),
			RouteTableName: tea.String(publicRouteTableName),
		}
		publicRouteTableRes, err := a.vpcClient.CreateRouteTable(publicRouteTableReq)
		if err != nil {
			return errors.Wrap(err, "failed to create public route table")
		}

		// Add tags to public route table
		err = a.createVpcTags(cluster.Region, tea.StringValue(publicRouteTableRes.Body.RouteTableId), "ROUTETABLE", publicRouteTableTags)
		if err != nil {
			return errors.Wrap(err, "failed to tag public route table")
		}

		cluster.AddCloudResource(&CloudResource{
			Name:         publicRouteTableName,
			RefId:        tea.StringValue(publicRouteTableRes.Body.RouteTableId),
			Tags:         cluster.EncodeTags(publicRouteTableTags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("public route table %s created", tea.StringValue(publicRouteTableRes.Body.RouteTableId))

		// Add route to Internet Gateway in public route table
		_, err = a.vpcClient.CreateRouteEntry(&vpc20160428.CreateRouteEntryRequest{
			RegionId:             tea.String(cluster.Region),
			RouteTableId:         publicRouteTableRes.Body.RouteTableId,
			DestinationCidrBlock: tea.String("0.0.0.0/0"),
			NextHopType:          tea.String("InternetGateway"),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add route to Internet Gateway")
		}

		// Associate public subnets with public route table
		for _, subnetResource := range cluster.GetCloudResource(ResourceType_SUBNET) {
			subnetResourceMapTags := cluster.DecodeTags(subnetResource.Tags)
			if typeVal, ok := subnetResourceMapTags[ALICLOUD_TAG_KEY_TYPE]; !ok || typeVal != AlicloudResourcePublic {
				continue
			}

			_, err = a.vpcClient.AssociateRouteTable(&vpc20160428.AssociateRouteTableRequest{
				RegionId:     tea.String(cluster.Region),
				RouteTableId: publicRouteTableRes.Body.RouteTableId,
				VSwitchId:    tea.String(subnetResource.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate public subnet with route table")
			}
		}
	}

	// Create private route tables (one per AZ)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		privateRouteTableName := fmt.Sprintf("%s-private-rt-%s", cluster.Name, az.Name)
		tags := map[string]string{
			ALICLOUD_TAG_KEY_NAME: privateRouteTableName,
			ALICLOUD_TAG_KEY_TYPE: AlicloudResourcePrivate,
			ALICLOUD_TAG_KEY_ZONE: az.Name,
		}

		if cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, ALICLOUD_TAG_KEY_NAME, privateRouteTableName) != nil {
			continue
		}

		// Create private route table
		privateRouteTableReq := &vpc20160428.CreateRouteTableRequest{
			RegionId:       tea.String(cluster.Region),
			VpcId:          tea.String(vpc.RefId),
			RouteTableName: tea.String(privateRouteTableName),
		}
		privateRouteTableRes, err := a.vpcClient.CreateRouteTable(privateRouteTableReq)
		if err != nil {
			return errors.Wrap(err, "failed to create private route table for AZ "+az.Name)
		}

		// Add tags to private route table
		err = a.createVpcTags(cluster.Region, tea.StringValue(privateRouteTableRes.Body.RouteTableId), "ROUTETABLE", tags)
		if err != nil {
			return errors.Wrap(err, "failed to tag private route table")
		}

		cluster.AddCloudResource(&CloudResource{
			Name:         privateRouteTableName,
			RefId:        tea.StringValue(privateRouteTableRes.Body.RouteTableId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_ROUTE_TABLE,
			AssociatedId: vpc.RefId,
		})
		a.log.Infof("private route table %s created for AZ %s", tea.StringValue(privateRouteTableRes.Body.RouteTableId), az.Name)

		// Add route to NAT Gateway in private route table
		for _, natGateway := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
			natGatewayMapTags := cluster.DecodeTags(natGateway.Tags)
			if zoneName, ok := natGatewayMapTags[ALICLOUD_TAG_KEY_ZONE]; !ok || zoneName != az.Name {
				continue
			}

			_, err = a.vpcClient.CreateRouteEntry(&vpc20160428.CreateRouteEntryRequest{
				RegionId:             tea.String(cluster.Region),
				RouteTableId:         privateRouteTableRes.Body.RouteTableId,
				DestinationCidrBlock: tea.String("0.0.0.0/0"),
				NextHopType:          tea.String("NatGateway"),
				NextHopId:            tea.String(natGateway.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to add route to NAT Gateway for AZ "+az.Name)
			}
		}

		// Associate private subnets with private route table
		for _, subnet := range cluster.GetCloudResourceByTags(ResourceType_SUBNET, ALICLOUD_TAG_KEY_TYPE, AlicloudResourcePrivate, ALICLOUD_TAG_KEY_ZONE, az.Name) {
			_, err = a.vpcClient.AssociateRouteTable(&vpc20160428.AssociateRouteTableRequest{
				RegionId:     tea.String(cluster.Region),
				RouteTableId: privateRouteTableRes.Body.RouteTableId,
				VSwitchId:    tea.String(subnet.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate private subnet with route table in AZ "+az.Name)
			}
		}
	}

	return nil
}

func (a *AliCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	sgNames := []string{
		fmt.Sprintf("%s-%s-sg", cluster.Name, AlicloudResourceHttpSG),
		fmt.Sprintf("%s-%s-sg", cluster.Name, AlicloudResourceBostionHostSG),
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

	// Process existing security groups
	for _, securityGroup := range existingSecurityGroups {
		if utils.InArray(tea.StringValue(securityGroup.SecurityGroupName), sgNames) {
			if cluster.GetCloudResourceByRefID(ResourceType_SECURITY_GROUP, tea.StringValue(securityGroup.SecurityGroupId)) != nil {
				a.log.Infof("security group %s already exists", tea.StringValue(securityGroup.SecurityGroupId))
				continue
			}

			tags := make(map[string]string)
			for _, tag := range securityGroup.Tags.Tag {
				tags[tea.StringValue(tag.TagKey)] = tea.StringValue(tag.TagValue)
			}

			cluster.AddCloudResource(&CloudResource{
				Name:         tea.StringValue(securityGroup.SecurityGroupName),
				RefId:        tea.StringValue(securityGroup.SecurityGroupId),
				Tags:         cluster.EncodeTags(tags),
				AssociatedId: vpc.RefId,
				Type:         ResourceType_SECURITY_GROUP,
			})
			a.log.Infof("security group %s already exists", tea.StringValue(securityGroup.SecurityGroupId))
		}
	}

	// Create security groups if they don't exist
	for _, sgName := range sgNames {
		if cluster.GetCloudResourceByName(ResourceType_SECURITY_GROUP, sgName) != nil {
			continue
		}

		tags := map[string]string{ALICLOUD_TAG_KEY_NAME: sgName}
		if strings.Contains(sgName, AlicloudResourceHttpSG) {
			tags[ALICLOUD_TAG_KEY_TYPE] = AlicloudResourceHttpSG
		}
		if strings.Contains(sgName, AlicloudResourceBostionHostSG) {
			tags[ALICLOUD_TAG_KEY_TYPE] = AlicloudResourceBostionHostSG
		}

		// Create security group
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

		// Add tags to security group
		err = a.createEcsTag(cluster.Region, tea.StringValue(sgRes.Body.SecurityGroupId), "securitygroup", tags)
		if err != nil {
			return errors.Wrap(err, "failed to tag security group")
		}

		cluster.AddCloudResource(&CloudResource{
			Name:         sgName,
			RefId:        tea.StringValue(sgRes.Body.SecurityGroupId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SECURITY_GROUP,
			AssociatedId: vpc.RefId,
		})
		a.log.Infof("security group %s created", tea.StringValue(sgRes.Body.SecurityGroupId))

		// Add security group rules
		if v, ok := tags[ALICLOUD_TAG_KEY_TYPE]; ok && v == AlicloudResourceHttpSG {
			// Add rules for bastion host security group
			for _, sg := range cluster.SecurityGroups {
				_, err = a.ecsClient.AuthorizeSecurityGroup(&ecs20140526.AuthorizeSecurityGroupRequest{
					RegionId:        tea.String(cluster.Region),
					SecurityGroupId: sgRes.Body.SecurityGroupId,
					IpProtocol:      tea.String(sg.Protocol),
					PortRange:       tea.String(fmt.Sprintf("%d/%d", sg.IngressPort, sg.EgressPort)),
					SourceCidrIp:    tea.String(sg.IpCidr),
					Description:     tea.String(fmt.Sprintf("Allow %s access", sg.Protocol)),
				})
				if err != nil {
					return errors.Wrap(err, "failed to add security group rule")
				}
			}
		}

		if v, ok := tags[ALICLOUD_TAG_KEY_TYPE]; ok && v == AlicloudResourceHttpSG {
			// Add HTTP and HTTPS rules
			httpRules := []struct {
				protocol  string
				portRange string
			}{
				{"tcp", "80/80"},
				{"tcp", "443/443"},
			}

			for _, rule := range httpRules {
				_, err = a.ecsClient.AuthorizeSecurityGroup(&ecs20140526.AuthorizeSecurityGroupRequest{
					RegionId:        tea.String(cluster.Region),
					SecurityGroupId: sgRes.Body.SecurityGroupId,
					IpProtocol:      tea.String(rule.protocol),
					PortRange:       tea.String(rule.portRange),
					SourceCidrIp:    tea.String("0.0.0.0/0"),
					Description:     tea.String(fmt.Sprintf("Allow %s access on port %s", rule.protocol, rule.portRange)),
				})
				if err != nil {
					return errors.Wrap(err, "failed to add security group rule")
				}
			}
		}
	}

	return nil
}

func (a *AliCloudUsecase) createSLB(ctx context.Context, cluster *Cluster) error {
	if cluster.Level == ClusterLevel_BASIC {
		a.log.Info("skip create slb for basic cluster")
		return nil
	}

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

	// Get public VSwitches
	publicVSwitchIDs := make([]string, 0)
	for _, subnet := range cluster.GetCloudResource(ResourceType_SUBNET) {
		subnetMapTags := cluster.DecodeTags(subnet.Tags)
		if typeVal, ok := subnetMapTags[ALICLOUD_TAG_KEY_TYPE]; !ok || typeVal != AlicloudResourcePublic {
			continue
		}
		publicVSwitchIDs = append(publicVSwitchIDs, subnet.RefId)
	}
	if len(publicVSwitchIDs) == 0 {
		return errors.New("failed to get public vswitches")
	}

	// Get security groups
	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, ALICLOUD_TAG_KEY_TYPE, AlicloudResourceHttpSG)
	if len(sgs) == 0 {
		return errors.New("failed to get security group")
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
	tags := map[string]string{ALICLOUD_TAG_KEY_NAME: name}
	createSLBReq := &slb20140515.CreateLoadBalancerRequest{
		RegionId:         tea.String(cluster.Region),
		VpcId:            tea.String(vpc.RefId),
		VSwitchId:        tea.String(publicVSwitchIDs[0]), // Use first public VSwitch
		LoadBalancerName: tea.String(name),
		AddressType:      tea.String("internet"),
		LoadBalancerSpec: tea.String("slb.s2.small"),
		PayType:          tea.String("PayAsYouGo"),
	}

	slbRes, err := a.slbClient.CreateLoadBalancer(createSLBReq)
	if err != nil {
		return errors.Wrap(err, "failed to create SLB")
	}

	// Add tags to SLB
	err = a.createSlbTag(cluster.Region, tea.StringValue(slbRes.Body.LoadBalancerId), "instance", tags)
	if err != nil {
		return errors.Wrap(err, "failed to tag SLB")
	}

	cluster.AddCloudResource(&CloudResource{
		Name:  name,
		RefId: tea.StringValue(slbRes.Body.LoadBalancerId),
		Tags:  cluster.EncodeTags(tags),
		Type:  ResourceType_LOAD_BALANCER,
	})

	// Create VServer Group (similar to target group in AWS)
	vserverGroupName := fmt.Sprintf("%s-vserver-group", cluster.Name)
	vserverGroupReq := &slb20140515.CreateVServerGroupRequest{
		RegionId:         tea.String(cluster.Region),
		LoadBalancerId:   slbRes.Body.LoadBalancerId,
		VServerGroupName: tea.String(vserverGroupName),
	}

	vserverGroupRes, err := a.slbClient.CreateVServerGroup(vserverGroupReq)
	if err != nil {
		return errors.Wrap(err, "failed to create vserver group")
	}
	a.log.Infof("vserver group %s created", tea.StringValue(vserverGroupRes.Body.VServerGroupId))

	// Create listener
	listenerReq := &slb20140515.CreateLoadBalancerTCPListenerRequest{
		RegionId:          tea.String(cluster.Region),
		LoadBalancerId:    slbRes.Body.LoadBalancerId,
		ListenerPort:      tea.Int32(6443),
		BackendServerPort: tea.Int32(6443),
		VServerGroupId:    vserverGroupRes.Body.VServerGroupId,
		Bandwidth:         tea.Int32(-1), // Unlimited for PayAsYouGo
	}

	_, err = a.slbClient.CreateLoadBalancerTCPListener(listenerReq)
	if err != nil {
		return errors.Wrap(err, "failed to create listener")
	}

	// Start the listener
	_, err = a.slbClient.StartLoadBalancerListener(&slb20140515.StartLoadBalancerListenerRequest{
		RegionId:       tea.String(cluster.Region),
		LoadBalancerId: slbRes.Body.LoadBalancerId,
		ListenerPort:   tea.Int32(6443),
	})
	if err != nil {
		return errors.Wrap(err, "failed to start listener")
	}

	return nil
}

func (a *AliCloudUsecase) getIntanceTypeFamilies(nodeGroup *NodeGroup) string {
	if nodeGroup == nil {
		return "ecs.g6"
	}
	switch nodeGroup.Type {
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

func (a *AliCloudUsecase) findImage(regionId string) (*ecs20140526.DescribeImagesResponseBodyImagesImage, error) {
	images, err := a.ecsClient.DescribeImages(&ecs20140526.DescribeImagesRequest{
		RegionId:    tea.String(regionId),
		Status:      tea.String("Available"),
		OSType:      tea.String("Linux"),
		ImageFamily: tea.String("Ubuntu"),
		PageNumber:  tea.Int32(1),
		PageSize:    tea.Int32(1),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to describe images")
	}
	if tea.Int32Value(images.Body.TotalCount) == 0 {
		return nil, nil
	}
	return images.Body.Images.Image[0], nil
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

func (a *AliCloudUsecase) findInstanceType(instanceTypeFamiliy string, CPU, GPU, Memory int32) (*ecs20140526.DescribeInstanceTypesResponseBodyInstanceTypesInstanceType, error) {
	instanceTypes := make(InstanceTypes, 0)
	nexttoken := ""
	for {
		instancesRes, err := a.ecsClient.DescribeInstanceTypes(&ecs20140526.DescribeInstanceTypesRequest{
			InstanceTypeFamily:  tea.String(instanceTypeFamiliy),
			CpuArchitecture:     tea.String("x86_64"),
			MaximumCpuCoreCount: tea.Int32(CPU),
			MaximumGPUAmount:    tea.Int32(GPU),
			MaximumMemorySize:   tea.Float32(float32(Memory)),
			NextToken:           tea.String(nexttoken),
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to describe instance types")
		}
		instanceTypes = append(instanceTypes, instancesRes.Body.InstanceTypes.InstanceType...)
		if len(instancesRes.Body.InstanceTypes.InstanceType) == 0 || tea.StringValue(instancesRes.Body.NextToken) == "" {
			break
		}
		nexttoken = tea.StringValue(instancesRes.Body.NextToken)
	}
	sort.Sort(instanceTypes)
	var instanceTypeInfo *ecs20140526.DescribeInstanceTypesResponseBodyInstanceTypesInstanceType
	for _, instanceType := range instanceTypes {
		if tea.Float32Value(instanceType.MemorySize) == 0 {
			continue
		}
		if tea.Float32Value(instanceType.MemorySize) >= float32(Memory) && tea.Int32Value(instanceType.CpuCoreCount) >= CPU {
			instanceTypeInfo = instanceType
		}
		if instanceTypeInfo == nil {
			continue
		}
		if GPU == 0 {
			break
		}
		if tea.Int32Value(instanceType.GPUAmount) >= GPU {
			break
		}
	}
	if instanceTypeInfo == nil {
		return nil, errors.New("no instance type found")
	}
	return instanceTypeInfo, nil
}

func (a *AliCloudUsecase) createVpcTags(regionID, resourceID, resourceType string, tags map[string]string) error {
	vpcTags := make([]*vpc20160428.TagResourcesRequestTag, 0)
	for key, value := range tags {
		vpcTags = append(vpcTags, &vpc20160428.TagResourcesRequestTag{
			Key:   tea.String(key),
			Value: tea.String(value),
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

func (a *AliCloudUsecase) createEcsTag(regionID, resourceID, resourceType string, tags map[string]string) error {
	ecsTags := make([]*ecs20140526.TagResourcesRequestTag, 0)
	for key, value := range tags {
		ecsTags = append(ecsTags, &ecs20140526.TagResourcesRequestTag{
			Key:   tea.String(key),
			Value: tea.String(value),
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

func (a *AliCloudUsecase) createSlbTag(regionID, resourceID, resourceType string, tags map[string]string) error {
	slbTags := make([]*slb20140515.TagResourcesRequestTag, 0)
	for key, value := range tags {
		slbTags = append(slbTags, &slb20140515.TagResourcesRequestTag{
			Key:   tea.String(key),
			Value: tea.String(value),
		})
	}
	_, err := a.slbClient.TagResources(&slb20140515.TagResourcesRequest{
		RegionId:     tea.String(regionID),
		ResourceType: tea.String(resourceType),
		ResourceId:   tea.StringSlice([]string{resourceID}),
		Tag:          slbTags,
	})
	if err != nil {
		return errors.Wrap(err, "failed to tag slb")
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
