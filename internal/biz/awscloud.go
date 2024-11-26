package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elasticloadbalancingv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/pkg/errors"
)

const (
	awsDefaultRegion = "us-east-1"
	AwsTagKeyName    = "Name"
	AwsTagKeyType    = "Type"
	AwsTagKeyZone    = "Zone"
	AwsTagKeyVpc     = "Vpc"

	AwsResourcePublic        = "Public"
	AwsResourcePrivate       = "Private"
	AwsReosurceUnBind        = "false"
	AwsReousrceBostionHostSG = "bostionHost"
	AwsResourceHttpSG        = "http"
)

const (
	TimeoutPerInstance = 5 * time.Minute
	AwsNotFound        = "NotFound"
)

type AwsCloudUsecase struct {
	ec2Client   *ec2.Client
	elbv2Client *elasticloadbalancingv2.Client
	log         *log.Helper
}

func NewAwsCloudUseCase(logger log.Logger) *AwsCloudUsecase {
	c := &AwsCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}

func (a *AwsCloudUsecase) Connections(ctx context.Context, cluster *Cluster) error {
	if cluster.Region == "" {
		cluster.Region = awsDefaultRegion
	}
	os.Setenv("AWS_REGION", cluster.Region)
	os.Setenv("AWS_DEFAULT_REGION", cluster.Region)
	os.Setenv("AWS_ACCESS_KEY_ID", cluster.AccessId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", cluster.AccessKey)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cluster.Region))
	if err != nil {
		return err
	}
	a.ec2Client = ec2.NewFromConfig(cfg)
	a.elbv2Client = elasticloadbalancingv2.NewFromConfig(cfg)
	return nil
}

// Get availability zones
func (a *AwsCloudUsecase) GetAvailabilityZones(ctx context.Context, cluster *Cluster) error {
	cluster.DeleteCloudResource(ResourceType_AVAILABILITY_ZONES)
	result, err := a.ec2Client.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
			{
				Name:   aws.String("region-name"),
				Values: []string{cluster.Region},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe regions")
	}
	if len(result.AvailabilityZones) == 0 {
		return errors.New("no availability zones found")
	}
	for _, az := range result.AvailabilityZones {
		cluster.AddCloudResource(&CloudResource{
			Name:  aws.ToString(az.ZoneName),
			RefId: aws.ToString(az.ZoneId),
			Type:  ResourceType_AVAILABILITY_ZONES,
			Value: aws.ToString(az.RegionName),
		})
	}
	return nil
}

// create network(vpc, subnet, internet gateway,nat gateway, route table, security group)
func (a *AwsCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	funcs := []func(context.Context, *Cluster) error{
		a.createVPC,             // Step 1: Check and Create VPC
		a.createSubnets,         // Step 2: Check and Create subnets
		a.createInternetGateway, // Step 3: Check and Create Internet Gateway
		a.createNATGateways,     // Step 4: Check and Create NAT Gateways
		a.createRouteTables,     // Step 5: Check and Create route tables
		a.createSecurityGroup,   // Step 6: Check and Create security group
		a.createS3Endpoint,      // Step 7: Check and Create s3 endpoint
		a.createSLB,             // Step 8: Check and Create slb
	}
	for _, f := range funcs {
		err := f(ctx, cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

// delete network(vpc, subnet, internet gateway, nat gateway, route table, security group)
func (a *AwsCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	// Delete vpc s3 endpoints
	for _, endpoint := range cluster.GetCloudResource(ResourceType_VPC_ENDPOINT_S3) {
		_, err := a.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			VpcEndpointIds: []string{endpoint.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No vpc endpoint found with name: %s\n", endpoint.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe vpc endpoint")
		}
		_, err = a.ec2Client.DeleteVpcEndpoints(ctx, &ec2.DeleteVpcEndpointsInput{
			VpcEndpointIds: []string{endpoint.RefId},
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete vpc endpoint")
		}
	}
	cluster.DeleteCloudResource(ResourceType_VPC_ENDPOINT_S3)

	// Step 1: Delete security group
	for _, sg := range cluster.GetCloudResource(ResourceType_SECURITY_GROUP) {
		_, err := a.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{sg.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No security group found with name: %s\n", sg.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe security group")
		}
		_, err = a.ec2Client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(sg.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete security group")
		}
	}
	cluster.DeleteCloudResource(ResourceType_SECURITY_GROUP)

	// Step 2: Delete route tables
	rts := cluster.GetCloudResource(ResourceType_ROUTE_TABLE)
	for _, rt := range rts {
		_, err := a.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			RouteTableIds: []string{rt.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No route table found with name: %s\n", rt.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe route table")
		}
		for _, subRtassoc := range rt.SubResources {
			_, err = a.ec2Client.DisassociateRouteTable(ctx, &ec2.DisassociateRouteTableInput{
				AssociationId: aws.String(subRtassoc.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to disassociate route table")
			}
		}
		_, err = a.ec2Client.DeleteRouteTable(ctx, &ec2.DeleteRouteTableInput{
			RouteTableId: aws.String(rt.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete route table")
		}
	}
	cluster.DeleteCloudResource(ResourceType_ROUTE_TABLE)

	// Step 4: Delete NAT Gateways
	natGwIDs := make([]string, 0)
	for _, natGw := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
		_, err := a.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
			NatGatewayIds: []string{natGw.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No NAT Gateway found with Name: %s\n", natGw.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe NAT Gateway")
		}
		_, err = a.ec2Client.DeleteNatGateway(ctx, &ec2.DeleteNatGatewayInput{
			NatGatewayId: aws.String(natGw.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete NAT Gateway")
		}
		natGwIDs = append(natGwIDs, natGw.RefId)
	}
	// Wait for NAT Gateway to be deleted
	waiter := ec2.NewNatGatewayDeletedWaiter(a.ec2Client)
	err := waiter.Wait(ctx, &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: natGwIDs,
	}, time.Duration(len(natGwIDs))*TimeoutPerInstance)
	if err != nil {
		return fmt.Errorf("failed to wait for NAT Gateway deletion: %w", err)
	}
	cluster.DeleteCloudResource(ResourceType_NAT_GATEWAY)

	// Release Elastic IPs associated with NAT Gateways
	for _, addr := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
		_, err := a.ec2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
			AllocationIds: []string{addr.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No Elastic IP found with name: %s\n", addr.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe Elastic IP")
		}
		_, err = a.ec2Client.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{
			AllocationId: aws.String(addr.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to release Elastic IP")
		}
	}
	cluster.DeleteCloudResource(ResourceType_ELASTIC_IP)

	// Step 3: Delete Internet Gateway
	for _, igw := range cluster.GetCloudResource(ResourceType_INTERNET_GATEWAY) {
		_, err := a.ec2Client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []string{igw.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No Internet Gateway found with name: %s\n", igw.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe Internet Gateway")
		}
		_, err = a.ec2Client.DetachInternetGateway(ctx, &ec2.DetachInternetGatewayInput{
			InternetGatewayId: aws.String(igw.RefId),
			VpcId:             aws.String(vpc.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to detach Internet Gateway")
		}
		_, err = a.ec2Client.DeleteInternetGateway(ctx, &ec2.DeleteInternetGatewayInput{
			InternetGatewayId: aws.String(igw.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete Internet Gateway")
		}
	}
	cluster.DeleteCloudResource(ResourceType_INTERNET_GATEWAY)

	// // Step 5: Delete Subnets
	for _, subnet := range cluster.GetCloudResource(ResourceType_SUBNET) {
		_, err := a.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []string{subnet.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No subnet found with Name: %s\n", subnet.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe subnet")
		}
		_, err = a.ec2Client.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{
			SubnetId: aws.String(subnet.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete subnet")
		}
	}
	cluster.DeleteCloudResource(ResourceType_SUBNET)

	// Step 6: Delete VPC
	_, err = a.ec2Client.DeleteVpc(ctx, &ec2.DeleteVpcInput{
		VpcId: aws.String(vpc.RefId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to delete VPC")
	}
	cluster.DeleteCloudResource(ResourceType_VPC)

	// step 7: Delete SLB
	for _, slb := range cluster.GetCloudResource(ResourceType_LOAD_BALANCER) {
		_, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			LoadBalancerArns: []string{slb.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Warnf("No SLB found with name: %s\n", slb.Name)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe SLB")
		}
		_, err = a.elbv2Client.DeleteLoadBalancer(ctx, &elasticloadbalancingv2.DeleteLoadBalancerInput{
			LoadBalancerArn: &slb.RefId,
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete SLB")
		}
	}
	cluster.DeleteCloudResource(ResourceType_LOAD_BALANCER)
	return nil
}

// get instance type familiy
func (a *AwsCloudUsecase) SetByNodeGroups(ctx context.Context, cluster *Cluster) error {
	image, err := a.findImage(ctx)
	if err != nil {
		return err
	}
	for _, ng := range cluster.NodeGroups {
		platformDetails := strings.Split(aws.ToString(image.PlatformDetails), "/")
		if len(platformDetails) > 0 {
			ng.Os = strings.ToLower(platformDetails[0])
		}
		ng.Image = aws.ToString(image.ImageId)
		ng.ImageDescription = aws.ToString(image.Description)
		ng.Arch = string(image.Architecture)
		ng.DefaultUsername = a.determineUsername(aws.ToString(image.Name), aws.ToString(image.Description))
		ng.RootDeviceName = aws.ToString(image.RootDeviceName)
		for _, dataDeivce := range image.BlockDeviceMappings {
			if dataDeivce.DeviceName != nil && aws.ToString(dataDeivce.DeviceName) != ng.RootDeviceName {
				ng.DataDeviceName = aws.ToString(dataDeivce.DeviceName)
				break
			}
		}
		a.log.Info(strings.Join([]string{"image found: ", aws.ToString(image.Name), aws.ToString(image.Description)}, " "))

		if ng.InstanceType != "" {
			continue
		}
		instanceTypeFamiliy := a.getIntanceTypeFamilies(ng)
		instanceInfo, err := a.findInstanceType(ctx, instanceTypeFamiliy, ng.Cpu, ng.Gpu, ng.Memory)
		if err != nil {
			return err
		}
		ng.InstanceType = string(instanceInfo.InstanceType)
		if instanceInfo.VCpuInfo != nil && instanceInfo.VCpuInfo.DefaultVCpus != nil {
			ng.Cpu = aws.ToInt32(instanceInfo.VCpuInfo.DefaultVCpus)
		}
		if instanceInfo.MemoryInfo != nil && instanceInfo.MemoryInfo.SizeInMiB != nil {
			ng.Memory = int32(aws.ToInt64(instanceInfo.MemoryInfo.SizeInMiB) / 1024)
		}
		if ng.Gpu != 0 && instanceInfo.GpuInfo != nil && len(instanceInfo.GpuInfo.Gpus) > 0 {
			for _, g := range instanceInfo.GpuInfo.Gpus {
				ng.Gpu += aws.ToInt32(g.Count)
				ng.GpuSpec += fmt.Sprintf("-%s", aws.ToString(g.Name))
			}
		}
		a.log.Info("instance type found: ", ng.InstanceType)
	}
	return nil
}

// KeyPair
func (a *AwsCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	keyName := cluster.Name + "-keypair"
	tags := map[string]string{AwsTagKeyName: keyName}
	keyPairOutputs, err := a.ec2Client.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{
		KeyNames: []string{keyName},
	})
	if err != nil && !strings.Contains(err.Error(), AwsNotFound) {
		return fmt.Errorf("failed to describe key pair: %v", err)
	}
	if keyPairOutputs != nil && len(keyPairOutputs.KeyPairs) != 0 {
		for _, keyPair := range keyPairOutputs.KeyPairs {
			if keyPair.KeyPairId == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_KEY_PAIR, aws.ToString(keyPair.KeyPairId)) != nil {
				continue
			}
			cluster.AddCloudResource(&CloudResource{
				Name:  aws.ToString(keyPair.KeyName),
				RefId: aws.ToString(keyPair.KeyPairId),
				Tags:  cluster.EncodeTags(tags),
				Type:  ResourceType_KEY_PAIR,
			})
			a.log.Info("key pair found")
		}
		return nil
	}

	keyPairOutput, err := a.ec2Client.ImportKeyPair(ctx, &ec2.ImportKeyPairInput{
		KeyName:           aws.String(keyName),
		PublicKeyMaterial: []byte(cluster.PublicKey),
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeKeyPair,
				Tags:         a.mapToEc2Tags(tags),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to import key pair: %v", err)
	}
	a.log.Info("key pair imported")
	cluster.AddCloudResource(&CloudResource{
		Name:  keyName,
		RefId: aws.ToString(keyPairOutput.KeyPairId),
		Tags:  cluster.EncodeTags(tags),
		Type:  ResourceType_KEY_PAIR,
	})
	return nil
}

func (a *AwsCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	for _, keyPair := range cluster.GetCloudResource(ResourceType_KEY_PAIR) {
		_, err := a.ec2Client.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{
			KeyNames: []string{keyPair.Name},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Warnf("No key pair found with Key Name: %s\n", keyPair.Name)
			continue
		}
		_, err = a.ec2Client.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{
			KeyName: aws.String(keyPair.Name),
		})
		if err != nil {
			return fmt.Errorf("failed to delete key pair: %v", err)
		}
		a.log.Info("key pair deleted")
	}
	cluster.DeleteCloudResource(ResourceType_KEY_PAIR)
	return nil
}

func (a *AwsCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	// Delete instances
	needDeleteInstanceIDs := make([]string, 0)
	for _, node := range cluster.Nodes {
		if node.Status == NodeStatus_NODE_DELETING && node.InstanceId != "" {
			needDeleteInstanceIDs = append(needDeleteInstanceIDs, node.InstanceId)
		}
	}
	instances, err := a.getInstances(ctx, cluster, []string{}, []string{fmt.Sprintf("%s-node*", cluster.Name)})
	if err != nil {
		return err
	}
	deleteInstanceIDs := make([]string, 0)
	for _, instance := range instances {
		if utils.InArray(aws.ToString(instance.InstanceId), needDeleteInstanceIDs) {
			deleteInstanceIDs = append(deleteInstanceIDs, aws.ToString(instance.InstanceId))
		}
	}
	if len(deleteInstanceIDs) > 0 {
		_, err = a.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: deleteInstanceIDs,
		})
		if err != nil {
			return errors.Wrap(err, "failed to terminate instances")
		}
		waiter := ec2.NewInstanceTerminatedWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: deleteInstanceIDs,
		}, time.Duration(len(deleteInstanceIDs))*TimeoutPerInstance)
		if err != nil {
			return fmt.Errorf("failed to wait for instance termination: %w", err)
		}
		for _, node := range cluster.Nodes {
			if utils.InArray(node.InstanceId, deleteInstanceIDs) {
				node.Status = NodeStatus_NODE_DELETED
			}
		}
		a.log.Info("instances terminated")
	}

	// Create instances
	instanceIds := make([]string, 0)
	for index, node := range cluster.Nodes {
		if node.Status != NodeStatus_NODE_CREATING {
			continue
		}
		nodeGroup := cluster.GetNodeGroup(node.NodeGroupId)
		nodeTags := make(map[string]string)
		if node.Labels != "" {
			err = json.Unmarshal([]byte(node.Labels), &nodeTags)
			if err != nil {
				return errors.Wrap(err, "failed to parse labels")
			}
		}
		nodeTags[AwsTagKeyName] = node.Name
		// root Volume
		blockDeviceMappings := []ec2Types.BlockDeviceMapping{
			{
				DeviceName: aws.String(nodeGroup.RootDeviceName),
				Ebs: &ec2Types.EbsBlockDevice{
					VolumeSize:          aws.Int32(30),
					VolumeType:          ec2Types.VolumeTypeGp3,
					DeleteOnTermination: aws.Bool(true),
				},
			},
		}
		if nodeGroup.DataDisk > 0 {
			blockDeviceMappings = append(blockDeviceMappings, ec2Types.BlockDeviceMapping{
				DeviceName: aws.String(nodeGroup.DataDeviceName),
				Ebs: &ec2Types.EbsBlockDevice{
					VolumeSize:          aws.Int32(nodeGroup.DataDisk),
					VolumeType:          ec2Types.VolumeTypeGp3,
					DeleteOnTermination: aws.Bool(true),
				},
			})
		}
		sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, AwsTagKeyType, AwsResourceHttpSG)
		if sgs == nil {
			return errors.Wrap(err, "security group not found")
		}
		sgIDs := make([]string, 0)
		for _, v := range sgs {
			sgIDs = append(sgIDs, v.RefId)
		}
		keyName := cluster.GetSingleCloudResource(ResourceType_KEY_PAIR).Name
		privateSubnetID := a.distributeNodeSubnets(cluster, index)
		instanceOutput, err := a.ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
			ImageId:             aws.String(nodeGroup.Image),
			InstanceType:        ec2Types.InstanceType(nodeGroup.InstanceType),
			KeyName:             aws.String(keyName),
			MaxCount:            aws.Int32(1),
			MinCount:            aws.Int32(1),
			SecurityGroupIds:    sgIDs,
			SubnetId:            aws.String(privateSubnetID),
			BlockDeviceMappings: blockDeviceMappings,
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeInstance,
					Tags:         a.mapToEc2Tags(nodeTags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to run instances")
		}
		for _, instance := range instanceOutput.Instances {
			a.log.Info("instance createing", "name", node.Name, "id", aws.ToString(instance.InstanceId))
			if instance.PrivateIpAddress != nil {
				node.InternalIp = aws.ToString(instance.PrivateIpAddress)
			}
			if instance.PublicIpAddress != nil {
				node.ExternalIp = aws.ToString(instance.PublicIpAddress)
			}
			node.InstanceId = aws.ToString(instance.InstanceId)
			instanceIds = append(instanceIds, aws.ToString(instance.InstanceId))
		}
		node.User = nodeGroup.DefaultUsername
		node.Status = NodeStatus_NODE_CREATING
	}

	// wait for instance running
	if len(instanceIds) > 0 {
		waiter := ec2.NewInstanceRunningWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: instanceIds,
		}, time.Duration(len(instanceIds))*TimeoutPerInstance)
		if err != nil {
			return fmt.Errorf("failed to wait for instance running: %w", err)
		}
		for _, instanceId := range instanceIds {
			for _, node := range cluster.Nodes {
				if node.InstanceId == instanceId {
					node.Status = NodeStatus_NODE_RUNNING
					break
				}
			}
		}
	}
	return nil
}

// Manage BostionHost
func (a *AwsCloudUsecase) ManageBostionHost(ctx context.Context, cluster *Cluster) error {
	if cluster.BostionHost == nil {
		return nil
	}
	if cluster.BostionHost.Status == NodeStatus_NODE_DELETING {
		if cluster.BostionHost.InstanceId == "" {
			return nil
		}
		_, err := a.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: []string{cluster.BostionHost.InstanceId},
		})
		if err != nil {
			return errors.Wrap(err, "failed to terminate instances")
		}
		waiter := ec2.NewInstanceTerminatedWaiter(a.ec2Client)
		err = waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{cluster.BostionHost.InstanceId}}, time.Duration(1)*TimeoutPerInstance)
		if err != nil {
			return fmt.Errorf("failed to wait for instance termination: %w", err)
		}
		cluster.BostionHost.Status = NodeStatus_NODE_DELETED
		return nil
	}

	if cluster.BostionHost.Status != NodeStatus_NODE_CREATING {
		return nil
	}

	// find image
	image, err := a.findImage(ctx)
	if err != nil {
		return err
	}
	platformDetails := strings.Split(aws.ToString(image.PlatformDetails), "/")
	if len(platformDetails) > 0 {
		cluster.BostionHost.Os = strings.ToLower(platformDetails[0])
	}
	cluster.BostionHost.Arch = string(image.Architecture)
	cluster.BostionHost.Image = aws.ToString(image.ImageId)
	cluster.BostionHost.ImageDescription = aws.ToString(image.Description)

	// find instance type
	instanceType, err := a.findInstanceType(ctx, "t3.*", cluster.BostionHost.Cpu, 0, cluster.BostionHost.Memory)
	if err != nil {
		return err
	}
	publicSubnet := cluster.GetCloudResourceByTags(ResourceType_SUBNET, AwsTagKeyType, AwsResourcePublic)
	if len(publicSubnet) == 0 {
		return errors.New("public subnet not found in the ManageBostionHost")
	}
	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, AwsTagKeyType, AwsReousrceBostionHostSG)
	if len(sgs) == 0 {
		return errors.New("security group not found in the ManageBostionHost")
	}
	sgIds := make([]string, 0)
	for _, v := range sgs {
		sgIds = append(sgIds, v.RefId)
	}

	keyPair := cluster.GetSingleCloudResource(ResourceType_KEY_PAIR)
	if keyPair == nil {
		return errors.New("key pair not found in the ManageBostionHost")
	}

	bostionHostTag := map[string]string{
		AwsTagKeyName: fmt.Sprintf("%s-%s", cluster.Name, "bostion"),
	}
	instanceOutput, err := a.ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:      image.ImageId,
		InstanceType: ec2Types.InstanceType(instanceType.InstanceType),
		MaxCount:     aws.Int32(1),
		MinCount:     aws.Int32(1),
		KeyName:      aws.String(keyPair.Name),
		NetworkInterfaces: []ec2Types.InstanceNetworkInterfaceSpecification{
			{
				DeviceIndex:              aws.Int32(0),
				AssociatePublicIpAddress: aws.Bool(true),
				DeleteOnTermination:      aws.Bool(true),
				SubnetId:                 aws.String(publicSubnet[0].RefId),
				Groups:                   sgIds,
				Description:              aws.String("ManageBostionHost network interface"),
			},
		},
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeInstance,
				Tags:         a.mapToEc2Tags(bostionHostTag),
			},
		},
		BlockDeviceMappings: []ec2Types.BlockDeviceMapping{
			{
				DeviceName: aws.String(aws.ToString(image.RootDeviceName)),
				Ebs: &ec2Types.EbsBlockDevice{
					VolumeSize:          aws.Int32(10),
					VolumeType:          ec2Types.VolumeTypeGp3,
					DeleteOnTermination: aws.Bool(true),
				},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to run instances in the ManageBostionHost")
	}

	instanceIds := make([]string, 0)
	for _, instance := range instanceOutput.Instances {
		instanceIds = append(instanceIds, aws.ToString(instance.InstanceId))
	}
	waiter := ec2.NewInstanceRunningWaiter(a.ec2Client)
	err = waiter.Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	}, time.Duration(1)*TimeoutPerInstance)
	if err != nil {
		return fmt.Errorf("failed to wait for instance running: %w", err)
	}
	instances, err := a.getInstances(ctx, cluster, instanceIds, []string{})
	if err != nil {
		return err
	}
	for _, instance := range instances {
		cluster.BostionHost.InternalIp = aws.ToString(instance.PrivateIpAddress)
		cluster.BostionHost.ExternalIp = aws.ToString(instance.PublicIpAddress)
		cluster.BostionHost.Status = NodeStatus_NODE_RUNNING
		cluster.BostionHost.InstanceId = aws.ToString(instance.InstanceId)
		cluster.BostionHost.User = a.determineUsername(aws.ToString(image.Name), aws.ToString(image.Description))
		// cpu
		if instanceType.VCpuInfo != nil && instanceType.VCpuInfo.DefaultVCpus != nil {
			cluster.BostionHost.Cpu = aws.ToInt32(instanceType.VCpuInfo.DefaultVCpus)
		}
		// memory
		if instanceType.MemoryInfo != nil && instanceType.MemoryInfo.SizeInMiB != nil {
			cluster.BostionHost.Memory = int32(aws.ToInt64(instanceType.MemoryInfo.SizeInMiB) / 1024)
		}
	}
	return nil
}

// create vpc
func (a *AwsCloudUsecase) createVPC(ctx context.Context, cluster *Cluster) error {
	if cluster.GetSingleCloudResource(ResourceType_VPC) != nil {
		a.log.Info("vpc already exists ", "vpc ", cluster.GetSingleCloudResource(ResourceType_VPC).Name)
		return nil
	}
	vpcName := cluster.Name + "-vpc"
	existingVpcs, err := a.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{vpcName},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe VPCs")
	}
	vpcTags := map[string]string{AwsTagKeyName: vpcName}
	if len(existingVpcs.Vpcs) != 0 {
		for _, vpc := range existingVpcs.Vpcs {
			for _, tag := range vpc.Tags {
				vpcTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			cluster.AddCloudResource(&CloudResource{
				RefId: aws.ToString(vpc.VpcId),
				Name:  vpcName,
				Tags:  cluster.EncodeTags(vpcTags),
				Type:  ResourceType_VPC,
			})
			a.log.Infof("vpc %s already exists", cluster.GetSingleCloudResource(ResourceType_VPC).RefId)
		}
		return nil
	}

	// Create VPC if it doesn't exist
	vpcOutput, err := a.ec2Client.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String(cluster.IpCidr),
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeVpc,
				Tags:         a.mapToEc2Tags(vpcTags),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create VPC")
	}
	_, err = a.ec2Client.ModifyVpcAttribute(ctx, &ec2.ModifyVpcAttributeInput{
		VpcId: vpcOutput.Vpc.VpcId,
		EnableDnsSupport: &ec2Types.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to enable DNS support for VPC")
	}
	cluster.AddCloudResource(&CloudResource{
		RefId: aws.ToString(vpcOutput.Vpc.VpcId),
		Name:  vpcName,
		Tags:  cluster.EncodeTags(vpcTags),
		Type:  ResourceType_VPC,
	})
	a.log.Infof("vpc %s created", cluster.GetSingleCloudResource(ResourceType_VPC).Id)
	return nil
}

// Check and Create subnets
func (a *AwsCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingSubnets, err := a.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpc.RefId},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe subnets")
	}

	zoneSubnets := make(map[string][]ec2Types.Subnet)
	for _, subnet := range existingSubnets.Subnets {
		if subnet.AvailabilityZone == nil {
			continue
		}
		_, ok := zoneSubnets[aws.ToString(subnet.AvailabilityZone)]
		if ok && len(zoneSubnets[aws.ToString(subnet.AvailabilityZone)]) >= 3 {
			continue
		}
		zoneSubnets[aws.ToString(subnet.AvailabilityZone)] = append(zoneSubnets[aws.ToString(subnet.AvailabilityZone)], subnet)
	}
	for zoneName, subzoneSubnets := range zoneSubnets {
		for i, subnet := range subzoneSubnets {
			if subnet.SubnetId == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_SUBNET, aws.ToString(subnet.SubnetId)) != nil {
				a.log.Infof("subnet %s already exists", aws.ToString(subnet.SubnetId))
				continue
			}
			tags := make(map[string]string)
			name := ""
			for _, tag := range subnet.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			tags[AwsTagKeyZone] = zoneName
			if i < 2 {
				name = fmt.Sprintf("%s-private-subnet-%s-%d", cluster.Name, aws.ToString(subnet.AvailabilityZone), i+1)
				tags[AwsTagKeyType] = AwsResourcePrivate
			} else {
				name = fmt.Sprintf("%s-public-subnet-%s", cluster.Name, aws.ToString(subnet.AvailabilityZone))
				tags[AwsTagKeyType] = AwsResourcePublic
			}
			if nameVal, ok := tags[AwsTagKeyName]; !ok || nameVal != name {
				err = a.createTags(ctx, aws.ToString(subnet.SubnetId), ResourceType_SUBNET, tags)
				if err != nil {
					return err
				}
			}
			tags[AwsTagKeyName] = name
			cluster.AddCloudResource(&CloudResource{
				Name:  name,
				RefId: aws.ToString(subnet.SubnetId),
				Tags:  cluster.EncodeTags(tags),
				Type:  ResourceType_SUBNET,
			})
			a.log.Infof("subnet %s already exists", aws.ToString(subnet.SubnetId))
		}
	}

	// get subnet cidr
	privateSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES)) * 2
	publicSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES))
	subnetCidrRes, err := utils.GenerateSubnets(cluster.IpCidr, privateSubnetCount+publicSubnetCount+len(existingSubnets.Subnets))
	if err != nil {
		return errors.Wrap(err, "failed to generate subnet CIDRs")
	}
	subnetCidrs := make([]string, 0)
	existingSubnetCird := make(map[string]bool)
	for _, subnet := range existingSubnets.Subnets {
		existingSubnetCird[aws.ToString(subnet.CidrBlock)] = true
	}
	for _, subnetCidr := range subnetCidrRes {
		subnetCidrDecode := utils.DecodeCidr(subnetCidr)
		if subnetCidrDecode == "" {
			continue
		}
		ok := true
		for _, subnet := range existingSubnets.Subnets {
			existingSubnetCirdDecode := utils.DecodeCidr(aws.ToString(subnet.CidrBlock))
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
				AwsTagKeyName: name,
				AwsTagKeyType: AwsResourcePrivate,
				AwsTagKeyZone: az.Name,
			}
			if cluster.GetCloudResourceByTags(ResourceType_SUBNET, AwsTagKeyName, name) != nil {
				continue
			}
			cidr := subnetCidrs[i*2+j]
			subnetOutput, err := a.ec2Client.CreateSubnet(ctx, &ec2.CreateSubnetInput{
				VpcId:            aws.String(vpc.RefId),
				CidrBlock:        aws.String(cidr),
				AvailabilityZone: &az.Name,
				TagSpecifications: []ec2Types.TagSpecification{
					{
						ResourceType: ec2Types.ResourceTypeSubnet,
						Tags:         a.mapToEc2Tags(tags),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "failed to create private subnet")
			}
			cluster.AddCloudResource(&CloudResource{
				Name:         name,
				RefId:        aws.ToString(subnetOutput.Subnet.SubnetId),
				AssociatedId: vpc.RefId,
				Tags:         cluster.EncodeTags(tags),
				Type:         ResourceType_SUBNET,
			})
			a.log.Infof("private subnet %s created", aws.ToString(subnetOutput.Subnet.SubnetId))
		}

		// Create public subnet
		name := fmt.Sprintf("%s-public-subnet-%s", cluster.Name, az.Name)
		tags := map[string]string{
			AwsTagKeyName: name,
			AwsTagKeyType: AwsResourcePublic,
			AwsTagKeyZone: az.Name,
		}
		if cluster.GetCloudResourceByTags(ResourceType_SUBNET, AwsTagKeyName, name) != nil {
			continue
		}
		// Create public subnet
		cidr := subnetCidrs[privateSubnetCount+i]
		subnetOutput, err := a.ec2Client.CreateSubnet(ctx, &ec2.CreateSubnetInput{
			VpcId:            aws.String(vpc.RefId),
			CidrBlock:        aws.String(cidr),
			AvailabilityZone: &az.Name,
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeSubnet,
					Tags:         a.mapToEc2Tags(tags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create public subnet")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        aws.ToString(subnetOutput.Subnet.SubnetId),
			AssociatedId: vpc.RefId,
			Tags:         cluster.EncodeTags(tags),
		})
		a.log.Infof("public subnet %s created", aws.ToString(subnetOutput.Subnet.SubnetId))
	}
	return nil
}

// Check and Create Internet Gateway
func (a *AwsCloudUsecase) createInternetGateway(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingIgws, err := a.ec2Client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("attachment.vpc-id"),
				Values: []string{vpc.RefId},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe Internet Gateways")
	}

	if len(existingIgws.InternetGateways) != 0 {
		for _, igw := range existingIgws.InternetGateways {
			if igw.InternetGatewayId == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_INTERNET_GATEWAY, aws.ToString(igw.InternetGatewayId)) != nil {
				a.log.Infof("internet gateway %s already exists", aws.ToString(igw.InternetGatewayId))
				continue
			}
			name := ""
			tags := make(map[string]string)
			for _, tag := range igw.Tags {
				if aws.ToString(tag.Key) == AwsTagKeyName {
					name = aws.ToString(tag.Value)
				}
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if name == "" {
				name = fmt.Sprintf("%s-igw", cluster.Name)
			}
			if nameVal, ok := tags[AwsTagKeyName]; !ok || nameVal != name {
				tags[AwsTagKeyName] = name
				err = a.createTags(ctx, aws.ToString(igw.InternetGatewayId), ResourceType_INTERNET_GATEWAY, tags)
				if err != nil {
					return err
				}
			}
			tags[AwsTagKeyName] = name
			cluster.AddCloudResource(&CloudResource{
				Name:         name,
				RefId:        aws.ToString(igw.InternetGatewayId),
				Tags:         cluster.EncodeTags(tags),
				AssociatedId: vpc.RefId,
				Type:         ResourceType_INTERNET_GATEWAY,
			})
			a.log.Infof("internet gateway %s already exists", aws.ToString(igw.InternetGatewayId))
		}
		return nil
	}

	// Create Internet Gateway if it doesn't exist
	name := fmt.Sprintf("%s-igw", cluster.Name)
	tags := map[string]string{
		AwsTagKeyName: name,
	}
	igwOutput, err := a.ec2Client.CreateInternetGateway(ctx, &ec2.CreateInternetGatewayInput{
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeInternetGateway,
				Tags:         a.mapToEc2Tags(tags),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create Internet Gateway")
	}
	_, err = a.ec2Client.AttachInternetGateway(ctx, &ec2.AttachInternetGatewayInput{
		InternetGatewayId: igwOutput.InternetGateway.InternetGatewayId,
		VpcId:             aws.String(vpc.RefId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to attach Internet Gateway")
	}
	cluster.AddCloudResource(&CloudResource{
		Name:         name,
		RefId:        aws.ToString(igwOutput.InternetGateway.InternetGatewayId),
		Tags:         cluster.EncodeTags(tags),
		AssociatedId: vpc.RefId,
		Type:         ResourceType_INTERNET_GATEWAY,
	})

	a.log.Infof("internet gateway %s created", aws.ToString(igwOutput.InternetGateway.InternetGatewayId))
	return nil
}

// Check and Create NAT Gateways
func (a *AwsCloudUsecase) createNATGateways(ctx context.Context, cluster *Cluster) error {
	if cluster.Level == ClusterLevel_BASIC {
		return nil
	}
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingNatGateways, err := a.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			{Name: aws.String("state"), Values: []string{"available"}},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe NAT Gateways")
	}

	for _, natGateway := range existingNatGateways.NatGateways {
		if natGateway.SubnetId == nil || len(natGateway.NatGatewayAddresses) == 0 {
			continue
		}
		if cluster.GetCloudResourceByRefID(ResourceType_NAT_GATEWAY, aws.ToString(natGateway.NatGatewayId)) != nil {
			a.log.Infof("nat gateway %s already exists", aws.ToString(natGateway.NatGatewayId))
			continue
		}
		// check public subnet
		subnetCloudResource := cluster.GetCloudResourceByRefID(ResourceType_NAT_GATEWAY, aws.ToString(natGateway.SubnetId))
		if subnetCloudResource == nil {
			continue
		}
		subnetCloudResourceMapTags := cluster.DecodeTags(subnetCloudResource.Tags)
		if val, ok := subnetCloudResourceMapTags[AwsTagKeyType]; !ok || val != AwsResourcePublic {
			continue
		}
		tags := make(map[string]string)
		for _, tag := range natGateway.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		name := fmt.Sprintf("%s-nat-gateway-%s", cluster.Name, subnetCloudResourceMapTags[AwsTagKeyZone])
		tags[AwsTagKeyZone] = subnetCloudResourceMapTags[AwsTagKeyZone]
		if nameVal, ok := tags[AwsTagKeyName]; !ok || nameVal != name {
			tags[AwsTagKeyName] = name
			err = a.createTags(ctx, aws.ToString(natGateway.NatGatewayId), ResourceType_NAT_GATEWAY, tags)
			if err != nil {
				return err
			}
		}
		tags[AwsTagKeyName] = name
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        aws.ToString(natGateway.NatGatewayId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: aws.ToString(natGateway.SubnetId),
		})
		a.log.Infof("nat gateway %s already exists", aws.ToString(natGateway.NatGatewayId))
	}

	// Get Elastic IP
	eipRes, err := a.ec2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return errors.Wrap(err, "failed to describe Elastic IPs")
	}
	for _, eip := range eipRes.Addresses {
		if eip.Domain != ec2Types.DomainTypeVpc {
			continue
		}
		if eip.AssociationId != nil || eip.InstanceId != nil || eip.NetworkInterfaceId != nil {
			continue
		}
		if cluster.GetCloudResourceByID(ResourceType_ELASTIC_IP, aws.ToString(eip.AllocationId)) != nil {
			a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
			continue
		}
		name := ""
		tags := make(map[string]string)
		for _, tag := range eip.Tags {
			if aws.ToString(tag.Key) == AwsTagKeyName {
				name = aws.ToString(tag.Value)
			}
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		cluster.AddCloudResource(&CloudResource{
			RefId: aws.ToString(eip.AllocationId),
			Name:  name,
			Value: aws.ToString(eip.PublicIp),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_ELASTIC_IP,
		})
		a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
	}

	// Allocate Elastic IP
	usedEipID := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natGatewayName := fmt.Sprintf("%s-nat-gateway-%s", cluster.Name, az.Name)
		if cluster.GetCloudResourceByName(ResourceType_NAT_GATEWAY, natGatewayName) != nil {
			continue
		}
		eipName := fmt.Sprintf("%s-eip-%s", cluster.Name, az.Name)
		eipTags := map[string]string{AwsTagKeyName: eipName, AwsTagKeyZone: az.Name}
		for _, eipResource := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
			if utils.InArray(eipResource.RefId, usedEipID) {
				continue
			}
			if eipName != eipResource.Name {
				err = a.createTags(ctx, eipResource.RefId, ResourceType_ELASTIC_IP, eipTags)
				if err != nil {
					return err
				}
			}
			eipResource.Name = eipName
			eipResource.Tags = cluster.EncodeTags(eipTags)
			usedEipID = append(usedEipID, eipResource.RefId)
			break
		}

		if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, AwsTagKeyName, eipName) == nil {
			eipOutput, err := a.ec2Client.AllocateAddress(ctx, &ec2.AllocateAddressInput{
				Domain: ec2Types.DomainTypeVpc,
				TagSpecifications: []ec2Types.TagSpecification{
					{
						ResourceType: ec2Types.ResourceTypeElasticIp,
						Tags:         a.mapToEc2Tags(eipTags),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "failed to allocate Elastic IP")
			}
			cluster.AddCloudResource(&CloudResource{
				RefId: aws.ToString(eipOutput.AllocationId),
				Name:  eipName,
				Value: aws.ToString(eipOutput.PublicIp),
				Tags:  cluster.EncodeTags(eipTags),
				Type:  ResourceType_ELASTIC_IP,
			})
			a.log.Infof("elastic ip %s allocated", aws.ToString(eipOutput.PublicIp))
		}
	}

	// Create NAT Gateways if they don't exist for each AZ
	natGateWayIds := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natGatewayName := fmt.Sprintf("%s-nat-gateway-%s", cluster.Name, az.Name)
		if cluster.GetCloudResourceByName(ResourceType_NAT_GATEWAY, natGatewayName) != nil {
			continue
		}

		// Create NAT Gateway
		natGatewayTags := map[string]string{
			AwsTagKeyName: natGatewayName,
			AwsTagKeyType: AwsResourcePublic,
			AwsTagKeyZone: az.Name,
		}
		// eip
		eips := cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, AwsTagKeyZone, az.Name)
		if len(eips) == 0 {
			return errors.New("no Elastic IP found for AZ " + az.Name)
		}
		// public subnet
		publickSubnets := cluster.GetCloudResourceByTags(ResourceType_SUBNET, AwsTagKeyZone, az.Name, AwsTagKeyType, AwsResourcePublic)
		if len(publickSubnets) == 0 {
			return errors.New("no public subnet found for AZ " + az.Name)
		}
		natGatewayOutput, err := a.ec2Client.CreateNatGateway(ctx, &ec2.CreateNatGatewayInput{
			AllocationId:     &eips[0].RefId,
			SubnetId:         &publickSubnets[0].RefId,
			ConnectivityType: ec2Types.ConnectivityTypePublic,
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeNatgateway, // natgateway
					Tags:         a.mapToEc2Tags(natGatewayTags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create NAT Gateway")
		}
		natGateWayIds = append(natGateWayIds, *natGatewayOutput.NatGateway.NatGatewayId)
		cluster.AddCloudResource(&CloudResource{
			Name:  natGatewayName,
			RefId: aws.ToString(natGatewayOutput.NatGateway.NatGatewayId),
			Tags:  cluster.EncodeTags(natGatewayTags),
			Type:  ResourceType_NAT_GATEWAY,
		})
		a.log.Infof("nat gateway %s createing...", aws.ToString(natGatewayOutput.NatGateway.NatGatewayId))
	}

	if len(natGateWayIds) != 0 {
		a.log.Info("waiting for NAT Gateway availability")
		waiter := ec2.NewNatGatewayAvailableWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeNatGatewaysInput{
			NatGatewayIds: natGateWayIds,
		}, time.Duration(len(natGateWayIds))*TimeoutPerInstance)
		if err != nil {
			return fmt.Errorf("failed to wait for NAT Gateway availability: %w", err)
		}
	}
	return nil
}

// Check and Create route tables
func (a *AwsCloudUsecase) createRouteTables(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	existingRouteTables, err := a.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe route tables")
	}

	for _, routeTable := range existingRouteTables.RouteTables {
		if routeTable.Tags == nil {
			continue
		}
		if cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, aws.ToString(routeTable.RouteTableId)) != nil {
			a.log.Infof("route table %s already exists", aws.ToString(routeTable.RouteTableId))
			continue
		}
		name := ""
		tags := make(map[string]string)
		for _, tag := range routeTable.Tags {
			if aws.ToString(tag.Key) == AwsTagKeyName {
				name = aws.ToString(tag.Value)
			}
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		if val, ok := tags[AwsTagKeyType]; !ok || (val != AwsResourcePublic && val != AwsResourcePrivate) {
			continue
		}
		if tags[AwsTagKeyType] == AwsResourcePublic && name != fmt.Sprintf("%s-public-rt", cluster.Name) {
			continue
		}
		if tags[AwsTagKeyType] == AwsResourcePrivate {
			privateZoneName, ok := tags[AwsTagKeyZone]
			if !ok {
				continue
			}
			if name != fmt.Sprintf("%s-private-rt-%s", cluster.Name, privateZoneName) {
				continue
			}
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        aws.ToString(routeTable.RouteTableId),
			Tags:         cluster.EncodeTags(tags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("route table %s already exists", aws.ToString(routeTable.RouteTableId))
	}

	// Create public route table
	publicRouteTableName := fmt.Sprintf("%s-public-rt", cluster.Name)
	publicRouteTableNameTags := map[string]string{
		AwsTagKeyName: publicRouteTableName,
		AwsTagKeyType: AwsResourcePublic,
	}
	if cluster.GetCloudResourceByName(ResourceType_ROUTE_TABLE, publicRouteTableName) == nil {
		publicRouteTable, err := a.ec2Client.CreateRouteTable(ctx, &ec2.CreateRouteTableInput{
			VpcId: aws.String(vpc.RefId),
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeRouteTable,
					Tags:         a.mapToEc2Tags(publicRouteTableNameTags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create public route table")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         publicRouteTableName,
			RefId:        aws.ToString(publicRouteTable.RouteTable.RouteTableId),
			Tags:         cluster.EncodeTags(publicRouteTableNameTags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("public route table %s created", aws.ToString(publicRouteTable.RouteTable.RouteTableId))

		// Add route to Internet Gateway in public route table
		_, err = a.ec2Client.CreateRoute(ctx, &ec2.CreateRouteInput{
			RouteTableId:         publicRouteTable.RouteTable.RouteTableId,
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			GatewayId:            aws.String(cluster.GetSingleCloudResource(ResourceType_INTERNET_GATEWAY).RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add route to Internet Gateway")
		}

		// Associate public subnets with public route table
		for i, subnetReource := range cluster.GetCloudResource(ResourceType_SUBNET) {
			subnetReourceMapTags := cluster.DecodeTags(subnetReource.Tags)
			if typeVal, ok := subnetReourceMapTags[AwsTagKeyType]; !ok || typeVal != AwsResourcePublic {
				continue
			}
			publicAssociateRouteTable, err := a.ec2Client.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{
				RouteTableId: publicRouteTable.RouteTable.RouteTableId,
				SubnetId:     aws.String(subnetReource.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate public subnet with route table")
			}
			parent := cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, aws.ToString(publicRouteTable.RouteTable.RouteTableId))
			cluster.AddSubCloudResource(ResourceType_ROUTE_TABLE, parent.Id, &CloudResource{
				RefId:        aws.ToString(publicAssociateRouteTable.AssociationId),
				Name:         fmt.Sprintf("public associate routetable %d", i),
				Type:         ResourceType_ROUTE_TABLE,
				AssociatedId: aws.ToString(publicRouteTable.RouteTable.RouteTableId),
			})
		}
	}

	// Create private route tables (one per AZ)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		privateRouteTableName := fmt.Sprintf("%s-private-rt-%s", cluster.Name, az.Name)
		tags := map[string]string{
			AwsTagKeyName: privateRouteTableName,
			AwsTagKeyType: AwsResourcePrivate,
			AwsTagKeyZone: az.Name,
		}
		if cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, AwsTagKeyName, privateRouteTableName) != nil {
			continue
		}
		privateRouteTable, err := a.ec2Client.CreateRouteTable(ctx, &ec2.CreateRouteTableInput{
			VpcId: aws.String(cluster.GetSingleCloudResource(ResourceType_VPC).RefId),
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeRouteTable,
					Tags:         a.mapToEc2Tags(tags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create private route table for AZ "+az.Name)
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         privateRouteTableName,
			RefId:        aws.ToString(privateRouteTable.RouteTable.RouteTableId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_ROUTE_TABLE,
			AssociatedId: vpc.RefId,
		})
		a.log.Infof("private route table %s created for AZ %s", aws.ToString(privateRouteTable.RouteTable.RouteTableId), az.Name)

		// defalut local

		// Add route to NAT Gateway in private route table
		for _, natGateway := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
			natGatewayMapTags := cluster.DecodeTags(natGateway.Tags)
			if zoneName, ok := natGatewayMapTags[AwsTagKeyZone]; !ok || zoneName != az.Name {
				continue
			}
			_, err = a.ec2Client.CreateRoute(ctx, &ec2.CreateRouteInput{
				RouteTableId:         privateRouteTable.RouteTable.RouteTableId,
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				NatGatewayId:         aws.String(natGateway.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to add route to NAT Gateway for AZ "+az.Name)
			}
		}

		// Associate private subnets with private route table
		for _, subnet := range cluster.GetCloudResourceByTags(ResourceType_SUBNET, AwsTagKeyType, AwsResourcePrivate, AwsTagKeyZone, az.Name) {
			privateAssociateRouteTable, err := a.ec2Client.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{
				RouteTableId: privateRouteTable.RouteTable.RouteTableId,
				SubnetId:     aws.String(subnet.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate private subnet with route table in AZ "+az.Name)
			}
			parent := cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, aws.ToString(privateRouteTable.RouteTable.RouteTableId))
			cluster.AddSubCloudResource(ResourceType_ROUTE_TABLE, parent.Id, &CloudResource{
				RefId:        aws.ToString(privateAssociateRouteTable.AssociationId),
				Name:         fmt.Sprintf("%s-private-associate-routetable", subnet.Name),
				Type:         ResourceType_ROUTE_TABLE,
				AssociatedId: aws.ToString(privateRouteTable.RouteTable.RouteTableId),
			})
		}
	}
	return nil
}

// Check and Create security group
func (a *AwsCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	sgNames := []string{
		fmt.Sprintf("%s-%s-sg", cluster.Name, AwsResourceHttpSG),
		fmt.Sprintf("%s-%s-sg", cluster.Name, AwsReousrceBostionHostSG),
	}
	existingSecurityGroups, err := a.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			{Name: aws.String("group-name"), Values: sgNames},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe security groups")
	}

	if len(existingSecurityGroups.SecurityGroups) != 0 {
		for _, securityGroup := range existingSecurityGroups.SecurityGroups {
			if securityGroup.GroupId == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_SECURITY_GROUP, aws.ToString(securityGroup.GroupId)) != nil {
				a.log.Infof("security group %s already exists", aws.ToString(securityGroup.GroupId))
				continue
			}
			tags := make(map[string]string)
			for _, tag := range securityGroup.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			cluster.AddCloudResource(&CloudResource{
				Name:         aws.ToString(securityGroup.GroupName),
				RefId:        aws.ToString(securityGroup.GroupId),
				Tags:         cluster.EncodeTags(tags),
				AssociatedId: vpc.RefId,
				Type:         ResourceType_SECURITY_GROUP,
			})
			a.log.Infof("security group %s already exists", aws.ToString(securityGroup.GroupId))
		}
	}

	for _, sgName := range sgNames {
		if cluster.GetCloudResourceByName(ResourceType_SECURITY_GROUP, sgName) != nil {
			continue
		}
		tags := map[string]string{AwsTagKeyName: sgName}
		if strings.Contains(sgName, AwsResourceHttpSG) {
			tags[AwsTagKeyType] = AwsResourceHttpSG
		}
		if strings.Contains(sgName, AwsReousrceBostionHostSG) {
			tags[AwsTagKeyType] = AwsReousrceBostionHostSG
		}
		sgOutput, err := a.ec2Client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
			GroupName:   aws.String(sgName),
			VpcId:       aws.String(vpc.RefId),
			Description: aws.String(sgName),
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeSecurityGroup,
					Tags:         a.mapToEc2Tags(tags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create security group")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:         sgName,
			RefId:        aws.ToString(sgOutput.GroupId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SECURITY_GROUP,
			AssociatedId: vpc.RefId,
		})
		a.log.Infof("security group %s created", aws.ToString(sgOutput.GroupId))

		// IpProtocol: aws.String(string(ec2Types.ProtocolTcp)),
		// FromPort:   aws.Int32(22),
		// ToPort:     aws.Int32(22),
		// IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		ipPermissionsArr := make([]ec2Types.IpPermission, 0)
		for _, sg := range cluster.SecurityGroups {
			ipPermissionsArr = append(ipPermissionsArr, ec2Types.IpPermission{
				IpProtocol: aws.String(sg.Protocol),
				FromPort:   aws.Int32(sg.IngressPort),
				ToPort:     aws.Int32(sg.EgressPort),
				IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String(sg.IpCidr)}},
			})
		}
		if v, ok := tags[AwsTagKeyType]; ok && v == AwsReousrceBostionHostSG {
			_, err = a.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       sgOutput.GroupId,
				IpPermissions: ipPermissionsArr,
				TagSpecifications: []ec2Types.TagSpecification{
					{
						ResourceType: ec2Types.ResourceTypeSecurityGroupRule,
						Tags:         a.mapToEc2Tags(tags),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "failed to add inbound rules to security group")
			}
		}
		if v, ok := tags[AwsTagKeyType]; ok && v == AwsResourceHttpSG {
			_, err = a.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
				GroupId: sgOutput.GroupId,
				IpPermissions: []ec2Types.IpPermission{
					{
						IpProtocol: aws.String(string(ec2Types.ProtocolTcp)),
						FromPort:   aws.Int32(80),
						ToPort:     aws.Int32(80),
						IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
					{
						IpProtocol: aws.String(string(ec2Types.ProtocolTcp)),
						FromPort:   aws.Int32(443),
						ToPort:     aws.Int32(443),
						IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
				},
				TagSpecifications: []ec2Types.TagSpecification{
					{
						ResourceType: ec2Types.ResourceTypeSecurityGroupRule,
						Tags:         a.mapToEc2Tags(tags),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "failed to add inbound rules to security group")
			}
		}
	}
	return nil
}

func (a *AwsCloudUsecase) createS3Endpoint(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	privateRouterTable := cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, AwsTagKeyType, AwsResourcePrivate)
	if privateRouterTable == nil {
		return errors.New("public route table not found")
	}
	routerTableids := make([]string, 0)
	for _, v := range privateRouterTable {
		routerTableids = append(routerTableids, v.RefId)
	}

	if cluster.GetCloudResourceByTags(ResourceType_VPC_ENDPOINT_S3, AwsTagKeyVpc, vpc.RefId) != nil {
		a.log.Infof("s3 endpoint already exists")
		return nil
	}

	// s3 gateway
	name := fmt.Sprintf("%s-s3-endpoint", cluster.Name)
	tags := map[string]string{
		AwsTagKeyName: name,
		AwsTagKeyVpc:  vpc.RefId,
	}
	serviceNmae := fmt.Sprintf("com.amazonaws.%s.s3", cluster.Region)
	endpointoutpus, err := a.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			{Name: aws.String("service-name"), Values: []string{serviceNmae}},
			{Name: aws.String("tag:Name"), Values: []string{name}},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe s3 endpoint")
	}
	for _, endpoint := range endpointoutpus.VpcEndpoints {
		if endpoint.VpcEndpointId == nil {
			continue
		}
		cluster.AddCloudResource(&CloudResource{
			RefId: aws.ToString(endpoint.VpcEndpointId),
			Name:  name,
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_VPC_ENDPOINT_S3,
		})
		a.log.Infof("s3 endpoint %s already exists", aws.ToString(endpoint.VpcEndpointId))
		return nil
	}
	s3enpointoutput, err := a.ec2Client.CreateVpcEndpoint(ctx, &ec2.CreateVpcEndpointInput{
		VpcId:           aws.String(vpc.RefId),
		ServiceName:     aws.String(serviceNmae), // com.amazonaws.us-east-1.s3
		VpcEndpointType: ec2Types.VpcEndpointTypeGateway,
		RouteTableIds:   routerTableids,
		PolicyDocument:  aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeVpcEndpoint,
				Tags:         a.mapToEc2Tags(tags),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create s3 endpoint")
	}
	cluster.AddCloudResource(&CloudResource{
		Id:   aws.ToString(s3enpointoutput.VpcEndpoint.VpcEndpointId),
		Name: name,
		Tags: cluster.EncodeTags(tags),
		Type: ResourceType_VPC_ENDPOINT_S3,
	})
	a.log.Infof("s3 endpoint %s created", aws.ToString(s3enpointoutput.VpcEndpoint.VpcEndpointId))
	return nil
}

// create slb
func (a *AwsCloudUsecase) createSLB(ctx context.Context, cluster *Cluster) error {
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
	publicSubnetIDs := make([]string, 0)
	for _, subnet := range cluster.GetCloudResource(ResourceType_SUBNET) {
		subnetMapTags := cluster.DecodeTags(subnet.Tags)
		if typeVal, ok := subnetMapTags[AwsTagKeyType]; !ok || typeVal != AwsResourcePublic {
			continue
		}
		publicSubnetIDs = append(publicSubnetIDs, subnet.RefId)
	}
	if len(publicSubnetIDs) == 0 {
		return errors.New("failed to get public subnets")
	}
	sgs := cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, AwsTagKeyType, AwsResourceHttpSG)
	if sgs == nil {
		return errors.New("failed to get security group")
	}
	sgIDs := make([]string, 0)
	for _, v := range sgs {
		sgIDs = append(sgIDs, v.RefId)
	}

	loadBalancers, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
		Names: []string{name},
	})
	if err != nil && !strings.Contains(err.Error(), AwsNotFound) {
		return errors.Wrap(err, "failed to describe load balancers")
	}
	if loadBalancers != nil && loadBalancers.LoadBalancers != nil && len(loadBalancers.LoadBalancers) != 0 {
		for _, loadBalancer := range loadBalancers.LoadBalancers {
			if loadBalancer.LoadBalancerArn == nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_LOAD_BALANCER, aws.ToString(loadBalancer.LoadBalancerArn)) != nil {
				continue
			}
			cluster.AddCloudResource(&CloudResource{
				Name:  aws.ToString(loadBalancer.LoadBalancerName),
				RefId: aws.ToString(loadBalancer.LoadBalancerArn),
				Type:  ResourceType_LOAD_BALANCER,
			})
			a.log.Infof("slb %s already exists", aws.ToString(loadBalancer.LoadBalancerName))
		}
		return nil
	}

	// Create SLB
	tags := map[string]string{AwsTagKeyName: name}
	slbOutput, err := a.elbv2Client.CreateLoadBalancer(ctx, &elasticloadbalancingv2.CreateLoadBalancerInput{
		Name:           aws.String(name),
		Subnets:        publicSubnetIDs,
		SecurityGroups: sgIDs,
		Scheme:         elasticloadbalancingv2Types.LoadBalancerSchemeEnumInternetFacing,
		Type:           elasticloadbalancingv2Types.LoadBalancerTypeEnumApplication,
		Tags:           a.mapToElbv2Tags(tags),
	})
	if err != nil || len(slbOutput.LoadBalancers) == 0 {
		return errors.Wrap(err, "failed to create SLB")
	}
	slb := slbOutput.LoadBalancers[0]
	cluster.AddCloudResource(&CloudResource{
		Name:  name,
		RefId: aws.ToString(slb.LoadBalancerArn),
		Tags:  cluster.EncodeTags(tags),
		Type:  ResourceType_LOAD_BALANCER,
	})

	// Create target group
	taggetGroup, err := a.elbv2Client.CreateTargetGroup(ctx, &elasticloadbalancingv2.CreateTargetGroupInput{
		Name:       aws.String(fmt.Sprintf("%s-targetgroup", cluster.Name)),
		TargetType: elasticloadbalancingv2Types.TargetTypeEnumAlb,
		Port:       aws.Int32(6443),
		Protocol:   elasticloadbalancingv2Types.ProtocolEnumHttp,
		VpcId:      aws.String(vpc.RefId),
		Tags:       a.mapToElbv2Tags(tags),
	})
	if err != nil || len(taggetGroup.TargetGroups) == 0 {
		return errors.Wrap(err, "failed to create target group")
	}
	targetGroup := taggetGroup.TargetGroups[0]
	a.log.Infof("target group %s created", aws.ToString(targetGroup.TargetGroupArn))

	// create listener
	_, err = a.elbv2Client.CreateListener(ctx, &elasticloadbalancingv2.CreateListenerInput{
		DefaultActions: []elasticloadbalancingv2Types.Action{
			{
				Type: elasticloadbalancingv2Types.ActionTypeEnumForward,
				ForwardConfig: &elasticloadbalancingv2Types.ForwardActionConfig{
					TargetGroups: []elasticloadbalancingv2Types.TargetGroupTuple{
						{
							TargetGroupArn: targetGroup.TargetGroupArn,
							Weight:         aws.Int32(100),
						},
					},
				},
			},
		},
		LoadBalancerArn: slb.LoadBalancerArn,
		Port:            aws.Int32(6443),
		Protocol:        elasticloadbalancingv2Types.ProtocolEnumHttp,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create listener")
	}
	return nil
}

// find image
func (a *AwsCloudUsecase) findImage(ctx context.Context) (ec2Types.Image, error) {
	image := ec2Types.Image{}
	images, err := a.ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"amazon"},
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"},
			},
			{
				Name:   aws.String("architecture"),
				Values: []string{"x86_64"},
			},
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil || len(images.Images) == 0 {
		return image, errors.Wrap(err, "failed to describe images")
	}
	for _, image := range images.Images {
		return image, nil
	}
	return image, nil
}

type InstanceTypeResults []ec2Types.InstanceTypeInfo

// sort by vcpu and memory
func (a InstanceTypeResults) Len() int {
	return len(a)
}

func (a InstanceTypeResults) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a InstanceTypeResults) Less(i, j int) bool {
	if aws.ToInt32(a[i].VCpuInfo.DefaultVCpus) < aws.ToInt32(a[j].VCpuInfo.DefaultVCpus) {
		return true
	}
	if aws.ToInt32(a[i].VCpuInfo.DefaultVCpus) == aws.ToInt32(a[j].VCpuInfo.DefaultVCpus) {
		return aws.ToInt64(a[i].MemoryInfo.SizeInMiB) < aws.ToInt64(a[j].MemoryInfo.SizeInMiB)
	}
	return false
}

func (a *AwsCloudUsecase) findInstanceType(ctx context.Context, instanceTypeFamiliy string, CPU, GPU, Memory int32) (ec2Types.InstanceTypeInfo, error) {
	instanceTypeInfo := ec2Types.InstanceTypeInfo{}
	instanceData := make(InstanceTypeResults, 0)
	instanceTypeInput := &ec2.DescribeInstanceTypesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("current-generation"),
				Values: []string{"true"},
			},
			{
				Name:   aws.String("processor-info.supported-architecture"),
				Values: []string{"x86_64"},
			},
			{
				Name:   aws.String("instance-type"),
				Values: []string{instanceTypeFamiliy},
			},
		},
	}
	for {
		instanceTypes, err := a.ec2Client.DescribeInstanceTypes(ctx, instanceTypeInput)
		if err != nil {
			return instanceTypeInfo, errors.Wrap(err, "failed to describe instance types")
		}
		for _, instanceType := range instanceTypes.InstanceTypes {
			instanceData = append(instanceData, instanceType)
		}
		if instanceTypes.NextToken == nil {
			break
		}
		instanceTypeInput.NextToken = instanceTypes.NextToken
	}
	sort.Sort(instanceData)
	for _, instanceType := range instanceData {
		if aws.ToInt64(instanceType.MemoryInfo.SizeInMiB) == 0 {
			continue
		}
		memoryGBiSize := aws.ToInt64(instanceType.MemoryInfo.SizeInMiB) / 1024
		if int32(memoryGBiSize) >= Memory && aws.ToInt32(instanceType.VCpuInfo.DefaultVCpus) >= CPU {
			instanceTypeInfo = instanceType
		}
		if instanceTypeInfo.InstanceType == "" {
			continue
		}
		if GPU == 0 {
			break
		}
		for _, gpues := range instanceType.GpuInfo.Gpus {
			if aws.ToInt32(gpues.Count) >= GPU {
				break
			}
		}
	}
	if instanceTypeInfo.InstanceType == "" {
		return instanceTypeInfo, errors.New("no instance type found")
	}
	return instanceTypeInfo, nil
}

func (a *AwsCloudUsecase) getInstances(ctx context.Context, cluster *Cluster, instanceIDs, tagNames []string) ([]ec2Types.Instance, error) {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return nil, errors.New("failed to get vpc")
	}
	filters := []ec2Types.Filter{
		{
			Name:   aws.String("vpc-id"),
			Values: []string{vpc.RefId},
		},
		{
			Name:   aws.String("instance-state-name"),
			Values: []string{string(ec2Types.InstanceStateNameRunning)},
		},
	}
	if len(tagNames) > 0 {
		filters = append(filters, ec2Types.Filter{
			Name:   aws.String("tag:Name"),
			Values: tagNames,
		})
	}
	input := &ec2.DescribeInstancesInput{
		Filters: filters,
	}
	if len(instanceIDs) > 0 {
		input.InstanceIds = instanceIDs
	}
	var instances []ec2Types.Instance
	for {
		output, err := a.ec2Client.DescribeInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range output.Reservations {
			instances = append(instances, reservation.Instances...)
		}

		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	return instances, nil
}

func (a *AwsCloudUsecase) distributeNodeSubnets(cluster *Cluster, nodeIndex int) (subNetID string) {
	subnets := cluster.GetCloudResource(ResourceType_SUBNET)
	if len(subnets) == 0 {
		return ""
	}
	nodeSize := len(cluster.Nodes)
	subnetsSize := len(subnets)
	if nodeSize <= subnetsSize {
		return subnets[nodeIndex%subnetsSize].RefId
	}
	interval := nodeSize / subnetsSize
	return subnets[(nodeIndex/interval)%subnetsSize].RefId
}

// create Tags
func (a *AwsCloudUsecase) createTags(ctx context.Context, resourceID string, resourceType ResourceType, tags map[string]string) error {
	_, err := a.ec2Client.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{resourceID},
		Tags:      a.mapToEc2Tags(tags),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create tags for %s", resourceType)
	}
	return nil
}

// map to ec2 tags
func (a *AwsCloudUsecase) mapToEc2Tags(tags map[string]string) []ec2Types.Tag {
	ec2Tags := []ec2Types.Tag{}
	for key, value := range tags {
		ec2Tags = append(ec2Tags, ec2Types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return ec2Tags
}

// map to elbv2 tags
func (a *AwsCloudUsecase) mapToElbv2Tags(tags map[string]string) []elasticloadbalancingv2Types.Tag {
	elbv2Tags := []elasticloadbalancingv2Types.Tag{}
	for key, value := range tags {
		elbv2Tags = append(elbv2Tags, elasticloadbalancingv2Types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return elbv2Tags
}

func (a *AwsCloudUsecase) getIntanceTypeFamilies(nodeGroup *NodeGroup) string {
	if nodeGroup == nil || nodeGroup.Type == 0 {
		return "m5.*"
	}
	switch nodeGroup.Type {
	case NodeGroupType_NORMAL:
		return "m5.*"
	case NodeGroupType_HIGH_COMPUTATION:
		return "c5.*"
	case NodeGroupType_GPU_ACCELERATERD:
		return "p3.*"
	case NodeGroupType_HIGH_MEMORY:
		return "r5.*"
	case NodeGroupType_LARGE_HARD_DISK:
		return "i3.*"
	default:
		return "m5.*"
	}
}

func (a *AwsCloudUsecase) determineUsername(amiName, amiDescription string) string {
	amiName = strings.ToLower(amiName)
	amiDescription = strings.ToLower(amiDescription)

	if strings.Contains(amiName, "amazon linux") || strings.Contains(amiDescription, "amazon linux") {
		return "ec2-user"
	} else if strings.Contains(amiName, "ubuntu") || strings.Contains(amiDescription, "ubuntu") {
		return "ubuntu"
	} else if strings.Contains(amiName, "centos") || strings.Contains(amiDescription, "centos") {
		return "centos"
	} else if strings.Contains(amiName, "debian") || strings.Contains(amiDescription, "debian") {
		return "admin"
	} else if strings.Contains(amiName, "rhel") || strings.Contains(amiDescription, "red hat") {
		return "ec2-user"
	} else if strings.Contains(amiName, "suse") || strings.Contains(amiDescription, "suse") {
		return "ec2-user"
	} else if strings.Contains(amiName, "fedora") || strings.Contains(amiDescription, "fedora") {
		return "fedora"
	} else if strings.Contains(amiName, "bitnami") || strings.Contains(amiDescription, "bitnami") {
		return "bitnami"
	}

	// Default to ec2-user if we can't determine the username
	return "ec2-user"
}
