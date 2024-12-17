package biz

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elasticloadbalancingv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

const (
	awsDefaultRegion = "us-east-1"

	TimeoutPerInstance = 5 * time.Minute
	AwsNotFound        = "NotFound"

	AWS_REGION            = "AWS_REGION"
	AWS_ACCESS_KEY_ID     = "AWS_ACCESS_KEY_ID"
	AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
	AWS_DEFAULT_REGION    = "AWS_DEFAULT_REGION"
)

type AwsCloudUsecase struct {
	ec2Client           *ec2.Client
	elbv2Client         *elasticloadbalancingv2.Client
	eksClient           *eks.Client
	servicequotasClient *servicequotas.Client
	iamClient           *iam.Client
	log                 *log.Helper
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
	os.Setenv(AWS_REGION, cluster.Region)
	os.Setenv(AWS_DEFAULT_REGION, cluster.Region)
	os.Setenv(AWS_ACCESS_KEY_ID, cluster.AccessId)
	os.Setenv(AWS_SECRET_ACCESS_KEY, cluster.AccessKey)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cluster.Region))
	if err != nil {
		return err
	}
	a.ec2Client = ec2.NewFromConfig(cfg)
	a.elbv2Client = elasticloadbalancingv2.NewFromConfig(cfg)
	a.eksClient = eks.NewFromConfig(cfg)
	a.servicequotasClient = servicequotas.NewFromConfig(cfg)
	a.iamClient = iam.NewFromConfig(cfg)
	return nil
}

func (a *AwsCloudUsecase) GetAvailabilityRegions(ctx context.Context, cluster *Cluster) error {
	res, err := a.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return errors.Wrap(err, "failed to describe regions")
	}
	for _, v := range res.Regions {
		cluster.AddCloudResource(&CloudResource{
			Type:  ResourceType_REGION,
			RefId: aws.ToString(v.RegionName),
			Name:  aws.ToString(v.RegionName),
			Value: tea.ToString(v.Endpoint),
		})
	}
	return nil
}

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

func (a *AwsCloudUsecase) OpenSSh(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AwsCloudUsecase) CloseSSh(ctx context.Context, cluster *Cluster) error {
	return nil
}

// create network(vpc, subnet, eip,nat gateway, route table, security group)
func (a *AwsCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	funcs := []func(context.Context, *Cluster) error{
		a.createVPC,           // Step 1: Check and Create VPC
		a.createSubnets,       // Step 2: Check and Create subnets
		a.createEips,          // Step 3: Check and Create EIPs
		a.createNatGateways,   // Step 4: Check and Create NAT Gateways
		a.createRouteTables,   // Step 5: Check and Create route tables
		a.createSecurityGroup, // Step 6: Check and Create security group
		a.createSLB,
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
	if vpc == nil {
		return errors.New("vpc not found")
	}
	// Delete vpc s3 endpoints
	for _, endpoint := range cluster.GetCloudResource(ResourceType_VPC_ENDPOINT_S3) {
		_, err := a.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			VpcEndpointIds: []string{endpoint.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Infof("No vpc endpoint found with name: %s", endpoint.Name)
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
			a.log.Infof("No security group found with name: %s", sg.Name)
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
			a.log.Infof("No route table found with name: %s", rt.Name)
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
			a.log.Infof("No NAT Gateway found with Name: %s", natGw.Name)
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
			a.log.Infof("No Elastic IP found with name: %s", addr.Name)
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
			a.log.Infof("No Internet Gateway found with name: %s", igw.Name)
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
			a.log.Infof("No subnet found with Name: %s", subnet.Name)
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
	vpcRes, err := a.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		VpcIds: []string{vpc.RefId},
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe VPC")
	}
	for _, vpc := range vpcRes.Vpcs {
		if aws.ToBool(vpc.IsDefault) {
			continue
		}
		_, err = a.ec2Client.DeleteVpc(ctx, &ec2.DeleteVpcInput{
			VpcId: vpc.VpcId,
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete VPC")
		}
	}
	cluster.DeleteCloudResource(ResourceType_VPC)

	// step 7: Delete SLB
	for _, slb := range cluster.GetCloudResource(ResourceType_LOAD_BALANCER) {
		_, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			LoadBalancerArns: []string{slb.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Warnf("No SLB found with name: %s", slb.Name)
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
// func (a *AwsCloudUsecase) SetByNodeGroups(ctx context.Context, cluster *Cluster) error {
// 	image, err := a.findImage(ctx)
// 	if err != nil {
// 		return err
// 	}
// 	for _, ng := range cluster.NodeGroups {
// 		// image
// 		platformDetails := strings.Split(aws.ToString(image.PlatformDetails), "/")
// 		if len(platformDetails) > 0 {
// 			ng.Os = strings.ToLower(platformDetails[0])
// 		}
// 		ng.Image = aws.ToString(image.ImageId)
// 		ng.ImageDescription = aws.ToString(image.Description)
// 		ng.DefaultUsername = a.determineUsername(aws.ToString(image.Name), aws.ToString(image.Description))
// 		ng.RootDeviceName = aws.ToString(image.RootDeviceName)
// 		for _, dataDeivce := range image.BlockDeviceMappings {
// 			if dataDeivce.DeviceName != nil && aws.ToString(dataDeivce.DeviceName) != ng.RootDeviceName {
// 				ng.DataDeviceName = aws.ToString(dataDeivce.DeviceName)
// 				break
// 			}
// 		}
// 		a.log.Info(strings.Join([]string{"image found: ", aws.ToString(image.Name), aws.ToString(image.Description)}, " "))

// 		// instance type
// 		if ng.InstanceType != "" {
// 			continue
// 		}
// 		instanceTypeFamiliy := a.getIntanceTypeFamilies(ng)
// 		instanceInfo, err := a.findInstanceType(ctx, instanceTypeFamiliy, ng.Cpu, ng.Gpu, ng.Memory)
// 		if err != nil {
// 			return err
// 		}
// 		ng.InstanceType = string(instanceInfo.InstanceType)
// 		if instanceInfo.VCpuInfo != nil && instanceInfo.VCpuInfo.DefaultVCpus != nil {
// 			ng.Cpu = aws.ToInt32(instanceInfo.VCpuInfo.DefaultVCpus)
// 		}
// 		if instanceInfo.MemoryInfo != nil && instanceInfo.MemoryInfo.SizeInMiB != nil {
// 			ng.Memory = int32(aws.ToInt64(instanceInfo.MemoryInfo.SizeInMiB) / 1024)
// 		}
// 		if ng.Gpu != 0 && instanceInfo.GpuInfo != nil && len(instanceInfo.GpuInfo.Gpus) > 0 {
// 			for _, g := range instanceInfo.GpuInfo.Gpus {
// 				ng.Gpu += aws.ToInt32(g.Count)
// 			}
// 		}
// 		a.log.Info("instance type found: ", ng.InstanceType)
// 	}
// 	return nil
// }

// KeyPair
func (a *AwsCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	keyName := cluster.Name + "-keypair"
	tags := map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: keyName}
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
			a.log.Infof("%s key pair found", keyPair.KeyName)
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
		return errors.Wrap(err, "failed to import key pair")
	}
	keyPairCloudResource := &CloudResource{
		Name: keyName,
		Tags: cluster.EncodeTags(tags),
		Type: ResourceType_KEY_PAIR,
	}
	keyPairCloudResource.RefId = aws.ToString(keyPairOutput.KeyPairId)
	cluster.AddCloudResource(keyPairCloudResource)
	a.log.Info("% key pair imported", keyName)
	return nil
}

func (a *AwsCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	for _, keyPair := range cluster.GetCloudResource(ResourceType_KEY_PAIR) {
		_, err := a.ec2Client.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{
			KeyNames: []string{keyPair.Name},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			a.log.Warnf("No key pair found with Key Name: %s", keyPair.Name)
			continue
		}
		_, err = a.ec2Client.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{
			KeyName: aws.String(keyPair.Name),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete key pair")
		}
		a.log.Info("key pair deleted")
	}
	cluster.DeleteCloudResource(ResourceType_KEY_PAIR)
	return nil
}

// get instance quota number
func (a *AwsCloudUsecase) GetInstanceQuota(ctx context.Context, cluster *Cluster) error {
	servicequotas, err := a.servicequotasClient.ListServiceQuotas(ctx, &servicequotas.ListServiceQuotasInput{
		ServiceCode: aws.String("ec2"),
	})
	if err != nil {
		return errors.Wrap(err, "failed to list service quotas")
	}
	for _, quota := range servicequotas.Quotas {
		fmt.Println("Quota service code:", aws.ToString(quota.ServiceCode))
		fmt.Println("Quota service name:", aws.ToString(quota.ServiceName))
		fmt.Printf("Quota Name: %s\n", aws.ToString(quota.QuotaName))
		fmt.Printf("Quota Value: %.2f\n", aws.ToFloat64(quota.Value))
		fmt.Printf("Quota Type: %s\n", aws.ToString(quota.Unit))
		fmt.Println("-----")
	}
	return nil
}

func (a *AwsCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	vpcCloudResource := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpcCloudResource == nil {
		return errors.New("vpc not found")
	}
	instances, err := a.getInstances(ctx, vpcCloudResource)
	if err != nil {
		return err
	}
	// clear history node
	for _, node := range cluster.Nodes {
		nodeExits := false
		for _, instance := range instances {
			if node.InstanceId == aws.ToString(instance.InstanceId) {
				nodeExits = true
				break
			}
		}
		if !nodeExits && (node.Status == NodeStatus_NODE_RUNNING || node.Status == NodeStatus_NODE_PENDING) {
			node.InstanceId = ""
		}
	}
	// handler needdelete instances
	needDeleteInstanceIDs := make([]string, 0)
	for _, node := range cluster.Nodes {
		if node.Status == NodeStatus_NODE_DELETING && node.InstanceId != "" {
			needDeleteInstanceIDs = append(needDeleteInstanceIDs, node.InstanceId)
		}
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
		err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: deleteInstanceIDs}, time.Duration(len(deleteInstanceIDs))*TimeoutPerInstance)
		if err != nil {
			return fmt.Errorf("failed to wait for instance termination: %w", err)
		}
		for _, node := range cluster.Nodes {
			if utils.InArray(node.InstanceId, deleteInstanceIDs) {
				node.InstanceId = ""
			}
		}
	}

	sg := cluster.GetSingleCloudResource(ResourceType_SECURITY_GROUP)
	if sg == nil {
		return errors.New("security group not found")
	}

	// Create instances
	instanceIds := make([]string, 0)
	for _, nodeGroup := range cluster.NodeGroups {
		image, err := a.findImage(ctx, nodeGroup.Arch)
		if err != nil {
			return err
		}
		// root Volume
		blockDeviceMappings := []ec2Types.BlockDeviceMapping{
			{
				DeviceName: image.RootDeviceName,
				Ebs: &ec2Types.EbsBlockDevice{
					VolumeSize:          aws.Int32(nodeGroup.SystemDiskSize),
					VolumeType:          ec2Types.VolumeType(ec2Types.VolumeTypeGp3),
					DeleteOnTermination: aws.Bool(true),
				},
			},
		}
		// data Volume
		if nodeGroup.DataDiskSize > 0 {
			dataDeviceName := ""
			for _, dataDeivce := range image.BlockDeviceMappings {
				if dataDeivce.DeviceName != nil && aws.ToString(dataDeivce.DeviceName) != aws.ToString(image.RootDeviceName) {
					dataDeviceName = aws.ToString(dataDeivce.DeviceName)
					break
				}
			}
			blockDeviceMappings = append(blockDeviceMappings, ec2Types.BlockDeviceMapping{
				DeviceName: aws.String(dataDeviceName),
				Ebs: &ec2Types.EbsBlockDevice{
					VolumeSize:          aws.Int32(nodeGroup.DataDiskSize),
					VolumeType:          ec2Types.VolumeType(ec2Types.VolumeTypeGp3),
					DeleteOnTermination: aws.Bool(true),
				},
			})
		}
		instancesInput := &ec2.RunInstancesInput{
			ImageId: aws.String(*image.ImageId),
			// InstanceType:        ec2Types.InstanceType(nodeGroup.InstanceType),
			KeyName:             aws.String(cluster.GetSingleCloudResource(ResourceType_KEY_PAIR).Name),
			MaxCount:            aws.Int32(1),
			MinCount:            aws.Int32(1),
			SecurityGroupIds:    []string{sg.RefId},
			BlockDeviceMappings: blockDeviceMappings,
		}
		for index, node := range cluster.Nodes {
			if node.Status != NodeStatus_NODE_CREATING || node.NodeGroupId != nodeGroup.Id {
				continue
			}
			instancesInput.InstanceType = ""
			privateSubnet := cluster.DistributeNodePrivateSubnets(index)
			instancesInput.SubnetId = aws.String(privateSubnet.RefId)
			instancesInput.TagSpecifications = []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeInstance,
					Tags:         a.mapToEc2Tags(cluster.DecodeTags(node.Labels)),
				},
			}
			instancesOutput, err := a.ec2Client.RunInstances(ctx, instancesInput)
			if err != nil {
				return errors.Wrap(err, "failed to run instances")
			}
			for _, instance := range instancesOutput.Instances {
				instanceIds = append(instanceIds, aws.ToString(instance.InstanceId))
				node.InstanceId = aws.ToString(instance.InstanceId)
				node.Ip = aws.ToString(instance.PrivateIpAddress)
				for _, blockDevice := range instance.BlockDeviceMappings {
					cluster.AddCloudResource(&CloudResource{
						Name:         aws.ToString(blockDevice.DeviceName),
						RefId:        aws.ToString(blockDevice.Ebs.VolumeId),
						AssociatedId: aws.ToString(instance.InstanceId),
						Value:        aws.ToString(blockDevice.Ebs.AssociatedResource),
						Type:         ResourceType_DATA_DEVICE,
					})
				}
			}
		}
	}
	// wait for instance running
	if len(instanceIds) > 0 {
		waiter := ec2.NewInstanceRunningWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: instanceIds}, time.Duration(len(instanceIds))*TimeoutPerInstance)
		if err != nil {
			return errors.Wrap(err, "failed to wait for instance running")
		}
	}
	return nil
}

// create vpc
func (a *AwsCloudUsecase) createVPC(ctx context.Context, cluster *Cluster) error {
	vpcName := cluster.Name + "-vpc"
	nextToken := ""
	vpcs := make([]ec2Types.Vpc, 0)
	for {
		describeVpcsInput := &ec2.DescribeVpcsInput{NextToken: aws.String(nextToken)}
		if nextToken == "" {
			describeVpcsInput = &ec2.DescribeVpcsInput{}
		}
		vpcsResponse, err := a.ec2Client.DescribeVpcs(ctx, describeVpcsInput)
		if err != nil {
			return errors.Wrap(err, "failed to describe VPCs")
		}
		vpcs = append(vpcs, vpcsResponse.Vpcs...)
		nextToken = aws.ToString(vpcsResponse.NextToken)
		if nextToken == "" {
			break
		}
	}
	for _, vpc := range vpcs {
		vpc := cluster.GetCloudResourceByRefID(ResourceType_VPC, aws.ToString(vpc.VpcId))
		if vpc != nil {
			return nil
		}
	}
	if len(cluster.GetCloudResource(ResourceType_VPC)) > 0 {
		cluster.DeleteCloudResource(ResourceType_VPC)
	}
	vpcTags := map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: vpcName}
	for _, vpc := range vpcs {
		if len(cluster.GetCloudResource(ResourceType_VPC)) != 0 {
			return nil
		}
		if aws.ToString(vpc.CidrBlock) != VpcCIDR {
			continue
		}
		a.createTags(ctx, aws.ToString(vpc.VpcId), ResourceType_VPC, vpcTags)
		cluster.AddCloudResource(&CloudResource{
			RefId: aws.ToString(vpc.VpcId),
			Name:  vpcName,
			Tags:  cluster.EncodeTags(vpcTags),
			Type:  ResourceType_VPC,
		})
		a.log.Infof("vpc %s already exists", vpcName)
	}
	if len(cluster.GetCloudResource(ResourceType_VPC)) != 0 {
		return nil
	}
	// Create VPC if it doesn't exist
	vpcResource := &CloudResource{Name: vpcName, Tags: cluster.EncodeTags(vpcTags), Type: ResourceType_VPC}
	vpcOutput, err := a.ec2Client.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String(VpcCIDR),
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
	vpcResource.RefId = aws.ToString(vpcOutput.Vpc.VpcId)
	_, err = a.ec2Client.ModifyVpcAttribute(ctx, &ec2.ModifyVpcAttributeInput{
		VpcId: vpcOutput.Vpc.VpcId,
		EnableDnsSupport: &ec2Types.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to enable DNS support for VPC, but vpc is created")
	}
	cluster.AddCloudResource(vpcResource)
	a.log.Infof("vpc %s created", vpcName)
	return nil
}

// Check and Create subnets
func (a *AwsCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	subnets := make([]ec2Types.Subnet, 0)
	nextToken := ""
	for {
		describeSubnetsInput := &ec2.DescribeSubnetsInput{
			Filters: []ec2Types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
				{Name: aws.String("state"), Values: []string{"available"}},
			},
		}
		if nextToken != "" {
			describeSubnetsInput.NextToken = aws.String(nextToken)
		}
		subnetRes, err := a.ec2Client.DescribeSubnets(ctx, describeSubnetsInput)
		if err != nil {
			return errors.Wrap(err, "failed to describe subnets")
		}
		subnets = append(subnets, subnetRes.Subnets...)
		nextToken = aws.ToString(subnetRes.NextToken)
		if nextToken == "" {
			break
		}
	}
	for _, subnetCloudResource := range cluster.GetCloudResource(ResourceType_SUBNET) {
		subnetCloudResourceExits := false
		for _, subnet := range subnets {
			if aws.ToString(subnet.SubnetId) == subnetCloudResource.RefId {
				subnetCloudResourceExits = true
				break
			}
		}
		if !subnetCloudResourceExits {
			cluster.DeleteCloudResourceByID(ResourceType_SUBNET, subnetCloudResource.RefId)
		}
	}

	zoneSubnets := make(map[string][]ec2Types.Subnet)
	for _, subnet := range subnets {
		if subnet.AvailabilityZone == nil {
			continue
		}
		_, ok := zoneSubnets[aws.ToString(subnet.AvailabilityZone)]
		if ok && len(zoneSubnets[aws.ToString(subnet.AvailabilityZone)]) >= 3 { // 1 public subnet, 2 private subnet
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
			tags := GetTags()
			var name string
			if i < 2 {
				name = fmt.Sprintf("%s-private-subnet-%s-%d", cluster.Name, aws.ToString(subnet.AvailabilityZone), i+1)
				tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
			} else {
				name = fmt.Sprintf("%s-public-subnet-%s", cluster.Name, aws.ToString(subnet.AvailabilityZone))
				tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
			}
			tags[ResourceTypeKeyValue_NAME] = name
			tags[ResourceTypeKeyValue_ZONE_ID] = zoneName
			a.createTags(ctx, aws.ToString(subnet.SubnetId), ResourceType_SUBNET, tags)
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
	subnetCidrRes, err := utils.GenerateSubnets(VpcCIDR, privateSubnetCount+publicSubnetCount+len(subnets))
	if err != nil {
		return errors.Wrap(err, "failed to generate subnet CIDRs")
	}
	subnetCidrs := make([]string, 0)
	existingSubnetCird := make(map[string]bool)
	for _, subnet := range subnets {
		existingSubnetCird[aws.ToString(subnet.CidrBlock)] = true
	}
	for _, subnetCidr := range subnetCidrRes {
		subnetCidrDecode := utils.DecodeCidr(subnetCidr)
		if subnetCidrDecode == "" {
			continue
		}
		ok := true
		for _, subnet := range subnets {
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
			tags := GetTags()
			tags[ResourceTypeKeyValue_NAME] = name
			tags[ResourceTypeKeyValue_ZONE_ID] = az.Name
			tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
			searchTags := GetTags()
			searchTags[ResourceTypeKeyValue_NAME] = name
			if cluster.GetCloudResourceByTags(ResourceType_SUBNET, searchTags) != nil {
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
			privateSubnetCloudResource := &CloudResource{
				Name:         name,
				AssociatedId: vpc.RefId,
				Tags:         cluster.EncodeTags(tags),
				Type:         ResourceType_SUBNET,
			}
			privateSubnetCloudResource.RefId = aws.ToString(subnetOutput.Subnet.SubnetId)
			cluster.AddCloudResource(privateSubnetCloudResource)
			a.log.Infof("private subnet %s created", name)
		}

		// Create public subnet
		name := fmt.Sprintf("%s-public-subnet-%s", cluster.Name, az.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
		searchTags := GetTags()
		searchTags[ResourceTypeKeyValue_NAME] = name
		if cluster.GetCloudResourceByTags(ResourceType_SUBNET, searchTags) != nil {
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
		publicSubnetCloudResource := &CloudResource{
			Name:         name,
			AssociatedId: vpc.RefId,
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SUBNET,
		}
		publicSubnetCloudResource.RefId = aws.ToString(subnetOutput.Subnet.SubnetId)
		cluster.AddCloudResource(publicSubnetCloudResource)
		a.log.Infof("public subnet %s created", name)
	}
	return nil
}

func (a *AwsCloudUsecase) createEips(ctx context.Context, cluster *Cluster) error {
	return nil
}

// Check and Create NAT Gateways
func (a *AwsCloudUsecase) createNatGateways(ctx context.Context, cluster *Cluster) error {
	if cluster.Level != ClusterLevel_ADVANCED {
		return nil
	}
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	natgateways := make([]ec2Types.NatGateway, 0)
	nextToken := ""
	for {
		describeNatGatewaysInput := &ec2.DescribeNatGatewaysInput{
			Filter: []ec2Types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			},
		}
		if nextToken != "" {
			describeNatGatewaysInput.NextToken = aws.String(nextToken)
		}
		natgatewayRes, err := a.ec2Client.DescribeNatGateways(ctx, describeNatGatewaysInput)
		if err != nil {
			return errors.Wrap(err, "failed to describe NAT Gateways")
		}
		natgateways = append(natgateways, natgatewayRes.NatGateways...)
		if natgatewayRes.NextToken == nil {
			break
		}
		nextToken = aws.ToString(natgatewayRes.NextToken)
	}

	for _, natgatewayResource := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
		natgatewayResourceExits := false
		for _, natgateway := range natgateways {
			if aws.ToString(natgateway.NatGatewayId) == natgatewayResource.RefId {
				natgatewayResourceExits = true
				break
			}
		}
		if !natgatewayResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_NAT_GATEWAY, natgatewayResource.RefId)
		}
	}

	for _, natGateway := range natgateways {
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
		if val, ok := subnetCloudResourceMapTags[ResourceTypeKeyValue_ACCESS]; !ok || val != ResourceTypeKeyValue_ACCESS_PUBLIC {
			continue
		}
		tags := GetTags()
		zoneName := cast.ToString(subnetCloudResourceMapTags[ResourceTypeKeyValue_ZONE_ID])
		name := a.getNatgatewayName(cluster.Name, zoneName)
		tags[ResourceTypeKeyValue_ZONE_ID] = zoneName
		tags[ResourceTypeKeyValue_NAME] = name
		a.createTags(ctx, aws.ToString(natGateway.NatGatewayId), ResourceType_NAT_GATEWAY, tags)
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
	for _, eipResource := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
		eipResourceExits := false
		for _, eip := range eipRes.Addresses {
			if aws.ToString(eip.AllocationId) == eipResource.RefId {
				eipResourceExits = true
				break
			}
		}
		if !eipResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_ELASTIC_IP, eipResource.RefId)
		}
	}

	for _, eip := range eipRes.Addresses {
		if eip.Domain != ec2Types.DomainTypeVpc {
			continue
		}
		if eip.AssociationId != nil || eip.InstanceId != nil || eip.NetworkInterfaceId != nil {
			continue
		}
		if cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, aws.ToString(eip.AllocationId)) != nil {
			a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
			continue
		}
		name := ""
		tags := GetTags()
		eipNoExitsZoneName := ""
		for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
			eip := cluster.GetCloudResourceByTagsSingle(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{
				ResourceTypeKeyValue_ZONE_ID: az.Name,
			})
			if eip == nil {
				eipNoExitsZoneName = az.Name
				break
			}
		}
		if eipNoExitsZoneName == "" {
			continue
		}
		tags[ResourceTypeKeyValue_ZONE_ID] = eipNoExitsZoneName
		tags[ResourceTypeKeyValue_NAME] = a.getEipName(cluster.Name, eipNoExitsZoneName)
		a.createTags(ctx, aws.ToString(eip.AllocationId), ResourceType_ELASTIC_IP, tags)
		cluster.AddCloudResource(&CloudResource{
			RefId: aws.ToString(eip.AllocationId),
			Name:  name,
			Value: aws.ToString(eip.PublicIp),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_ELASTIC_IP,
		})
		a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
	}

	// Allocate Elastic IP if it doesn't exist
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natGatewayName := a.getNatgatewayName(cluster.Name, az.Name)
		if cluster.GetCloudResourceByName(ResourceType_NAT_GATEWAY, natGatewayName) != nil {
			continue
		}
		eipName := a.getEipName(cluster.Name, az.Name)
		eipTags := map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: eipName, ResourceTypeKeyValue_ZONE_ID: az.Name}
		if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: eipName}) == nil {
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
			eipCloudResource := &CloudResource{
				Name: eipName,
				Tags: cluster.EncodeTags(eipTags),
				Type: ResourceType_ELASTIC_IP,
			}
			eipCloudResource.RefId = aws.ToString(eipOutput.AllocationId)
			eipCloudResource.Value = aws.ToString(eipOutput.PublicIp)
			cluster.AddCloudResource(eipCloudResource)
			a.log.Infof("elastic ip %s allocated", eipName)
		}
	}

	// Create NAT Gateways if they don't exist for each AZ
	natGateWayIds := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natGatewayName := a.getNatgatewayName(cluster.Name, az.Name)
		if cluster.GetCloudResourceByName(ResourceType_NAT_GATEWAY, natGatewayName) != nil {
			continue
		}

		// Create NAT Gateway
		natGatewayTags := GetTags()
		natGatewayTags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		natGatewayTags[ResourceTypeKeyValue_NAME] = natGatewayName
		natGatewayTags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
		// eip
		eip := cluster.GetCloudResourceByTagsSingle(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name})
		if eip == nil {
			return errors.New("no Elastic IP found for AZ " + az.Name)
		}
		// public subnet
		publickSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ZONE_ID: az.Name,
			ResourceTypeKeyValue_ACCESS:  ResourceTypeKeyValue_ACCESS_PUBLIC,
		})
		if publickSubnet == nil {
			return errors.New("no public subnet found for AZ " + az.Name)
		}
		natGatewayOutput, err := a.ec2Client.CreateNatGateway(ctx, &ec2.CreateNatGatewayInput{
			AllocationId:     aws.String(eip.RefId),
			SubnetId:         aws.String(publickSubnet.RefId),
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
		natGateWayCloudResource := &CloudResource{
			Name: natGatewayName,
			Tags: cluster.EncodeTags(natGatewayTags),
			Type: ResourceType_NAT_GATEWAY,
		}
		natGateWayCloudResource.RefId = aws.ToString(natGatewayOutput.NatGateway.NatGatewayId)
		natGateWayIds = append(natGateWayIds, natGateWayCloudResource.RefId)
		cluster.AddCloudResource(natGateWayCloudResource)
		a.log.Infof("nat gateway %s createing...", natGatewayName)
	}
	if len(natGateWayIds) != 0 {
		a.log.Info("waiting for NAT Gateway availability")
		waiter := ec2.NewNatGatewayAvailableWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeNatGatewaysInput{NatGatewayIds: natGateWayIds}, time.Duration(len(natGateWayIds))*TimeoutPerInstance)
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

	nextToken := ""
	routeTables := make([]ec2Types.RouteTable, 0)
	for {
		describeRouteTablesInput := &ec2.DescribeRouteTablesInput{
			Filters: []ec2Types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			},
		}
		if nextToken != "" {
			describeRouteTablesInput.NextToken = aws.String(nextToken)
		}
		routeTableRes, err := a.ec2Client.DescribeRouteTables(ctx, describeRouteTablesInput)
		if err != nil {
			return errors.Wrap(err, "failed to describe route tables")
		}
		routeTables = append(routeTables, routeTableRes.RouteTables...)
		if routeTableRes.NextToken == nil {
			break
		}
		nextToken = aws.ToString(routeTableRes.NextToken)
	}

	// Check existing route tables
	for _, routeTableResource := range cluster.GetCloudResource(ResourceType_ROUTE_TABLE) {
		routeTableResourceExits := false
		for _, routeTable := range routeTables {
			if aws.ToString(routeTable.RouteTableId) == routeTableResource.RefId {
				routeTableResourceExits = true
				break
			}
		}
		if !routeTableResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_ROUTE_TABLE, routeTableResource.RefId)
		}
	}

	// Create public route table
	publicRouteTableName := fmt.Sprintf("%s-public-rt", cluster.Name)
	publicRouteTableNameTags := GetTags()
	publicRouteTableNameTags[ResourceTypeKeyValue_NAME] = publicRouteTableName
	publicRouteTableNameTags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
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
		publicRouteTableResource := &CloudResource{
			Name:         publicRouteTableName,
			Tags:         cluster.EncodeTags(publicRouteTableNameTags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_ROUTE_TABLE,
		}
		publicRouteTableResource.RefId = aws.ToString(publicRouteTable.RouteTable.RouteTableId)
		cluster.AddCloudResource(publicRouteTableResource)
		a.log.Infof("public route table %s created", publicRouteTableName)

		// Add route to Internet Gateway in public route table
		_, err = a.ec2Client.CreateRoute(ctx, &ec2.CreateRouteInput{
			RouteTableId:         aws.String(publicRouteTableResource.RefId),
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			GatewayId:            aws.String(cluster.GetSingleCloudResource(ResourceType_INTERNET_GATEWAY).RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add route to Internet Gateway")
		}

		// Associate public subnets with public route table
		for i, publicSubnetReource := range cluster.GetCloudResourceByTags(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PUBLIC}) {
			publicAssociateRouteTable, err := a.ec2Client.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{
				RouteTableId: aws.String(publicRouteTableResource.RefId),
				SubnetId:     aws.String(publicSubnetReource.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate public subnet with route table")
			}
			parent := cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, publicRouteTableResource.RefId)
			publicAssociateRouteTableResource := &CloudResource{
				Name:         fmt.Sprintf("public associate routetable %d", i),
				Type:         ResourceType_ROUTE_TABLE,
				AssociatedId: publicRouteTableResource.RefId,
			}
			publicAssociateRouteTableResource.RefId = aws.ToString(publicAssociateRouteTable.AssociationId)
			cluster.AddSubCloudResource(ResourceType_ROUTE_TABLE, parent.Id, publicAssociateRouteTableResource)
		}
	}

	// Create private route tables (one per AZ)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		privateRouteTableName := fmt.Sprintf("%s-private-rt-%s", cluster.Name, az.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = privateRouteTableName
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		if cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: privateRouteTableName}) != nil {
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
		privateRouteTableCloudResource := &CloudResource{
			Name:         privateRouteTableName,
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_ROUTE_TABLE,
			AssociatedId: vpc.RefId,
		}
		privateRouteTableCloudResource.RefId = aws.ToString(privateRouteTable.RouteTable.RouteTableId)
		cluster.AddCloudResource(privateRouteTableCloudResource)
		a.log.Infof("private route table %s created for AZ %s", privateRouteTableName, az.Name)
		// Add route to NAT Gateway in private route table
		for _, natGateway := range cluster.GetCloudResourceByTags(ResourceType_NAT_GATEWAY, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name}) {
			_, err = a.ec2Client.CreateRoute(ctx, &ec2.CreateRouteInput{
				RouteTableId:         aws.String(privateRouteTableCloudResource.RefId),
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				NatGatewayId:         aws.String(natGateway.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to add route to NAT Gateway for AZ "+az.Name)
			}
		}

		// Associate private subnets with private route table
		searchTags := GetTags()
		searchTags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		searchTags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		for _, subnet := range cluster.GetCloudResourceByTags(ResourceType_SUBNET, searchTags) {
			privateAssociateRouteTable, err := a.ec2Client.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{
				RouteTableId: aws.String(privateRouteTableCloudResource.RefId),
				SubnetId:     aws.String(subnet.RefId),
			})
			if err != nil {
				return errors.Wrap(err, "failed to associate private subnet with route table in AZ "+az.Name)
			}
			parent := cluster.GetCloudResourceByRefID(ResourceType_ROUTE_TABLE, privateRouteTableCloudResource.RefId)
			privateAssociateRouteTableCloudResource := &CloudResource{
				Name:         fmt.Sprintf("%s-private-associate-routetable", subnet.Name),
				Type:         ResourceType_ROUTE_TABLE,
				AssociatedId: privateRouteTableCloudResource.RefId,
			}
			privateAssociateRouteTableCloudResource.RefId = aws.ToString(privateAssociateRouteTable.AssociationId)
			cluster.AddSubCloudResource(ResourceType_ROUTE_TABLE, parent.Id, privateAssociateRouteTableCloudResource)
		}
	}
	return nil
}

// Check and Create security group
func (a *AwsCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	// ToDo
	// vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	// if vpc == nil {
	// 	return errors.New("vpc not found")
	// }
	// sgNames := []string{
	// 	fmt.Sprintf("%s-%s-sg", cluster.Name, ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER.String()),
	// 	fmt.Sprintf("%s-%s-sg", cluster.Name, ResourceTypeKeyValue_SECURITY_GROUP_TYPE_BOSTION.String()),
	// }
	// securityGroups := make([]ec2Types.SecurityGroup, 0)
	// nextToken := ""
	// for {
	// 	describeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
	// 		Filters: []ec2Types.Filter{
	// 			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
	// 			{Name: aws.String("group-name"), Values: sgNames},
	// 		},
	// 	}
	// 	if nextToken != "" {
	// 		describeSecurityGroupsInput.NextToken = aws.String(nextToken)
	// 	}
	// 	securityGroupRes, err := a.ec2Client.DescribeSecurityGroups(ctx, describeSecurityGroupsInput)
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to describe security groups")
	// 	}
	// 	securityGroups = append(securityGroups, securityGroupRes.SecurityGroups...)
	// 	nextToken = aws.ToString(securityGroupRes.NextToken)
	// 	if nextToken == "" {
	// 		break
	// 	}
	// }

	// for _, sgCloudResource := range cluster.GetCloudResource(ResourceType_SECURITY_GROUP) {
	// 	sgCloudResourceExits := false
	// 	for _, sg := range securityGroups {
	// 		if aws.ToString(sg.GroupId) == sgCloudResource.RefId {
	// 			sgCloudResourceExits = true
	// 			break
	// 		}
	// 	}
	// 	if !sgCloudResourceExits {
	// 		cluster.DeleteCloudResourceByRefID(ResourceType_SECURITY_GROUP, sgCloudResource.RefId)
	// 	}
	// }

	// for _, sgName := range sgNames {
	// 	if cluster.GetCloudResourceByName(ResourceType_SECURITY_GROUP, sgName) != nil {
	// 		continue
	// 	}
	// 	tags := GetTags()
	// 	tags[ResourceTypeKeyValue_NAME] = sgName
	// 	if strings.Contains(sgName, ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER.String()) {
	// 		tags[ResourceTypeKeyValue_SECURITY_GROUP_TYPE] = ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER
	// 	}
	// 	if strings.Contains(sgName, ResourceTypeKeyValue_SECURITY_GROUP_TYPE_BOSTION.String()) {
	// 		tags[ResourceTypeKeyValue_SECURITY_GROUP_TYPE] = ResourceTypeKeyValue_SECURITY_GROUP_TYPE_BOSTION
	// 	}
	// 	sgOutput, err := a.ec2Client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
	// 		GroupName:   aws.String(sgName),
	// 		VpcId:       aws.String(vpc.RefId),
	// 		Description: aws.String(sgName),
	// 		TagSpecifications: []ec2Types.TagSpecification{
	// 			{
	// 				ResourceType: ec2Types.ResourceTypeSecurityGroup,
	// 				Tags:         a.mapToEc2Tags(tags),
	// 			},
	// 		},
	// 	})
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to create security group")
	// 	}
	// 	sgCloudResource := &CloudResource{
	// 		Name:         sgName,
	// 		Tags:         cluster.EncodeTags(tags),
	// 		Type:         ResourceType_SECURITY_GROUP,
	// 		AssociatedId: vpc.RefId,
	// 	}
	// 	sgCloudResource.RefId = aws.ToString(sgOutput.GroupId)
	// 	cluster.AddCloudResource(sgCloudResource)
	// 	a.log.Infof("security group %s created", sgName)

	// 	ipPermissionsArr := make([]ec2Types.IpPermission, 0)
	// 	for _, sg := range cluster.SecurityGroups {
	// 		ipPermissionsArr = append(ipPermissionsArr, ec2Types.IpPermission{
	// 			IpProtocol: aws.String(sg.Protocol),
	// 			FromPort:   aws.Int32(sg.StartPort),
	// 			ToPort:     aws.Int32(sg.EndPort),
	// 			IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String(sg.IpCidr)}},
	// 		})
	// 	}
	// 	if v, ok := tags[ResourceTypeKeyValue_SECURITY_GROUP_TYPE]; ok && v == ResourceTypeKeyValue_SECURITY_GROUP_TYPE_BOSTION {
	// 		_, err = a.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
	// 			GroupId:       aws.String(sgCloudResource.RefId),
	// 			IpPermissions: ipPermissionsArr,
	// 			TagSpecifications: []ec2Types.TagSpecification{
	// 				{
	// 					ResourceType: ec2Types.ResourceTypeSecurityGroupRule,
	// 					Tags:         a.mapToEc2Tags(tags),
	// 				},
	// 			},
	// 		})
	// 		if err != nil {
	// 			return errors.Wrap(err, "failed to add inbound rules to security group")
	// 		}
	// 	}
	// 	if v, ok := tags[ResourceTypeKeyValue_SECURITY_GROUP_TYPE]; ok && v == ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER {
	// 		_, err = a.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
	// 			GroupId: aws.String(sgCloudResource.RefId),
	// 			IpPermissions: []ec2Types.IpPermission{
	// 				{
	// 					IpProtocol: aws.String(string(ec2Types.ProtocolTcp)),
	// 					FromPort:   aws.Int32(80),
	// 					ToPort:     aws.Int32(80),
	// 					IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
	// 				},
	// 				{
	// 					IpProtocol: aws.String(string(ec2Types.ProtocolTcp)),
	// 					FromPort:   aws.Int32(443),
	// 					ToPort:     aws.Int32(443),
	// 					IpRanges:   []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
	// 				},
	// 			},
	// 			TagSpecifications: []ec2Types.TagSpecification{
	// 				{
	// 					ResourceType: ec2Types.ResourceTypeSecurityGroupRule,
	// 					Tags:         a.mapToEc2Tags(tags),
	// 				},
	// 			},
	// 		})
	// 		if err != nil {
	// 			return errors.Wrap(err, "failed to add inbound rules to security group")
	// 		}
	// 	}
	// }
	return nil
}

// create slb
func (a *AwsCloudUsecase) createSLB(ctx context.Context, cluster *Cluster) error {
	// todo
	// vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	// if vpc == nil {
	// 	return errors.New("vpc not found")
	// }
	// name := fmt.Sprintf("%s-slb", cluster.Name)
	// publicSubnetIDs := make([]string, 0)
	// for _, subnet := range cluster.GetCloudResourceByTags(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PUBLIC}) {
	// 	publicSubnetIDs = append(publicSubnetIDs, subnet.RefId)
	// }
	// if len(publicSubnetIDs) == 0 {
	// 	return errors.New("failed to get public subnets")
	// }
	// sgIDs := make([]string, 0)
	// for _, sg := range cluster.GetCloudResourceByTags(ResourceType_SECURITY_GROUP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_SECURITY_GROUP_TYPE: ResourceTypeKeyValue_SECURITY_GROUP_TYPE_CLUSTER}) {
	// 	sgIDs = append(sgIDs, sg.RefId)
	// }
	// if len(sgIDs) == 0 {
	// 	return errors.New("failed to get security group")
	// }

	// loadBalancers, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
	// 	Names: []string{name},
	// })
	// if err != nil && !strings.Contains(err.Error(), AwsNotFound) {
	// 	return errors.Wrap(err, "failed to describe load balancers")
	// }
	// for _, cloudResource := range cluster.GetCloudResource(ResourceType_LOAD_BALANCER) {
	// 	cloudResourceExits := false
	// 	for _, loadBalancer := range loadBalancers.LoadBalancers {
	// 		if aws.ToString(loadBalancer.LoadBalancerArn) == cloudResource.RefId {
	// 			cloudResourceExits = true
	// 			break
	// 		}
	// 	}
	// 	if !cloudResourceExits {
	// 		cluster.DeleteCloudResourceByRefID(ResourceType_LOAD_BALANCER, cloudResource.RefId)
	// 	}
	// }

	// if loadBalancers != nil && loadBalancers.LoadBalancers != nil && len(loadBalancers.LoadBalancers) != 0 {
	// 	for _, loadBalancer := range loadBalancers.LoadBalancers {
	// 		if loadBalancer.LoadBalancerArn == nil {
	// 			continue
	// 		}
	// 		if cluster.GetCloudResourceByRefID(ResourceType_LOAD_BALANCER, aws.ToString(loadBalancer.LoadBalancerArn)) != nil {
	// 			continue
	// 		}
	// 		cluster.AddCloudResource(&CloudResource{
	// 			Name:  aws.ToString(loadBalancer.LoadBalancerName),
	// 			RefId: aws.ToString(loadBalancer.LoadBalancerArn),
	// 			Type:  ResourceType_LOAD_BALANCER,
	// 		})
	// 		a.log.Infof("slb %s already exists", aws.ToString(loadBalancer.LoadBalancerName))
	// 	}
	// 	return nil
	// }

	// // Create SLB
	// tags := GetTags()
	// tags[ResourceTypeKeyValue_NAME] = name
	// slbOutput, err := a.elbv2Client.CreateLoadBalancer(ctx, &elasticloadbalancingv2.CreateLoadBalancerInput{
	// 	Name:           aws.String(name),
	// 	Subnets:        publicSubnetIDs,
	// 	SecurityGroups: sgIDs,
	// 	Scheme:         elasticloadbalancingv2Types.LoadBalancerSchemeEnumInternetFacing,
	// 	Type:           elasticloadbalancingv2Types.LoadBalancerTypeEnumApplication,
	// 	Tags:           a.mapToElbv2Tags(tags),
	// })
	// if err != nil || len(slbOutput.LoadBalancers) == 0 {
	// 	return errors.Wrap(err, "failed to create SLB")
	// }
	// slb := slbOutput.LoadBalancers[0]
	// cluster.AddCloudResource(&CloudResource{
	// 	Name:  name,
	// 	RefId: aws.ToString(slb.LoadBalancerArn),
	// 	Tags:  cluster.EncodeTags(tags),
	// 	Type:  ResourceType_LOAD_BALANCER,
	// })

	// // Create target group
	// taggetGroup, err := a.elbv2Client.CreateTargetGroup(ctx, &elasticloadbalancingv2.CreateTargetGroupInput{
	// 	Name:       aws.String(fmt.Sprintf("%s-targetgroup", cluster.Name)),
	// 	TargetType: elasticloadbalancingv2Types.TargetTypeEnumAlb,
	// 	Port:       aws.Int32(6443),
	// 	Protocol:   elasticloadbalancingv2Types.ProtocolEnumHttp,
	// 	VpcId:      aws.String(vpc.RefId),
	// 	Tags:       a.mapToElbv2Tags(tags),
	// })
	// if err != nil || len(taggetGroup.TargetGroups) == 0 {
	// 	return errors.Wrap(err, "failed to create target group")
	// }
	// targetGroup := taggetGroup.TargetGroups[0]
	// a.log.Infof("target group %s created", aws.ToString(targetGroup.TargetGroupArn))

	// // create listener
	// _, err = a.elbv2Client.CreateListener(ctx, &elasticloadbalancingv2.CreateListenerInput{
	// 	DefaultActions: []elasticloadbalancingv2Types.Action{
	// 		{
	// 			Type: elasticloadbalancingv2Types.ActionTypeEnumForward,
	// 			ForwardConfig: &elasticloadbalancingv2Types.ForwardActionConfig{
	// 				TargetGroups: []elasticloadbalancingv2Types.TargetGroupTuple{
	// 					{
	// 						TargetGroupArn: targetGroup.TargetGroupArn,
	// 						Weight:         aws.Int32(100),
	// 					},
	// 				},
	// 			},
	// 		},
	// 	},
	// 	LoadBalancerArn: slb.LoadBalancerArn,
	// 	Port:            aws.Int32(6443),
	// 	Protocol:        elasticloadbalancingv2Types.ProtocolEnumHttp,
	// })
	// if err != nil {
	// 	return errors.Wrap(err, "failed to create listener")
	// }
	return nil
}

var NodeArchToAwsIMagecloudType = map[NodeArchType]string{
	NodeArchType_NodeArchType_UNSPECIFIED: "x86_64",
	NodeArchType_AMD64:                    "x86_64",
	NodeArchType_ARM64:                    "arm64",
}

func (a *AwsCloudUsecase) findImage(ctx context.Context, arch NodeArchType) (ec2Types.Image, error) {
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
				Values: []string{NodeArchToAwsIMagecloudType[arch]},
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

func (a *AwsCloudUsecase) findInstanceType(_ context.Context, _ findInstanceTypeParam) (*InstanceTypeInfo, error) {
	// instanceTypeInfo := ec2Types.InstanceTypeInfo{}
	// instanceData := make(InstanceTypeResults, 0)
	// instanceTypeInput := &ec2.DescribeInstanceTypesInput{
	// 	Filters: []ec2Types.Filter{
	// 		{
	// 			Name:   aws.String("processor-info.supported-architecture"),
	// 			Values: []string{NodeArchToAwsIMagecloudType[findInstanceTypeParam.Arch]},
	// 		},
	// 		{
	// 			Name:   aws.String("vcpu-info.default-vcpus"),
	// 			Values: []string{fmt.Sprintf("%s", findInstanceTypeParam.CPU)},
	// 		},
	// 		{
	// 			Name:   aws.String("memory-info.size-in-mib"),
	// 			Values: []string{fmt.Sprintf("%s", findInstanceTypeParam.Memory*1024)},
	// 		},
	// 	},
	// }
	// ToDo
	// for {
	// 	instanceTypes, err := a.ec2Client.DescribeInstanceTypes(ctx, instanceTypeInput)
	// 	if err != nil {
	// 		return instanceTypeInfo, errors.Wrap(err, "failed to describe instance types")
	// 	}
	// 	instanceData = append(instanceData, instanceTypes.InstanceTypes...)
	// 	if instanceTypes.NextToken == nil {
	// 		break
	// 	}
	// 	instanceTypeInput.NextToken = instanceTypes.NextToken
	// }
	// sort.Sort(instanceData)
	// for _, instanceType := range instanceData {
	// 	if aws.ToInt64(instanceType.MemoryInfo.SizeInMiB) == 0 {
	// 		continue
	// 	}
	// 	memoryGBiSize := aws.ToInt64(instanceType.MemoryInfo.SizeInMiB) / 1024
	// 	if int32(memoryGBiSize) >= Memory && aws.ToInt32(instanceType.VCpuInfo.DefaultVCpus) >= CPU {
	// 		instanceTypeInfo = instanceType
	// 	}
	// 	if instanceTypeInfo.InstanceType == "" {
	// 		continue
	// 	}
	// 	if GPU == 0 {
	// 		break
	// 	}
	// 	for _, gpues := range instanceType.GpuInfo.Gpus {
	// 		if aws.ToInt32(gpues.Count) >= GPU {
	// 			break
	// 		}
	// 	}
	// }
	// if instanceTypeInfo.InstanceType == "" {
	// 	return instanceTypeInfo, errors.New("no instance type found")
	// }
	// return instanceTypeInfo, nil
	return nil, nil
}

func (a *AwsCloudUsecase) getInstances(ctx context.Context, vpcCloudResource *CloudResource, instanceIds ...string) ([]ec2Types.Instance, error) {
	filters := []ec2Types.Filter{
		{Name: aws.String("vpc-id"), Values: []string{vpcCloudResource.RefId}},
		{Name: aws.String("instance-state-name"), Values: []string{
			string(ec2Types.InstanceStateNamePending),
			string(ec2Types.InstanceStateNameRunning),
			string(ec2Types.InstanceStateNameShuttingDown),
			string(ec2Types.InstanceStateNameStopping),
			string(ec2Types.InstanceStateNameStopped),
		}},
	}
	input := &ec2.DescribeInstancesInput{Filters: filters}
	if len(instanceIds) > 0 {
		input.InstanceIds = instanceIds
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

// create Tags
func (a *AwsCloudUsecase) createTags(ctx context.Context, resourceID string, resourceType ResourceType, tags map[ResourceTypeKeyValue]any) error {
	_, err := a.ec2Client.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{resourceID},
		Tags:      a.mapToEc2Tags(tags),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create tags for %s", resourceType.String())
	}
	return nil
}

// map to ec2 tags
func (a *AwsCloudUsecase) mapToEc2Tags(tags map[ResourceTypeKeyValue]any) []ec2Types.Tag {
	ec2Tags := []ec2Types.Tag{}
	for key, value := range tags {
		ec2Tags = append(ec2Tags, ec2Types.Tag{Key: aws.String(key.String()), Value: aws.String(cast.ToString(value))})
	}
	return ec2Tags
}

// map to elbv2 tags
func (a *AwsCloudUsecase) mapToElbv2Tags(tags map[ResourceTypeKeyValue]any) []elasticloadbalancingv2Types.Tag {
	elbv2Tags := []elasticloadbalancingv2Types.Tag{}
	for key, value := range tags {
		elbv2Tags = append(elbv2Tags, elasticloadbalancingv2Types.Tag{Key: aws.String(key.String()), Value: aws.String(cast.ToString(value))})
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

func (a *AwsCloudUsecase) getNatgatewayName(clusterName, zoneName string) string {
	return fmt.Sprintf("%s-nat-gateway-%s", clusterName, zoneName)
}

func (a *AwsCloudUsecase) getEipName(clusterName, zoneName string) string {
	return fmt.Sprintf("%s-eip-%s", clusterName, zoneName)
}
