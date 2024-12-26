package biz

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

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
			Value: aws.ToString(v.Endpoint),
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
	for _, rule := range cluster.IngressControllerRules {
		if rule.StartPort == 22 && rule.EndPort == 22 {
			rule.Access = IngressControllerRuleAccess_PUBLIC
		}
	}
	return a.ManageSLB(ctx, cluster)
}

func (a *AwsCloudUsecase) CloseSSh(ctx context.Context, cluster *Cluster) error {
	for _, rule := range cluster.IngressControllerRules {
		if rule.StartPort == 22 && rule.EndPort == 22 {
			rule.Access = IngressControllerRuleAccess_PRIVATE
		}
	}
	return a.ManageSLB(ctx, cluster)
}

func (a *AwsCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	funcs := []func(context.Context, *Cluster) error{
		a.createVPC,
		a.createInternetGateway,
		a.createSubnets,
		a.createEips,
		a.createNatGateways,
		a.createRouteTables,
	}
	for _, f := range funcs {
		err := f(ctx, cluster)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *AwsCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	keyName := cluster.GetkeyPairName()
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
	cluster.AddCloudResource(&CloudResource{
		Name:  keyName,
		RefId: aws.ToString(keyPairOutput.KeyPairId),
		Tags:  cluster.EncodeTags(tags),
		Type:  ResourceType_KEY_PAIR,
	})
	a.log.Info("% key pair imported", keyName)
	return nil
}

// delete network(vpc, subnet, internet gateway, nat gateway, route table, security group)
func (a *AwsCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// Delete SLB
	for _, slb := range cluster.GetCloudResource(ResourceType_LOAD_BALANCER) {
		_, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			LoadBalancerArns: []string{slb.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_LOAD_BALANCER, slb.Id)
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
		cluster.DeleteCloudResourceByID(ResourceType_LOAD_BALANCER, slb.Id)
	}

	// Delete security group
	for _, sg := range cluster.GetCloudResource(ResourceType_SECURITY_GROUP) {
		_, err := a.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{sg.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_SECURITY_GROUP, sg.Id)
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
		cluster.DeleteCloudResourceByID(ResourceType_SECURITY_GROUP, sg.Id)
	}

	// Delete the eip
	for _, eip := range cluster.GetCloudResource(ResourceType_ELASTIC_IP) {
		_, err := a.ec2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
			AllocationIds: []string{eip.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_ELASTIC_IP, eip.Id)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe eip")
		}
		_, err = a.ec2Client.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{
			AllocationId: aws.String(eip.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to release Elastic IP")
		}
		cluster.DeleteCloudResourceByID(ResourceType_ELASTIC_IP, eip.Id)
	}

	// Delete NAT Gateways
	natGwIDs := make([]string, 0)
	for _, natGw := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
		_, err := a.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
			NatGatewayIds: []string{natGw.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_NAT_GATEWAY, natGw.Id)
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

	// Delete route tables
	rts := cluster.GetCloudResource(ResourceType_ROUTE_TABLE)
	for _, rt := range rts {
		_, err := a.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			RouteTableIds: []string{rt.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_ROUTE_TABLE, rt.Id)
			continue
		}
		if err != nil {
			return errors.Wrap(err, "failed to describe route table")
		}
		_, err = a.ec2Client.DeleteRouteTable(ctx, &ec2.DeleteRouteTableInput{
			RouteTableId: aws.String(rt.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete route table")
		}
	}
	cluster.DeleteCloudResource(ResourceType_ROUTE_TABLE)

	// Delete Subnets
	for _, subnet := range cluster.GetCloudResource(ResourceType_SUBNET) {
		_, err := a.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []string{subnet.RefId},
		})
		if err != nil && strings.Contains(err.Error(), AwsNotFound) {
			cluster.DeleteCloudResourceByID(ResourceType_SUBNET, subnet.Id)
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

func (a *AwsCloudUsecase) checkingInstanceInventory(ctx context.Context, instanceType, zoneId string) (bool, error) {
	res, err := a.ec2Client.DescribeInstanceTypeOfferings(ctx, &ec2.DescribeInstanceTypeOfferingsInput{
		Filters: []ec2Types.Filter{{
			Name:   aws.String("instance-type"),
			Values: []string{instanceType},
		}, {
			Name:   aws.String("location"),
			Values: []string{zoneId},
		}},
		LocationType: ec2Types.LocationTypeAvailabilityZone,
	})
	if err != nil {
		return false, errors.Wrap(err, "failed to describe instance type offerings")
	}
	for _, v := range res.InstanceTypeOfferings {
		if string(v.InstanceType) == instanceType && aws.ToString(v.Location) == zoneId {
			return true, nil
		}
	}
	return false, nil
}

func (a *AwsCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	vpcCloudResource := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpcCloudResource == nil {
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

	// Create instances
	instanceIds := make([]string, 0)
	for _, nodeGroup := range cluster.NodeGroups {
		needCreateNode := false
		for _, node := range cluster.Nodes {
			if node.NodeGroupId == nodeGroup.Id && node.Status == NodeStatus_NODE_CREATING {
				needCreateNode = true
				break
			}
		}
		if !needCreateNode {
			continue
		}
		instancesInput := &ec2.RunInstancesInput{
			KeyName:          aws.String(keyPair.Name),
			MaxCount:         aws.Int32(1),
			MinCount:         aws.Int32(1),
			SecurityGroupIds: []string{sg.RefId},
		}
		for index, node := range cluster.Nodes {
			if node.Status != NodeStatus_NODE_CREATING || node.NodeGroupId != nodeGroup.Id {
				continue
			}
			privateSubnet := cluster.DistributeNodePrivateSubnets(index)
			if privateSubnet == nil {
				return errors.New("no private subnet found")
			}
			privateSubnetTagsMap := cluster.DecodeTags(privateSubnet.Tags)
			zoneId := cast.ToString(privateSubnetTagsMap[ResourceTypeKeyValue_ZONE_ID])
			ok, err := a.checkingInstanceInventory(ctx, node.InstanceType, zoneId)
			if err != nil {
				return err
			}
			if !ok {
				for _, instanceId := range strings.Split(node.BackupInstanceIds, ",") {
					ok, err = a.checkingInstanceInventory(ctx, instanceId, zoneId)
					if err != nil {
						return err
					}
					if ok {
						node.InstanceId = instanceId
						break
					}
				}
			}
			if !ok {
				node.ErrorInfo = NodeError_INSUFFICIENT_INVENTORY
				continue
			}
			instancesInput.InstanceType = ec2Types.InstanceType(node.InstanceType)
			instancesInput.ImageId = aws.String(node.ImageId)
			blockDeviceMappings := []ec2Types.BlockDeviceMapping{
				{
					DeviceName: aws.String(node.SystemDiskName),
					Ebs: &ec2Types.EbsBlockDevice{
						VolumeSize:          aws.Int32(node.SystemDiskSize),
						VolumeType:          ec2Types.VolumeType(ec2Types.VolumeTypeGp3),
						DeleteOnTermination: aws.Bool(true),
					},
				},
			}
			instancesInput.BlockDeviceMappings = blockDeviceMappings
			instancesInput.SubnetId = aws.String(privateSubnet.RefId)
			instancesOutput, err := a.ec2Client.RunInstances(ctx, instancesInput)
			if err != nil {
				return errors.Wrap(err, "failed to run instances")
			}
			for _, instance := range instancesOutput.Instances {
				instanceIds = append(instanceIds, aws.ToString(instance.InstanceId))
				node.InstanceId = aws.ToString(instance.InstanceId)
				node.Ip = aws.ToString(instance.PrivateIpAddress)
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
	vpcName := cluster.GetVpcName()
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

func (a *AwsCloudUsecase) createInternetGateway(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	internetgatewayRes, err := a.ec2Client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("attachment.state"), Values: []string{"available"}},
			{Name: aws.String("attachment.vpc-id"), Values: []string{vpc.RefId}},
		},
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe internet gateways")
	}
	// clear history internet gateway
	for _, inter := range cluster.GetCloudResource(ResourceType_INTERNET_GATEWAY) {
		exits := false
		for _, v := range internetgatewayRes.InternetGateways {
			if inter.RefId == aws.ToString(v.InternetGatewayId) {
				exits = true
				break
			}
		}
		if !exits {
			cluster.DeleteCloudResourceByID(ResourceType_INTERNET_GATEWAY, inter.Id)
		}
	}
	name := fmt.Sprintf("%s-%s", cluster.Name, "internet-gateway")
	tag := GetTags()
	tag[ResourceTypeKeyValue_NAME] = name
	for _, internetgateway := range internetgatewayRes.InternetGateways {
		if cluster.GetCloudResourceByRefID(ResourceType_INTERNET_GATEWAY, aws.ToString(internetgateway.InternetGatewayId)) != nil {
			a.log.Infof("internet gateway %s already exists", aws.ToString(internetgateway.InternetGatewayId))
			return nil
		}
		cluster.AddCloudResource(&CloudResource{
			RefId: aws.ToString(internetgateway.InternetGatewayId),
			Name:  name,
			Tags:  cluster.EncodeTags(tag),
			Type:  ResourceType_INTERNET_GATEWAY,
		})
	}
	if cluster.GetSingleCloudResource(ResourceType_INTERNET_GATEWAY) != nil {
		return nil
	}
	createInternetGatewayRes, err := a.ec2Client.CreateInternetGateway(ctx, &ec2.CreateInternetGatewayInput{
		TagSpecifications: []ec2Types.TagSpecification{
			{
				ResourceType: ec2Types.ResourceTypeInternetGateway,
				Tags:         a.mapToEc2Tags(tag),
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create internet gateway")
	}
	_, err = a.ec2Client.AttachInternetGateway(ctx, &ec2.AttachInternetGatewayInput{
		InternetGatewayId: createInternetGatewayRes.InternetGateway.InternetGatewayId,
		VpcId:             aws.String(vpc.RefId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to attach internet gateway")
	}
	cluster.AddCloudResource(&CloudResource{
		RefId: aws.ToString(createInternetGatewayRes.InternetGateway.InternetGatewayId),
		Name:  name,
		Tags:  cluster.EncodeTags(tag),
		Type:  ResourceType_INTERNET_GATEWAY,
	})
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

	// One subnet for one available zone
	subnetExitsCidrs := make([]string, 0)
	zoneSubnets := make(map[string]ec2Types.Subnet)
	for _, subnet := range subnets {
		if subnet.AvailabilityZone == nil || subnet.AvailabilityZoneId == nil || subnet.CidrBlock == nil || subnet.SubnetId == nil {
			continue
		}
		subnetExitsCidrs = append(subnetExitsCidrs, aws.ToString(subnet.CidrBlock))
		_, ok := zoneSubnets[aws.ToString(subnet.AvailabilityZone)]
		if ok {
			continue
		}
		zoneSubnets[aws.ToString(subnet.AvailabilityZone)] = subnet
	}
	for zoneName, subnet := range zoneSubnets {
		if cluster.GetCloudResourceByRefID(ResourceType_SUBNET, aws.ToString(subnet.SubnetId)) != nil {
			a.log.Infof("subnet %s already exists", aws.ToString(subnet.SubnetId))
			continue
		}
		name := cluster.GetSubnetName(zoneName)
		tags := GetTags()
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ZONE_ID] = zoneName
		a.createTags(ctx, aws.ToString(subnet.SubnetId), ResourceType_SUBNET, tags)
		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: aws.ToString(subnet.SubnetId),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_SUBNET,
			Value: aws.ToString(subnet.CidrBlock),
		})
		a.log.Infof("subnet %s already exists", aws.ToString(subnet.SubnetId))
	}

	// Create subnets
	for _, zone := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		name := cluster.GetSubnetName(zone.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ZONE_ID] = zone.Name
		if cluster.GetCloudResourceByTags(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_NAME: name}) != nil {
			continue
		}
		cidr, err := utils.GenerateSubnet(VpcCIDR, subnetExitsCidrs)
		if err != nil {
			return err
		}
		subnetExitsCidrs = append(subnetExitsCidrs, cidr)
		subnetOutput, err := a.ec2Client.CreateSubnet(ctx, &ec2.CreateSubnetInput{
			VpcId:            aws.String(vpc.RefId),
			CidrBlock:        aws.String(cidr),
			AvailabilityZone: aws.String(zone.Name),
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
			Value:        cidr,
		})
		a.log.Infof("private subnet %s created", name)
	}
	return nil
}

func (a *AwsCloudUsecase) createEips(ctx context.Context, cluster *Cluster) error {
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

	// one zone one eip for nat gateway
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		name := cluster.GetEipName(az.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		tags[ResourceTypeKeyValue_NAME] = name
		for _, eip := range eipRes.Addresses {
			if eip.Domain != ec2Types.DomainTypeVpc || eip.AssociationId != nil || eip.InstanceId != nil || eip.NetworkInterfaceId != nil {
				continue
			}
			if cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, aws.ToString(eip.AllocationId)) != nil {
				a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
				continue
			}
			if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name}) != nil {
				break
			}
			cluster.AddCloudResource(&CloudResource{
				Name:  name,
				RefId: aws.ToString(eip.AllocationId),
				Value: aws.ToString(eip.PublicIp),
				Tags:  cluster.EncodeTags(tags),
				Type:  ResourceType_ELASTIC_IP,
			})
			a.log.Infof("elastic ip %s already exists", aws.ToString(eip.PublicIp))
		}
		if cluster.GetCloudResourceByTags(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name}) != nil {
			continue
		}
		eipOutput, err := a.ec2Client.AllocateAddress(ctx, &ec2.AllocateAddressInput{
			Domain: ec2Types.DomainTypeVpc,
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeElasticIp,
					Tags:         a.mapToEc2Tags(tags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to allocate Elastic IP")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: aws.ToString(eipOutput.AllocationId),
			Value: aws.ToString(eipOutput.PublicIp),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_ELASTIC_IP,
		})
		a.log.Infof("elastic ip %s allocated for %s", name, az.Name)
		time.Sleep(time.Second * TimeOutSecond)
	}
	return nil
}

// Check and Create NAT Gateways
func (a *AwsCloudUsecase) createNatGateways(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	natgatewayRes, err := a.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			{Name: aws.String("state"), Values: []string{"available"}},
		},
		MaxResults: aws.Int32(500),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe nat gateway")
	}

	for _, natgatewayResource := range cluster.GetCloudResource(ResourceType_NAT_GATEWAY) {
		natgatewayResourceExits := false
		for _, natgateway := range natgatewayRes.NatGateways {
			if aws.ToString(natgateway.NatGatewayId) == natgatewayResource.RefId && natgateway.State == ec2Types.NatGatewayStateAvailable {
				natgatewayResourceExits = true
				break
			}
		}
		if !natgatewayResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_NAT_GATEWAY, natgatewayResource.RefId)
		}
	}

	for _, natGateway := range natgatewayRes.NatGateways {
		if cluster.GetCloudResourceByRefID(ResourceType_NAT_GATEWAY, aws.ToString(natGateway.NatGatewayId)) != nil {
			a.log.Infof("nat gateway %s already exists", aws.ToString(natGateway.NatGatewayId))
			continue
		}
		if natGateway.SubnetId == nil || len(natGateway.NatGatewayAddresses) == 0 {
			continue
		}
		subnetCloudResource := cluster.GetCloudResourceByRefID(ResourceType_SUBNET, aws.ToString(natGateway.SubnetId))
		if subnetCloudResource == nil {
			continue
		}
		subnetCloudResourceMapTags := cluster.DecodeTags(subnetCloudResource.Tags)
		if val, ok := subnetCloudResourceMapTags[ResourceTypeKeyValue_ACCESS]; !ok || cast.ToInt32(val) != int32(ResourceTypeKeyValue_ACCESS_PRIVATE.Number()) {
			continue
		}
		eipBindOk := false
		eipId := ""
		for _, eip := range natGateway.NatGatewayAddresses {
			eipId = aws.ToString(eip.AllocationId)
			if eipId != "" && cluster.GetCloudResourceByRefID(ResourceType_ELASTIC_IP, eipId) != nil {
				eipBindOk = true
				break
			}
		}
		if !eipBindOk {
			continue
		}
		tags := GetTags()
		name := cluster.GetNatgatewayName(cast.ToString(subnetCloudResourceMapTags[ResourceTypeKeyValue_ZONE_ID]))
		tags[ResourceTypeKeyValue_NAME] = name
		tags[ResourceTypeKeyValue_ZONE_ID] = subnetCloudResourceMapTags[ResourceTypeKeyValue_ZONE_ID]
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		a.createTags(ctx, aws.ToString(natGateway.NatGatewayId), ResourceType_NAT_GATEWAY, tags)
		cluster.AddCloudResource(&CloudResource{
			Name:         name,
			RefId:        aws.ToString(natGateway.NatGatewayId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_NAT_GATEWAY,
			AssociatedId: subnetCloudResource.RefId,
			Value:        eipId,
		})
		a.log.Infof("nat gateway %s already exists", aws.ToString(natGateway.NatGatewayId))
	}

	// Create NAT Gateways if they don't exist for each AZ
	natGateWayIds := make([]string, 0)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		natgatewayResource := cluster.GetCloudResourceByTagsSingle(ResourceType_NAT_GATEWAY, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name})
		// value is the eip id
		if natgatewayResource != nil && natgatewayResource.Value != "" {
			continue
		}
		// Get private subnet for the AZ
		privateSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS:  ResourceTypeKeyValue_ACCESS_PRIVATE,
			ResourceTypeKeyValue_ZONE_ID: az.Name,
		})
		if privateSubnet == nil {
			return errors.New("no private subnet found for AZ " + az.Name)
		}
		// Get Elastic IP
		eip := cluster.GetCloudResourceByTagsSingle(ResourceType_ELASTIC_IP, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name})
		if eip == nil {
			return errors.New("no eip found for AZ " + az.Name)
		}
		// Create NAT Gateway
		natGatewayName := cluster.GetNatgatewayName(az.Name)
		natGatewayTags := GetTags()
		natGatewayTags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		natGatewayTags[ResourceTypeKeyValue_NAME] = natGatewayName
		natGatewayTags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PUBLIC
		natGatewayOutput, err := a.ec2Client.CreateNatGateway(ctx, &ec2.CreateNatGatewayInput{
			AllocationId:     aws.String(eip.RefId),
			SubnetId:         aws.String(privateSubnet.RefId),
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
		natGateWayIds = append(natGateWayIds, aws.ToString(natGatewayOutput.NatGateway.NatGatewayId))
		cluster.AddCloudResource(&CloudResource{
			Name:  natGatewayName,
			Tags:  cluster.EncodeTags(natGatewayTags),
			Type:  ResourceType_NAT_GATEWAY,
			RefId: aws.ToString(natGatewayOutput.NatGateway.NatGatewayId),
		})
		a.log.Infof("nat gateway %s createing...", natGatewayName)
	}
	if len(natGateWayIds) != 0 {
		waiter := ec2.NewNatGatewayAvailableWaiter(a.ec2Client)
		err := waiter.Wait(ctx, &ec2.DescribeNatGatewaysInput{NatGatewayIds: natGateWayIds}, time.Duration(len(natGateWayIds))*TimeoutPerInstance)
		if err != nil {
			return errors.Wrap(err, "failed to wait for NAT Gateway availability")
		}
		a.log.Info("nat gateway created")
	}
	return nil
}

func (a *AwsCloudUsecase) createRouteTables(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	nextToken := ""
	routeTableExits := make([]ec2Types.RouteTable, 0)
	for {
		describeRouteTablesInput := &ec2.DescribeRouteTablesInput{
			Filters: []ec2Types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
				{Name: aws.String("association.main"), Values: []string{"false"}},
				{Name: aws.String("route.state"), Values: []string{"active"}},
			},
			MaxResults: aws.Int32(100),
		}
		if nextToken != "" {
			describeRouteTablesInput.NextToken = aws.String(nextToken)
		}
		routeTableRes, err := a.ec2Client.DescribeRouteTables(ctx, describeRouteTablesInput)
		if err != nil {
			return errors.Wrap(err, "failed to describe route tables")
		}
		routeTableExits = append(routeTableExits, routeTableRes.RouteTables...)
		if aws.ToString(routeTableRes.NextToken) == "" {
			break
		}
		nextToken = aws.ToString(routeTableRes.NextToken)
	}

	// Check existing route tables
	for _, routeTableResource := range cluster.GetCloudResource(ResourceType_ROUTE_TABLE) {
		routeTableResourceExits := false
		for _, routeTable := range routeTableExits {
			if aws.ToString(routeTable.RouteTableId) == routeTableResource.RefId {
				routeTableResourceExits = true
				break
			}
		}
		if !routeTableResourceExits {
			cluster.DeleteCloudResourceByRefID(ResourceType_ROUTE_TABLE, routeTableResource.RefId)
		}
	}

	// Create private route tables (one per AZ)
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		if cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, map[ResourceTypeKeyValue]any{ResourceTypeKeyValue_ZONE_ID: az.Name}) != nil {
			continue
		}
		routeTableName := cluster.GetRouteTableName(az.Name)
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = routeTableName
		tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
		tags[ResourceTypeKeyValue_ZONE_ID] = az.Name
		// Create private route table
		routeTable, err := a.ec2Client.CreateRouteTable(ctx, &ec2.CreateRouteTableInput{
			VpcId: aws.String(vpc.RefId),
			TagSpecifications: []ec2Types.TagSpecification{
				{
					ResourceType: ec2Types.ResourceTypeRouteTable,
					Tags:         a.mapToEc2Tags(tags),
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "failed to create public route table")
		}
		cluster.AddCloudResource(&CloudResource{
			Name:  routeTableName,
			RefId: aws.ToString(routeTable.RouteTable.RouteTableId),
			Tags:  cluster.EncodeTags(tags),
			Type:  ResourceType_ROUTE_TABLE,
		})
		a.log.Infof("private route table %s createing for AZ %s", routeTableName, az.Name)
	}

	routeTables := cluster.GetCloudResourceByTags(ResourceType_ROUTE_TABLE, map[ResourceTypeKeyValue]any{
		ResourceTypeKeyValue_ACCESS: ResourceTypeKeyValue_ACCESS_PRIVATE,
	})

	// Associate private subnets with private route table
	for _, routeTable := range routeTables {
		subnetIds := make([]string, 0)
		for _, v := range routeTableExits {
			for _, vv := range v.Associations {
				subnetIds = append(subnetIds, aws.ToString(vv.SubnetId))
			}
		}
		routeTableTags := cluster.DecodeTags(routeTable.Tags)
		privateSubnet := cluster.GetCloudResourceByTagsSingle(ResourceType_SUBNET, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ACCESS:  ResourceTypeKeyValue_ACCESS_PRIVATE,
			ResourceTypeKeyValue_ZONE_ID: routeTableTags[ResourceTypeKeyValue_ZONE_ID],
		})
		if utils.InArray(privateSubnet.RefId, subnetIds) {
			continue
		}
		_, err := a.ec2Client.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{
			RouteTableId: aws.String(routeTable.RefId),
			SubnetId:     aws.String(privateSubnet.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to associate private subnet with route table in AZ ")
		}
		routeTable.Value = privateSubnet.RefId
	}

	// Add route to NAT Gateway in private route table
	for _, routeTable := range routeTables {
		natgatewayIds := make([]string, 0)
		for _, v := range routeTableExits {
			for _, vv := range v.Routes {
				natgatewayIds = append(natgatewayIds, aws.ToString(vv.NatGatewayId))
			}
		}
		routeTableTags := cluster.DecodeTags(routeTable.Tags)
		natGateway := cluster.GetCloudResourceByTagsSingle(ResourceType_NAT_GATEWAY, map[ResourceTypeKeyValue]any{
			ResourceTypeKeyValue_ZONE_ID: routeTableTags[ResourceTypeKeyValue_ZONE_ID],
		})
		if natGateway == nil {
			return errors.New("nat gateway not found in route table tags")
		}
		if utils.InArray(natGateway.RefId, natgatewayIds) {
			continue
		}
		_, err := a.ec2Client.CreateRoute(ctx, &ec2.CreateRouteInput{
			RouteTableId:         aws.String(routeTable.RefId),
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			NatGatewayId:         aws.String(natGateway.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add route to NAT Gateway for AZ")
		}
		routeTable.AssociatedId = natGateway.RefId
	}
	return nil
}

func (a *AwsCloudUsecase) ManageSecurityGroup(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	sgName := cluster.GetSecurityGroupName()
	securityGroupRes, err := a.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpc.RefId}},
			{Name: aws.String("group-name"), Values: []string{sgName}},
		},
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe security groups")
	}
	if len(securityGroupRes.SecurityGroups) == 0 && cluster.GetSingleCloudResource(ResourceType_SECURITY_GROUP) != nil {
		cluster.DeleteCloudResource(ResourceType_SECURITY_GROUP)
	}

	// Process existing security groups
	for _, securityGroup := range securityGroupRes.SecurityGroups {
		if cluster.GetCloudResourceByRefID(ResourceType_SECURITY_GROUP, aws.ToString(securityGroup.GroupId)) != nil {
			a.log.Infof("security group %s already exists", aws.ToString(securityGroup.GroupId))
			continue
		}
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = aws.ToString(securityGroup.GroupName)
		cluster.AddCloudResource(&CloudResource{
			Name:         aws.ToString(securityGroup.GroupName),
			RefId:        aws.ToString(securityGroup.GroupId),
			Tags:         cluster.EncodeTags(tags),
			AssociatedId: vpc.RefId,
			Type:         ResourceType_SECURITY_GROUP,
		})
		a.log.Infof("security group %s already exists", aws.ToString(securityGroup.GroupId))
	}

	sgCloudResource := cluster.GetCloudResourceByName(ResourceType_SECURITY_GROUP, sgName)
	if sgCloudResource == nil {
		// Create security group
		tags := GetTags()
		tags[ResourceTypeKeyValue_NAME] = sgName
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
		sgCloudResource = &CloudResource{
			Name:         sgName,
			RefId:        aws.ToString(sgOutput.GroupId),
			Tags:         cluster.EncodeTags(tags),
			Type:         ResourceType_SECURITY_GROUP,
			AssociatedId: vpc.RefId,
		}
		cluster.AddCloudResource(sgCloudResource)
		a.log.Infof("security group %s created", aws.ToString(sgOutput.GroupId))
	}

	// Add security group rules
	sgRuleRes, err := a.ec2Client.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
		Filters: []ec2Types.Filter{
			{Name: aws.String("group-id"), Values: []string{sgCloudResource.RefId}},
		},
		MaxResults: aws.Int32(500),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe security group rules")
	}
	// clear not exits rules
	exitsRules := make([]string, 0)
	for _, sgRule := range sgRuleRes.SecurityGroupRules {
		if aws.ToBool(sgRule.IsEgress) {
			continue
		}
		exits := false
		for _, clusterSgRule := range cluster.IngressControllerRules {
			clusterSgRuelVals := strings.Join([]string{
				clusterSgRule.Protocol, clusterSgRule.IpCidr,
				fmt.Sprintf("%d/%d", clusterSgRule.StartPort, clusterSgRule.EndPort)},
				"-")
			portRange := fmt.Sprintf("%d/%d", aws.ToInt32(sgRule.FromPort), aws.ToInt32(sgRule.ToPort))
			sgRuleVals := strings.Join([]string{
				strings.ToUpper(aws.ToString(sgRule.IpProtocol)), aws.ToString(sgRule.CidrIpv4),
				portRange},
				"-")
			if clusterSgRuelVals == sgRuleVals {
				exits = true
				exitsRules = append(exitsRules, sgRuleVals)
				break
			}
		}
		if !exits {
			_, err = a.ec2Client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
				GroupId:    aws.String(sgCloudResource.RefId),
				GroupName:  aws.String(sgName),
				CidrIp:     sgRule.CidrIpv4,
				IpProtocol: sgRule.IpProtocol,
				FromPort:   sgRule.FromPort,
				ToPort:     sgRule.ToPort,
			})
			if err != nil {
				return errors.Wrap(err, "failed to revoke security group ingress")
			}
		}
	}

	// add new ingress rules
	for _, sgRule := range cluster.IngressControllerRules {
		sgRuelVals := strings.Join([]string{
			sgRule.Protocol, sgRule.IpCidr,
			fmt.Sprintf("%d/%d", sgRule.StartPort, sgRule.EndPort)},
			"-")
		if utils.InArray(sgRuelVals, exitsRules) {
			continue
		}
		_, err = a.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:    aws.String(sgCloudResource.RefId),
			GroupName:  aws.String(sgName),
			IpProtocol: aws.String(strings.ToLower(sgRule.Protocol)),
			FromPort:   aws.Int32(sgRule.StartPort),
			ToPort:     aws.Int32(sgRule.EndPort),
			CidrIp:     aws.String(sgRule.IpCidr),
		})
		if err != nil {
			return errors.Wrap(err, "failed to add inbound rules to security group")
		}
	}
	return nil
}

func (a *AwsCloudUsecase) ManageSLB(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}
	sg := cluster.GetSingleCloudResource(ResourceType_SECURITY_GROUP)
	subnetIds := make([]string, 0)
	subnets := cluster.GetCloudResource(ResourceType_SUBNET)
	for _, v := range subnets {
		subnetIds = append(subnetIds, v.RefId)
	}

	// Check if SLB already exists
	slbName := cluster.GetLoadBalancerName()
	loadBalancerRes, err := a.elbv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
		Names: []string{slbName},
	})
	if err != nil && !strings.Contains(err.Error(), AwsNotFound) {
		return errors.Wrap(err, "failed to describe load balancers")
	}
	zones := cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES)
	zoneNames := make([]string, 0)
	for _, v := range zones {
		zoneNames = append(zoneNames, v.Name)
	}
	for _, lb := range loadBalancerRes.LoadBalancers {
		subnetOk := false
		for _, zone := range lb.AvailabilityZones {
			if utils.InArray(aws.ToString(zone.ZoneName), zoneNames) {
				subnetOk = true
				break
			}
		}
		if !subnetOk {
			_, err = a.elbv2Client.DeleteLoadBalancer(ctx, &elasticloadbalancingv2.DeleteLoadBalancerInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if err != nil {
				return errors.Wrap(err, "failed to delete SLB")
			}
			continue
		}
		cluster.AddCloudResource(&CloudResource{
			Name:  aws.ToString(lb.LoadBalancerName),
			RefId: aws.ToString(lb.LoadBalancerArn),
			Type:  ResourceType_LOAD_BALANCER,
			Value: aws.ToString(lb.DNSName),
		})
		a.log.Infof("slb %s already exists", aws.ToString(lb.LoadBalancerName))
	}
	if len(cluster.GetCloudResource(ResourceType_LOAD_BALANCER)) == 0 {
		// Create SLB
		slbOutput, err := a.elbv2Client.CreateLoadBalancer(ctx, &elasticloadbalancingv2.CreateLoadBalancerInput{
			Name:           aws.String(slbName),
			IpAddressType:  elasticloadbalancingv2Types.IpAddressTypeIpv4,
			Scheme:         elasticloadbalancingv2Types.LoadBalancerSchemeEnumInternetFacing,
			Type:           elasticloadbalancingv2Types.LoadBalancerTypeEnumNetwork,
			SecurityGroups: []string{sg.RefId},
			Subnets:        subnetIds,
			Tags: a.mapToElbv2Tags(map[ResourceTypeKeyValue]any{
				ResourceTypeKeyValue_NAME: slbName,
			}),
		})
		if err != nil || len(slbOutput.LoadBalancers) == 0 {
			return errors.Wrap(err, "failed to create SLB")
		}
		a.log.Infof("slb %s created", slbName)
		cluster.AddCloudResource(&CloudResource{
			Name:  slbName,
			RefId: aws.ToString(slbOutput.LoadBalancers[0].LoadBalancerArn),
			Type:  ResourceType_LOAD_BALANCER,
			Value: aws.ToString(slbOutput.LoadBalancers[0].DNSName),
		})
	}

	slbCloudResource := cluster.GetSingleCloudResource(ResourceType_LOAD_BALANCER)
	if slbCloudResource == nil {
		return errors.New("slb not found")
	}

	// handler listener
	targetGroupRes, err := a.elbv2Client.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: aws.String(slbCloudResource.RefId),
		PageSize:        aws.Int32(100),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe target groups")
	}
	ports := make([]int32, 0)
	for _, v := range cluster.IngressControllerRules {
		if v.Access != IngressControllerRuleAccess_PUBLIC {
			continue
		}
		for port := v.StartPort; port <= v.EndPort; port++ {
			ports = append(ports, port)
		}
	}
	// clear not exits target group
	for _, targetGroup := range targetGroupRes.TargetGroups {
		if utils.InArrayInt32(aws.ToInt32(targetGroup.Port), ports) {
			continue
		}
		_, err := a.elbv2Client.DeleteTargetGroup(ctx, &elasticloadbalancingv2.DeleteTargetGroupInput{
			TargetGroupArn: targetGroup.TargetGroupArn,
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete target group")
		}
	}

	listenerRes, err := a.elbv2Client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(slbCloudResource.RefId),
	})
	if err != nil {
		return errors.Wrap(err, "failed to describe listeners")
	}
	// clear not exits listener
	for _, listener := range listenerRes.Listeners {
		if utils.InArrayInt32(aws.ToInt32(listener.Port), ports) {
			continue
		}
		_, err := a.elbv2Client.DeleteListener(ctx, &elasticloadbalancingv2.DeleteListenerInput{
			ListenerArn: listener.ListenerArn,
		})
		if err != nil {
			return errors.Wrap(err, "failed to delete listener")
		}
	}

	for _, port := range ports {
		// Create target group
		targetGroupRes, err := a.elbv2Client.CreateTargetGroup(ctx, &elasticloadbalancingv2.CreateTargetGroupInput{
			Name:                       aws.String(fmt.Sprintf("tpc-%d", port)),
			TargetType:                 elasticloadbalancingv2Types.TargetTypeEnumInstance,
			Port:                       aws.Int32(port),
			HealthCheckPort:            aws.String(string(port)),
			Protocol:                   elasticloadbalancingv2Types.ProtocolEnumTcp,
			HealthCheckProtocol:        elasticloadbalancingv2Types.ProtocolEnumTcp,
			HealthCheckPath:            aws.String("/"),
			HealthCheckIntervalSeconds: aws.Int32(30),
			VpcId:                      aws.String(vpc.RefId),
		})
		if err != nil {
			return errors.Wrap(err, "failed to create target group")
		}
		if len(targetGroupRes.TargetGroups) == 0 {
			return errors.New("target group not found")
		}
		instanceTargets := make([]elasticloadbalancingv2Types.TargetDescription, 0)
		for _, node := range cluster.Nodes {
			if node.Role != NodeRole_MASTER || node.InstanceId == "" {
				continue
			}
			instanceTargets = append(instanceTargets, elasticloadbalancingv2Types.TargetDescription{
				Id:   aws.String(node.InstanceId),
				Port: aws.Int32(port),
			})
		}
		_, err = a.elbv2Client.RegisterTargets(ctx, &elasticloadbalancingv2.RegisterTargetsInput{
			TargetGroupArn: targetGroupRes.TargetGroups[0].TargetGroupArn,
			Targets:        instanceTargets,
		})
		if err != nil {
			return errors.Wrap(err, "failed to register targets")
		}
		// create listener
		_, err = a.elbv2Client.CreateListener(ctx, &elasticloadbalancingv2.CreateListenerInput{
			DefaultActions: []elasticloadbalancingv2Types.Action{
				{
					Type:           elasticloadbalancingv2Types.ActionTypeEnumForward,
					TargetGroupArn: targetGroupRes.TargetGroups[0].TargetGroupArn,
				},
			},
			LoadBalancerArn: aws.String(slbCloudResource.RefId),
			Port:            aws.Int32(port),
			Protocol:        elasticloadbalancingv2Types.ProtocolEnumTcp,
		})
		if err != nil {
			return errors.Wrap(err, "filled to create listener")
		}
	}
	return nil
}

var NodeArchToAwsIMagecloudType = map[NodeArchType]string{
	NodeArchType_NodeArchType_UNSPECIFIED: "x86_64",
	NodeArchType_AMD64:                    "x86_64",
	NodeArchType_ARM64:                    "arm64",
}

func (a *AwsCloudUsecase) FindImage(ctx context.Context, arch NodeArchType) (ec2Types.Image, error) {
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

func awsGenerateInstanceSize(cpu int32) string {
	if cpu == 1 {
		return "medium"
	}
	if cpu > 1 && cpu <= 2 {
		return "large"
	}
	if cpu > 2 && cpu <= 4 {
		return "xlarge"
	}
	size := ""
	if cpu >= 4 {
		if cpu%4 != 0 {
			cpu = (cpu/4 + 1) * 4
			fmt.Println(cpu)
		}
		size = fmt.Sprintf("%dxlarge", cpu/4)
	}
	return size
}

// https://aws.amazon.com/cn/ec2/instance-types/
func awsGetInstanceTypes(nodeGroupType NodeGroupType, instanceSize string) []ec2Types.InstanceType {
	instanceTypes := make([]string, 0)
	if nodeGroupType == NodeGroupType_NORMAL {
		instanceTypes = []string{
			fmt.Sprintf("m4.%s", instanceSize),
			fmt.Sprintf("m5a.%s", instanceSize),
			fmt.Sprintf("m5zn.%s", instanceSize),
			fmt.Sprintf("m5n.%s", instanceSize),
			fmt.Sprintf("m5.%s", instanceSize),
			fmt.Sprintf("m6a.%s", instanceSize),
			fmt.Sprintf("m6in.%s", instanceSize),
			fmt.Sprintf("m6i.%s", instanceSize),
			fmt.Sprintf("m6g.%s", instanceSize),
			fmt.Sprintf("m7a.%s", instanceSize),
			fmt.Sprintf("m7i-flex.%s", instanceSize),
			fmt.Sprintf("m7i.%s", instanceSize),
			fmt.Sprintf("m7g.%s", instanceSize),
			fmt.Sprintf("m8g.%s", instanceSize),
		}
	}
	if nodeGroupType == NodeGroupType_HIGH_COMPUTATION {
		instanceTypes = []string{
			fmt.Sprintf("c8g.%s", instanceSize),
			fmt.Sprintf("c7g.%s", instanceSize),
			fmt.Sprintf("c7gn.%s", instanceSize),
			fmt.Sprintf("c7i.%s", instanceSize),
			fmt.Sprintf("c7i-flex.%s", instanceSize),
			fmt.Sprintf("c7a.%s", instanceSize),
			fmt.Sprintf("c6g.%s", instanceSize),
			fmt.Sprintf("c6gn.%s", instanceSize),
			fmt.Sprintf("c6i.%s", instanceSize),
			fmt.Sprintf("c6in.%s", instanceSize),
			fmt.Sprintf("c6a.%s", instanceSize),
			fmt.Sprintf("c5.%s", instanceSize),
			fmt.Sprintf("c5n.%s", instanceSize),
			fmt.Sprintf("c5a.%s", instanceSize),
			fmt.Sprintf("c4.%s", instanceSize),
		}
	}
	if nodeGroupType == NodeGroupType_HIGH_MEMORY {
		instanceTypes = []string{
			fmt.Sprintf("r4.%s", instanceSize),
			fmt.Sprintf("r5a.%s", instanceSize),
			fmt.Sprintf("r5n.%s", instanceSize),
			fmt.Sprintf("r5.%s", instanceSize),
			fmt.Sprintf("r6a.%s", instanceSize),
			fmt.Sprintf("r6in.%s", instanceSize),
			fmt.Sprintf("r6i.%s", instanceSize),
			fmt.Sprintf("r6g.%s", instanceSize),
			fmt.Sprintf("r7a.%s", instanceSize),
			fmt.Sprintf("r7iz.%s", instanceSize),
			fmt.Sprintf("r7i.%s", instanceSize),
			fmt.Sprintf("r7g.%s", instanceSize),
			fmt.Sprintf("r8g.%s", instanceSize),
		}
	}
	if nodeGroupType == NodeGroupType_LARGE_HARD_DISK {
		// Big local disk
		instanceTypes = []string{
			fmt.Sprintf("h1.%s", instanceSize),
			fmt.Sprintf("d2.%s", instanceSize),
			fmt.Sprintf("d3en.%s", instanceSize),
			fmt.Sprintf("d3.%s", instanceSize),
		}
	}
	if nodeGroupType == NodeGroupType_LOAD_DISK {
		// Samll local disk
		instanceTypes = []string{
			fmt.Sprintf("i3en.%s", instanceSize),
			fmt.Sprintf("i3.%s", instanceSize),
			fmt.Sprintf("i4i.%s", instanceSize),
			fmt.Sprintf("is4gen.%s", instanceSize),
			fmt.Sprintf("im4gn.%s", instanceSize),
			fmt.Sprintf("i4g.%s", instanceSize),
			fmt.Sprintf("i7ie.%s", instanceSize),
			fmt.Sprintf("i8g.%s", instanceSize),
		}
	}
	if nodeGroupType == NodeGroupType_GPU_ACCELERATERD {
		instanceTypes = []string{
			fmt.Sprintf("g3s.%s", instanceSize),
			fmt.Sprintf("g4ad.%s", instanceSize),
			fmt.Sprintf("g4dn.%s", instanceSize),
			fmt.Sprintf("g5.%s", instanceSize),
			fmt.Sprintf("g5g.%s", instanceSize),
			fmt.Sprintf("g6.%s", instanceSize),
			fmt.Sprintf("g6e.%s", instanceSize),
			fmt.Sprintf("p2.%s", instanceSize),
			fmt.Sprintf("p3.%s", instanceSize),
			fmt.Sprintf("p4.%s", instanceSize),
			fmt.Sprintf("p5.%s", instanceSize),
		}
	}
	instanceType := new(ec2Types.InstanceType)
	data := make([]ec2Types.InstanceType, 0)
	for _, v := range instanceTypes {
		for _, realInstanceType := range instanceType.Values() {
			if v == string(realInstanceType) {
				data = append(data, realInstanceType)
				break
			}
		}
	}
	return data
}

func (a *AwsCloudUsecase) FindInstanceType(ctx context.Context, findInstanceTypeParam FindInstanceTypeParam) ([]ec2Types.InstanceTypeInfo, error) {
	instanceTypes := awsGetInstanceTypes(findInstanceTypeParam.NodeGroupType, awsGenerateInstanceSize(findInstanceTypeParam.CPU))
	instanceTypeInfos := make([]ec2Types.InstanceTypeInfo, 0)
	instanceTypeInput := &ec2.DescribeInstanceTypesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("processor-info.supported-architecture"),
				Values: []string{NodeArchToAwsIMagecloudType[findInstanceTypeParam.Arch]},
			},
			{
				Name:   aws.String("vcpu-info.default-vcpus"),
				Values: []string{fmt.Sprintf("%d", findInstanceTypeParam.CPU)},
			},
		},
		InstanceTypes: instanceTypes,
	}
	for {
		instanceTypes, err := a.ec2Client.DescribeInstanceTypes(ctx, instanceTypeInput)
		if err != nil {
			return nil, errors.Wrap(err, "failed to describe instance types")
		}
		for _, v := range instanceTypes.InstanceTypes {
			if findInstanceTypeParam.GPU > 0 {
				for _, gpuInfo := range v.GpuInfo.Gpus {
					if aws.ToInt32(gpuInfo.Count) == findInstanceTypeParam.GPU {
						if findInstanceTypeParam.GPUSpec.String() != "" {
							gpuSpecArr := strings.Split(findInstanceTypeParam.GPUSpec.String(), "_")
							if len(gpuSpecArr) < 2 {
								continue
							}
							if !strings.Contains(strings.ToUpper(aws.ToString(gpuInfo.Name)), gpuSpecArr[len(gpuSpecArr)-1]) {
								continue
							}
						}
						instanceTypeInfos = append(instanceTypeInfos, v)
						break
					}
				}
				continue
			}
			instanceTypeInfos = append(instanceTypeInfos, v)
		}
		if instanceTypes.NextToken == nil {
			break
		}
		instanceTypeInput.NextToken = instanceTypes.NextToken
	}
	return instanceTypeInfos, nil
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

func DetermineUsername(amiName, amiDescription string) string {
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
