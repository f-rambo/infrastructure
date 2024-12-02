package biz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type GoogleCloudUsecase struct {
	containerClient *container.ClusterManagerClient
	computeService  *compute.Service
	log             *log.Helper
	projectID       string
}

func NewGoogleCloudUseCase(logger log.Logger) *GoogleCloudUsecase {
	c := &GoogleCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}

func (g *GoogleCloudUsecase) Connections(ctx context.Context, cluster *Cluster) error {
	var err error
	g.containerClient, err = container.NewClusterManagerClient(ctx,
		option.WithCredentialsFile("gcp-credentials.json"))
	if err != nil {
		return errors.Wrap(err, "failed to create container client")
	}

	g.computeService, err = compute.NewService(ctx, option.WithCredentialsFile("gcp-credentials.json"))
	if err != nil {
		return errors.Wrap(err, "failed to create compute service")
	}

	g.projectID = cluster.Name
	return nil
}

func (g *GoogleCloudUsecase) GetAvailabilityZones(ctx context.Context, cluster *Cluster) error {
	// List all zones in the project
	zoneList, err := g.computeService.Zones.List(g.projectID).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list zones")
	}

	// Filter zones by region
	var zones []string
	for _, zone := range zoneList.Items {
		// Google Cloud zone names are in the format "region-[a-z]"
		// Example: us-central1-a belongs to region us-central1
		if strings.HasPrefix(zone.Name, cluster.Region+"-") {
			zones = append(zones, zone.Name)
		}
	}

	if len(zones) == 0 {
		return fmt.Errorf("no availability zones found in region %s", cluster.Region)
	}

	// Sort zones for consistent ordering
	sort.Strings(zones)
	g.log.Infof("Found %d availability zones in region %s: %v", len(zones), cluster.Region, zones)
	for _, zone := range zones {
		cluster.AddCloudResource(&CloudResource{
			RefId: zone,
			Name:  zone,
			Type:  ResourceType_AVAILABILITY_ZONES,
			Value: cluster.Region,
		})
	}
	return nil
}

func (g *GoogleCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	funcs := []func(context.Context, *Cluster) error{
		g.createVPC,
		g.createSubnets,
		g.createNatGateways,
		g.createRouteTables,
		g.createSecurityGroup,
	}
	for _, f := range funcs {
		if err := f(ctx, cluster); err != nil {
			return err
		}
	}
	return nil
}

func (g *GoogleCloudUsecase) SetByNodeGroups(ctx context.Context, cluster *Cluster) error {
	// Get the latest COS (Container-Optimized OS) image
	image, err := g.computeService.Images.GetFromFamily("cos-cloud", "cos-stable").Do()
	if err != nil {
		return errors.Wrap(err, "failed to get COS image")
	}

	// Get available machine types
	machineTypes, err := g.computeService.MachineTypes.List(g.projectID, cluster.Region).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list machine types")
	}

	for _, ng := range cluster.NodeGroups {
		// Set image information
		ng.Os = "cos" // Container-Optimized OS
		ng.Image = image.Name
		ng.ImageDescription = image.Description
		ng.Arch = "x86_64"         // COS is x86_64 only
		ng.DefaultUsername = "cos" // COS uses "cos" as default user

		// Skip if instance type is already set
		if ng.InstanceType != "" {
			continue
		}

		// Find the best matching machine type based on CPU and memory requirements
		var bestMatch *compute.MachineType
		minDiff := int32(1<<31 - 1) // Max int32

		for _, mt := range machineTypes.Items {
			// Skip if CPU count doesn't match
			if ng.Cpu != 0 && mt.GuestCpus != int64(ng.Cpu) {
				continue
			}

			// Calculate memory difference (convert GB to MB for comparison)
			memoryGB := int32(mt.MemoryMb / 1024)
			memDiff := abs(memoryGB - ng.Memory)

			// Update best match if this is better
			if memDiff < minDiff {
				minDiff = memDiff
				bestMatch = mt
			}
		}

		if bestMatch == nil {
			return fmt.Errorf("no suitable machine type found for node group %s", ng.Name)
		}

		// Set instance type and resources
		ng.InstanceType = bestMatch.Name
		ng.Cpu = int32(bestMatch.GuestCpus)
		ng.Memory = int32(bestMatch.MemoryMb / 1024) // Convert MB to GB

		// GPU handling (if required)
		if ng.Gpu > 0 {
			// Get available GPU types
			acceleratorTypes, err := g.computeService.AcceleratorTypes.List(g.projectID, cluster.Region).Do()
			if err != nil {
				return errors.Wrap(err, "failed to list accelerator types")
			}

			// Find suitable GPU type (this is a simplified version)
			if len(acceleratorTypes.Items) > 0 {
				ng.GpuSpec = acceleratorTypes.Items[0].Name
			}
		}

		g.log.Infof("Selected machine type %s for node group %s", ng.InstanceType, ng.Name)
	}

	return nil
}

func abs(x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

func (g *GoogleCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (g *GoogleCloudUsecase) ManageKubernetesCluster(ctx context.Context, cluster *Cluster) error {
	// Check if cluster exists
	clusterPath := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", g.projectID, cluster.Region, cluster.Name)
	existingCluster, err := g.containerClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: clusterPath,
	})
	if err == nil {
		g.log.Infof("cluster %s already exists with status: %s", cluster.Name, existingCluster.Status)
		return nil
	}

	// Create node pools configuration
	var nodePools []*containerpb.NodePool
	for _, ng := range cluster.NodeGroups {
		nodePool := &containerpb.NodePool{
			Name: ng.Name,
			Config: &containerpb.NodeConfig{
				MachineType: ng.InstanceType,
				DiskSizeGb:  int32(ng.DataDiskSize),
				OauthScopes: []string{
					"https://www.googleapis.com/auth/devstorage.read_only",
					"https://www.googleapis.com/auth/logging.write",
					"https://www.googleapis.com/auth/monitoring",
					"https://www.googleapis.com/auth/servicecontrol",
					"https://www.googleapis.com/auth/service.management.readonly",
					"https://www.googleapis.com/auth/trace.append",
				},
			},
			InitialNodeCount: int32(ng.TargetSize),
			Autoscaling: &containerpb.NodePoolAutoscaling{
				Enabled:      true,
				MinNodeCount: int32(ng.MinSize),
				MaxNodeCount: int32(ng.MaxSize),
			},
			Management: &containerpb.NodeManagement{
				AutoUpgrade: true,
				AutoRepair:  true,
			},
		}
		nodePools = append(nodePools, nodePool)
	}

	// Get network resources
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	subnets := cluster.GetCloudResource(ResourceType_SUBNET)
	if len(subnets) == 0 {
		return errors.New("no subnets found for cluster")
	}

	// Create cluster request
	req := &containerpb.CreateClusterRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", g.projectID, cluster.Region),
		Cluster: &containerpb.Cluster{
			Name:        cluster.Name,
			Description: "Managed by infrastructure",
			Network:     vpc.RefId,
			Subnetwork:  subnets[0].RefId, // Using first subnet
			NodePools:   nodePools,
			// Use latest stable channel release
			ReleaseChannel: &containerpb.ReleaseChannel{
				Channel: containerpb.ReleaseChannel_STABLE,
			},
			// Enable Workload Identity for better security
			WorkloadIdentityConfig: &containerpb.WorkloadIdentityConfig{
				WorkloadPool: fmt.Sprintf("%s.svc.id.goog", g.projectID),
			},
			// Enable network policy for better security
			NetworkPolicy: &containerpb.NetworkPolicy{
				Enabled: true,
			},
			// Enable private cluster
			PrivateClusterConfig: &containerpb.PrivateClusterConfig{
				EnablePrivateNodes: true,
			},
			// Configure IP allocation policy
			IpAllocationPolicy: &containerpb.IPAllocationPolicy{
				UseIpAliases:     true,
				ClusterIpv4Cidr:  "10.4.0.0/14", // Pod IP range
				ServicesIpv4Cidr: "10.8.0.0/20", // Service IP range
			},
		},
	}

	// Create cluster
	_, err = g.containerClient.CreateCluster(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to create GKE cluster")
	}

	// Wait for the operation to complete
	// for {
	// 	resp, err := operation.Wait(ctx)
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to poll cluster creation status")
	// 	}
	// 	if resp.Done {
	// 		if resp.Failed() {
	// 			return errors.New(resp.Error().Error())
	// 		}
	// 		break
	// 	}
	// 	time.Sleep(30 * time.Second)
	// }

	g.log.Infof("kubernetes cluster %s created successfully", cluster.Name)
	return nil
}

func (g *GoogleCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (g *GoogleCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (g *GoogleCloudUsecase) createVPC(_ context.Context, cluster *Cluster) error {
	// Check if VPC already exists
	existingVpcs := cluster.GetCloudResource(ResourceType_VPC)
	if len(existingVpcs) > 0 {
		g.log.Infof("VPC %s already exists", existingVpcs[0].Name)
		return nil
	}

	// Create VPC network
	network := &compute.Network{
		Name:                  cluster.Name + "-vpc",
		AutoCreateSubnetworks: false, // Custom subnet mode
		RoutingConfig: &compute.NetworkRoutingConfig{
			RoutingMode: "REGIONAL", // Use regional routing for better performance
		},
		Mtu:         1460, // Standard MTU size
		Description: cluster.Name + " VPC",
	}

	operation, err := g.computeService.Networks.Insert(g.projectID, network).Do()
	if err != nil {
		return errors.Wrap(err, "failed to create VPC network")
	}

	// Wait for the operation to complete
	for {
		result, err := g.computeService.GlobalOperations.Get(g.projectID, operation.Name).Do()
		if err != nil {
			return errors.Wrap(err, "failed to get operation status")
		}

		if result.Status == "DONE" {
			if result.Error != nil {
				return errors.New(fmt.Sprintf("operation failed: %v", result.Error.Errors))
			}
			break
		}

		time.Sleep(5 * time.Second)
	}

	// Get the created network
	network, err = g.computeService.Networks.Get(g.projectID, network.Name).Do()
	if err != nil {
		return errors.Wrap(err, "failed to get created network")
	}

	// Create Cloud NAT for internet access from private instances
	router := &compute.Router{
		Name: cluster.Name + "-router",
		Nats: []*compute.RouterNat{
			{
				Name:                          cluster.Name + "-nat",
				NatIpAllocateOption:           "AUTO_ONLY",
				SourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
				MinPortsPerVm:                 64,
			},
		},
		Network: network.SelfLink,
	}

	// Create router in each zone
	for _, zone := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		region := zone.Name[:len(zone.Name)-2] // Remove zone suffix to get region
		operation, err = g.computeService.Routers.Insert(g.projectID, region, router).Do()
		if err != nil {
			return errors.Wrap(err, "failed to create router in "+region)
		}

		// Wait for router creation
		for {
			result, err := g.computeService.RegionOperations.Get(g.projectID, region, operation.Name).Do()
			if err != nil {
				return errors.Wrap(err, "failed to get router operation status")
			}

			if result.Status == "DONE" {
				if result.Error != nil {
					return errors.New(fmt.Sprintf("router operation failed: %v", result.Error.Errors))
				}
				break
			}

			time.Sleep(5 * time.Second)
		}
	}

	// Create firewall rules
	firewallRules := []*compute.Firewall{
		{
			Name:         cluster.Name + "-allow-internal",
			Network:      network.SelfLink,
			Description:  "Allow internal traffic",
			SourceRanges: []string{"10.0.0.0/8"},
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      []string{"0-65535"},
				},
				{
					IPProtocol: "udp",
					Ports:      []string{"0-65535"},
				},
				{
					IPProtocol: "icmp",
				},
			},
		},
		{
			Name:         cluster.Name + "-allow-ssh",
			Network:      network.SelfLink,
			Description:  "Allow SSH access",
			SourceRanges: []string{"0.0.0.0/0"},
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      []string{"22"},
				},
			},
			TargetTags: []string{"bastion"},
		},
	}

	// Create firewall rules
	for _, rule := range firewallRules {
		operation, err = g.computeService.Firewalls.Insert(g.projectID, rule).Do()
		if err != nil {
			return errors.Wrap(err, "failed to create firewall rule "+rule.Name)
		}

		// Wait for firewall rule creation
		for {
			result, err := g.computeService.GlobalOperations.Get(g.projectID, operation.Name).Do()
			if err != nil {
				return errors.Wrap(err, "failed to get firewall operation status")
			}

			if result.Status == "DONE" {
				if result.Error != nil {
					return errors.New(fmt.Sprintf("firewall operation failed: %v", result.Error.Errors))
				}
				break
			}

			time.Sleep(5 * time.Second)
		}
	}

	// Add VPC to resources
	cluster.AddCloudResource(&CloudResource{
		Name:  network.Name,
		RefId: network.SelfLink,
		Type:  ResourceType_VPC,
		// Tags:  cluster.EncodeTags(map[string]string{"Name": network.Name}),
	})

	g.log.Infof("VPC %s created successfully with ID %s", network.Name, network.Id)
	return nil
}

func (g *GoogleCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// List existing subnets
	// req := &compute.SubnetworksListRequest{
	// 	Project: g.projectID,
	// 	Region:  cluster.Region,
	// 	Filter:  fmt.Sprintf("network eq %s", vpc.RefId),
	// }

	subnetList, err := g.computeService.Subnetworks.List(g.projectID, cluster.Region).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list subnets")
	}

	// Check existing subnets
	existingSubnets := make(map[string]*compute.Subnetwork)
	for _, subnet := range subnetList.Items {
		existingSubnets[subnet.Name] = subnet
	}

	// Generate subnet CIDRs
	privateSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES)) * 2
	publicSubnetCount := len(cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES))
	subnetCidrs, err := utils.GenerateSubnets(cluster.IpCidr, privateSubnetCount+publicSubnetCount)
	if err != nil {
		return errors.Wrap(err, "failed to generate subnet CIDRs")
	}

	cidrIndex := 0
	// Create subnets for each zone
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		// Create private subnets
		for i := 0; i < 2; i++ {
			name := fmt.Sprintf("%s-private-subnet-%s-%d", cluster.Name, az.Name, i+1)
			if _, exists := existingSubnets[name]; exists {
				g.log.Infof("subnet %s already exists", name)
				continue
			}

			subnet := &compute.Subnetwork{
				Name:                  name,
				Network:               vpc.RefId,
				IpCidrRange:           subnetCidrs[cidrIndex],
				Region:                cluster.Region,
				PrivateIpGoogleAccess: true,
			}

			op, err := g.computeService.Subnetworks.Insert(g.projectID, cluster.Region, subnet).Do()
			if err != nil {
				return errors.Wrap(err, "failed to create private subnet")
			}

			err = g.waitForOperation(ctx, op)
			if err != nil {
				return err
			}

			cluster.AddCloudResource(&CloudResource{
				Name:  name,
				RefId: subnet.Name,
				Type:  ResourceType_SUBNET,
				// Tags: cluster.EncodeTags(map[string]string{
				// 	"Name": name,
				// 	"Type": "private",
				// 	"Zone": az.Name,
				// }),
			})
			g.log.Infof("private subnet %s created", name)
			cidrIndex++
		}

		// Create public subnet
		name := fmt.Sprintf("%s-public-subnet-%s", cluster.Name, az.Name)
		if _, exists := existingSubnets[name]; exists {
			g.log.Infof("subnet %s already exists", name)
			continue
		}

		subnet := &compute.Subnetwork{
			Name:        name,
			Network:     vpc.RefId,
			IpCidrRange: subnetCidrs[cidrIndex],
			Region:      cluster.Region,
		}

		op, err := g.computeService.Subnetworks.Insert(g.projectID, cluster.Region, subnet).Do()
		if err != nil {
			return errors.Wrap(err, "failed to create public subnet")
		}

		err = g.waitForOperation(ctx, op)
		if err != nil {
			return err
		}

		cluster.AddCloudResource(&CloudResource{
			Name:  name,
			RefId: subnet.Name,
			Type:  ResourceType_SUBNET,
			// Tags: cluster.EncodeTags(map[string]string{
			// 	"Name": name,
			// 	"Type": "public",
			// 	"Zone": az.Name,
			// }),
		})
		g.log.Infof("public subnet %s created", name)
		cidrIndex++
	}

	return nil
}

func (g *GoogleCloudUsecase) createNatGateways(ctx context.Context, cluster *Cluster) error {
	if cluster.Level == ClusterLevel_BASIC {
		return nil
	}

	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// List existing Cloud NAT gateways
	routers, err := g.computeService.Routers.List(g.projectID, cluster.Region).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list Cloud Routers")
	}

	// Check existing NAT gateways
	existingNATs := make(map[string]*compute.Router)
	for _, router := range routers.Items {
		if router.Network == vpc.RefId {
			existingNATs[router.Name] = router
		}
	}

	// Create Cloud NAT for each zone
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		routerName := fmt.Sprintf("%s-router-%s", cluster.Name, az.Name)
		natName := fmt.Sprintf("%s-nat-%s", cluster.Name, az.Name)

		if _, exists := existingNATs[routerName]; exists {
			g.log.Infof("Cloud Router %s already exists", routerName)
			continue
		}

		// Create Cloud Router
		router := &compute.Router{
			Name:    routerName,
			Network: vpc.RefId,
			Region:  cluster.Region,
			Nats: []*compute.RouterNat{
				{
					Name:                          natName,
					NatIpAllocateOption:           "AUTO_ONLY",
					SourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
					MinPortsPerVm:                 64,
				},
			},
		}

		op, err := g.computeService.Routers.Insert(g.projectID, cluster.Region, router).Do()
		if err != nil {
			return errors.Wrap(err, "failed to create Cloud Router and NAT")
		}

		err = g.waitForOperation(ctx, op)
		if err != nil {
			return err
		}

		cluster.AddCloudResource(&CloudResource{
			Name:  natName,
			RefId: natName,
			Type:  ResourceType_NAT_GATEWAY,
			// Tags: cluster.EncodeTags(map[string]string{
			// 	"Name": natName,
			// 	"Zone": az.Name,
			// }),
		})
		g.log.Infof("Cloud NAT %s created", natName)
	}

	return nil
}

func (g *GoogleCloudUsecase) createRouteTables(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// List existing routes
	routes, err := g.computeService.Routes.List(g.projectID).Filter(fmt.Sprintf("network eq %s", vpc.RefId)).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list routes")
	}

	// Check existing routes
	existingRoutes := make(map[string]*compute.Route)
	for _, route := range routes.Items {
		existingRoutes[route.Name] = route
	}

	// Create routes for private and public subnets
	for _, az := range cluster.GetCloudResource(ResourceType_AVAILABILITY_ZONES) {
		// Private route
		privateRouteName := fmt.Sprintf("%s-private-route-%s", cluster.Name, az.Name)
		if _, exists := existingRoutes[privateRouteName]; !exists {
			route := &compute.Route{
				Name:           privateRouteName,
				Network:        vpc.RefId,
				DestRange:      "0.0.0.0/0",
				Priority:       1000,
				NextHopGateway: fmt.Sprintf("projects/%s/global/gateways/default-internet-gateway", g.projectID),
			}

			op, err := g.computeService.Routes.Insert(g.projectID, route).Do()
			if err != nil {
				return errors.Wrap(err, "failed to create private route")
			}

			err = g.waitForOperation(ctx, op)
			if err != nil {
				return err
			}

			cluster.AddCloudResource(&CloudResource{
				Name:  privateRouteName,
				RefId: privateRouteName,
				Type:  ResourceType_ROUTE_TABLE,
				// Tags: cluster.EncodeTags(map[string]string{
				// 	"Name": privateRouteName,
				// 	"Type": "private",
				// 	"Zone": az.Name,
				// }),
			})
			g.log.Infof("private route %s created", privateRouteName)
		}

		// Public route
		publicRouteName := fmt.Sprintf("%s-public-route-%s", cluster.Name, az.Name)
		if _, exists := existingRoutes[publicRouteName]; !exists {
			route := &compute.Route{
				Name:           publicRouteName,
				Network:        vpc.RefId,
				DestRange:      "0.0.0.0/0",
				Priority:       1000,
				NextHopGateway: fmt.Sprintf("projects/%s/global/gateways/default-internet-gateway", g.projectID),
			}

			op, err := g.computeService.Routes.Insert(g.projectID, route).Do()
			if err != nil {
				return errors.Wrap(err, "failed to create public route")
			}

			err = g.waitForOperation(ctx, op)
			if err != nil {
				return err
			}

			cluster.AddCloudResource(&CloudResource{
				Name:  publicRouteName,
				RefId: publicRouteName,
				Type:  ResourceType_ROUTE_TABLE,
				// Tags: cluster.EncodeTags(map[string]string{
				// 	"Name": publicRouteName,
				// 	"Type": "public",
				// 	"Zone": az.Name,
				// }),
			})
			g.log.Infof("public route %s created", publicRouteName)
		}
	}

	return nil
}

func (g *GoogleCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	vpc := cluster.GetSingleCloudResource(ResourceType_VPC)
	if vpc == nil {
		return errors.New("vpc not found")
	}

	// List existing firewall rules
	firewalls, err := g.computeService.Firewalls.List(g.projectID).Filter(fmt.Sprintf("network eq %s", vpc.RefId)).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list firewall rules")
	}

	// Check existing firewall rules
	existingFirewalls := make(map[string]*compute.Firewall)
	for _, firewall := range firewalls.Items {
		existingFirewalls[firewall.Name] = firewall
	}

	// Create firewall rules for cluster
	firewallRules := []struct {
		name         string
		description  string
		allowed      []*compute.FirewallAllowed
		sourceRanges []string
	}{
		{
			name:        fmt.Sprintf("%s-allow-internal", cluster.Name),
			description: "Allow internal traffic",
			allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      []string{"0-65535"},
				},
				{
					IPProtocol: "udp",
					Ports:      []string{"0-65535"},
				},
				{
					IPProtocol: "icmp",
				},
			},
			sourceRanges: []string{cluster.IpCidr},
		},
		{
			name:        fmt.Sprintf("%s-allow-ssh", cluster.Name),
			description: "Allow SSH access",
			allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      []string{"22"},
				},
			},
			sourceRanges: []string{"0.0.0.0/0"},
		},
		{
			name:        fmt.Sprintf("%s-allow-https", cluster.Name),
			description: "Allow HTTPS access",
			allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      []string{"443"},
				},
			},
			sourceRanges: []string{"0.0.0.0/0"},
		},
	}

	for _, rule := range firewallRules {
		if _, exists := existingFirewalls[rule.name]; exists {
			g.log.Infof("firewall rule %s already exists", rule.name)
			continue
		}

		firewall := &compute.Firewall{
			Name:         rule.name,
			Description:  rule.description,
			Network:      vpc.RefId,
			Allowed:      rule.allowed,
			SourceRanges: rule.sourceRanges,
		}

		op, err := g.computeService.Firewalls.Insert(g.projectID, firewall).Do()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create firewall rule %s", rule.name))
		}

		err = g.waitForOperation(ctx, op)
		if err != nil {
			return err
		}

		cluster.AddCloudResource(&CloudResource{
			Name:  rule.name,
			RefId: rule.name,
			Type:  ResourceType_SECURITY_GROUP,
			// Tags: cluster.EncodeTags(map[string]string{
			// 	"Name": rule.name,
			// }),
		})
		g.log.Infof("firewall rule %s created", rule.name)
	}

	return nil
}

func (g *GoogleCloudUsecase) waitForOperation(_ context.Context, op *compute.Operation) error {
	for {
		result, err := g.computeService.GlobalOperations.Get(g.projectID, op.Name).Do()
		if err != nil {
			return fmt.Errorf("failed to get operation status: %v", err)
		}

		if result.Status == "DONE" {
			if result.Error != nil {
				return fmt.Errorf("operation failed: %v", result.Error)
			}
			return nil
		}

		time.Sleep(5 * time.Second)
	}
}
