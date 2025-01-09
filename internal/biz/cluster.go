package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"golang.org/x/sync/errgroup"
)

const (
	VpcCIDR     = "172.16.0.0/16"
	ServiceCIDR = "10.96.0.0/16"
	PodCIDR     = "10.244.0.0/16"

	DefaultBandwidth = 5
)

func (c *Cluster) RangeNodeIps(startIp, endIp string) []string {
	var result []string
	return result
}

func (c *Cluster) GetCloudResource(resourceType ResourceType) []*CloudResource {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources != nil && resources.Type == resourceType {
			cloudResources = append(cloudResources, resources)
		}
	}
	return cloudResources
}

func (c *Cluster) AddCloudResource(resource *CloudResource) {
	if resource == nil {
		return
	}
	if c.CloudResources == nil {
		c.CloudResources = make([]*CloudResource, 0)
	}
	if resource.Id == "" {
		resource.Id = uuid.NewString()
	}
	c.CloudResources = append(c.CloudResources, resource)
}

func (c *Cluster) GetCloudResourceByName(resourceType ResourceType, name string) *CloudResource {
	for _, resource := range c.CloudResources {
		if resource.Type == resourceType && resource.Name == name {
			return resource
		}
	}
	return nil
}

func (c *Cluster) GetCloudResourceByID(resourceType ResourceType, id string) *CloudResource {
	resource := getCloudResourceByID(c.GetCloudResource(resourceType), id)
	if resource != nil {
		return resource
	}
	return nil
}

func (c *Cluster) GetCloudResourceByRefID(resourceType ResourceType, refID string) *CloudResource {
	for _, resource := range c.CloudResources {
		if resource.Type == resourceType && resource.RefId == refID {
			return resource
		}
	}
	return nil
}

func getCloudResourceByID(cloudResources []*CloudResource, id string) *CloudResource {
	for _, resource := range cloudResources {
		if resource.Id == id {
			return resource
		}
	}
	return nil
}

func (c *Cluster) GetSingleCloudResource(resourceType ResourceType) *CloudResource {
	resources := c.GetCloudResource(resourceType)
	if len(resources) == 0 {
		return nil
	}
	return resources[0]
}

// getCloudResource by resourceType and tag value and tag key
func (c *Cluster) GetCloudResourceByTags(resourceType ResourceType, tagKeyValues map[ResourceTypeKeyValue]any) []*CloudResource {
	cloudResources := make([]*CloudResource, 0)
	for _, resource := range c.GetCloudResource(resourceType) {
		if resource.Tags == "" {
			continue
		}
		resourceTagsMap := c.DecodeTags(resource.Tags)
		match := true
		for key, value := range tagKeyValues {
			val, ok := resourceTagsMap[key]
			if !ok {
				match = false
				break
			}
			if resourceTypeKeyValue, ok := value.(ResourceTypeKeyValue); ok {
				if int32(resourceTypeKeyValue.Number()) != cast.ToInt32(val) {
					match = false
					break
				}
				continue
			}
			if cast.ToString(val) != cast.ToString(value) {
				match = false
				break
			}
		}
		if match {
			cloudResources = append(cloudResources, resource)
		}
	}
	if len(cloudResources) == 0 {
		return nil
	}
	return cloudResources
}

func (c *Cluster) GetCloudResourceByTagsSingle(resourceType ResourceType, tagKeyValues map[ResourceTypeKeyValue]any) *CloudResource {
	resources := c.GetCloudResourceByTags(resourceType, tagKeyValues)
	if len(resources) == 0 {
		return nil
	}
	return resources[0]
}

func (c *Cluster) EncodeTags(tags map[ResourceTypeKeyValue]any) string {
	if tags == nil {
		return ""
	}
	jsonBytes, _ := json.Marshal(tags)
	return string(jsonBytes)
}

func (c *Cluster) DecodeTags(tags string) map[ResourceTypeKeyValue]any {
	tagsMap := make(map[ResourceTypeKeyValue]any)
	if tags == "" {
		return tagsMap
	}
	json.Unmarshal([]byte(tags), &tagsMap)
	return tagsMap
}

// delete cloud resource by resourceType
func (c *Cluster) DeleteCloudResource(resourceType ResourceType) {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources.Type != resourceType {
			cloudResources = append(cloudResources, resources)
		}
	}
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and id
func (c *Cluster) DeleteCloudResourceByID(resourceType ResourceType, id string) {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources.Type == resourceType && resources.Id == id {
			continue
		}
		cloudResources = append(cloudResources, resources)
	}
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and refID
func (c *Cluster) DeleteCloudResourceByRefID(resourceType ResourceType, refID string) {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources.Type == resourceType && resources.RefId == refID {
			continue
		}
		cloudResources = append(cloudResources, resources)
	}
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and tag value and tag key
func (c *Cluster) DeleteCloudResourceByTags(resourceType ResourceType, tagKeyValues ...ResourceTypeKeyValue) {
	cloudResources := make([]*CloudResource, 0)
	for _, resource := range c.CloudResources {
		if resource.Tags == "" {
			cloudResources = append(cloudResources, resource)
			continue
		}
		if resource.Type != resourceType {
			cloudResources = append(cloudResources, resource)
			continue
		}
		match := true
		resourceTagsMap := c.DecodeTags(resource.Tags)
		for i := 0; i < len(tagKeyValues); i += 2 {
			tagKey := tagKeyValues[i]
			tagValue := tagKeyValues[i+1]
			if resourceTagsMap[tagKey] != tagValue {
				match = false
				break
			}
		}
		if match {
			continue
		}
		cloudResources = append(cloudResources, resource)
	}
	c.CloudResources = cloudResources
}

func (c *Cluster) EncodeNodeGroup(nodeGroup *NodeGroup) string {
	return strings.Join([]string{
		strings.ToUpper(nodeGroup.Os),
		strings.ToUpper(nodeGroup.Platform),
		nodeGroup.Arch.String(),
		fmt.Sprintf("%d-%d-%d", nodeGroup.Cpu, nodeGroup.Memory, nodeGroup.Gpu),
		nodeGroup.GpuSpec.String(),
	}, "-")
}

func (c *Cluster) DecodeNodeGroup(nodeGroup string) *NodeGroup {
	nodeGroupSlice := strings.Split(nodeGroup, "-")
	if len(nodeGroupSlice) != 5 {
		return nil
	}
	return &NodeGroup{
		Os:       strings.ToLower(nodeGroupSlice[0]),
		Platform: strings.ToLower(nodeGroupSlice[1]),
		Arch:     NodeArchType(NodeArchType_value[nodeGroupSlice[2]]),
		Cpu:      cast.ToInt32(nodeGroupSlice[3]),
		Memory:   cast.ToInt32(nodeGroupSlice[4]),
		Gpu:      cast.ToInt32(nodeGroupSlice[5]),
		GpuSpec:  NodeGPUSpec(NodeGPUSpec_value[nodeGroupSlice[6]]),
	}
}

func (c ClusterType) IsCloud() bool {
	return c != ClusterType_LOCAL
}

func (c *Cluster) GetNodeGroup(nodeGroupId string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.Id == nodeGroupId {
			return nodeGroup
		}
	}
	return nil
}

func (c *Cluster) GetNodeGroupByName(nodeGroupName string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.Name == nodeGroupName {
			return nodeGroup
		}
	}
	return nil
}

func (c *Cluster) DistributeNodePrivateSubnets(nodeIndex int) *CloudResource {
	tags := GetTags()
	tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
	subnets := c.GetCloudResourceByTags(ResourceType_SUBNET, tags)
	if len(subnets) == 0 {
		return nil
	}
	nodeSize := len(c.Nodes)
	subnetsSize := len(subnets)
	if nodeSize <= subnetsSize {
		return subnets[nodeIndex%subnetsSize]
	}
	interval := nodeSize / subnetsSize
	return subnets[(nodeIndex/interval)%subnetsSize]
}

func GetTags() map[ResourceTypeKeyValue]any {
	return make(map[ResourceTypeKeyValue]any)
}

func (c *Cluster) CreateCluster() bool {
	return c.Status == ClusterStatus_STARTING
}

func (c *Cluster) UpdateCluster() bool {
	return c.Status == ClusterStatus_RUNNING
}

func (c *Cluster) DeleteCluster() bool {
	return c.Status == ClusterStatus_STOPPING || c.Status == ClusterStatus_DELETED
}

func (g *NodeGroup) CreateOrUpdateNodeGroup() bool {
	return g.TargetSize > 0
}

func (g *NodeGroup) DeleteNodeGroup() bool {
	return g.TargetSize == 0
}

func (n *Node) CreateNode() bool {
	return n.Status == NodeStatus_NODE_CREATING
}

func (n *Node) UpdateNode() bool {
	return n.Status == NodeStatus_NODE_RUNNING || n.Status == NodeStatus_NODE_PENDING
}

func (n *Node) DeleteNode() bool {
	return n.Status == NodeStatus_NODE_DELETING || n.Status == NodeStatus_NODE_DELETED
}

func (c *Cluster) GetVpcName() string {
	return fmt.Sprintf("%s-vpc", c.Name)
}

func (c *Cluster) GetkeyPairName() string {
	return fmt.Sprintf("%s-keypair", c.Name)
}

func (c *Cluster) GetSubnetName(zoneId string) string {
	return fmt.Sprintf("%s-%s-subnet", c.Name, zoneId)
}

func (c *Cluster) GetEipName(zoneId string) string {
	return fmt.Sprintf("%s-%s-eip", c.Name, zoneId)
}

func (c *Cluster) GetNatgatewayName(zoneId string) string {
	return fmt.Sprintf("%s-%s-natgateway", c.Name, zoneId)
}

func (c *Cluster) GetSecurityGroupName() string {
	return fmt.Sprintf("%s-securitygroup", c.Name)
}

func (c *Cluster) GetRouteTableName(zoneId string) string {
	return fmt.Sprintf("%s-%s-route-table", c.Name, zoneId)
}

func (c *Cluster) GetPublicRouteTableName() string {
	return fmt.Sprintf("%s-public-route-table", c.Name)
}

func (c *Cluster) GetLoadBalancerName() string {
	return strings.ReplaceAll(fmt.Sprintf("%s-slb", c.Name), "_", "-")
}

type ClusterUsecase struct {
	log  *log.Helper
	conf *conf.Bootstrap
}

func NewClusterUsecase(conf *conf.Bootstrap, logger log.Logger) *ClusterUsecase {
	return &ClusterUsecase{conf: conf, log: log.NewHelper(logger)}
}

var ARCH_MAP = map[string]string{
	"x86_64":  "amd64",
	"aarch64": "arm64",
}

const (
	LocalEnv       = "local"
	BostionHostEnv = "bostionhost"
	ClusterEnv     = "cluster"
)

var (
	NodeInitShell   string = "nodeinit.sh"
	KubernetesShell string = "kubernetes.sh"
	SystemInfoShell string = "systeminfo.sh"

	ClusterConfiguration        string = "cluster.yaml"
	NormalNodeJoinConfiguration string = "nodejoin.yaml"
	MasterNodeJoinConfiguration string = "masterjoin.yaml"
)

func (c *ClusterUsecase) MigrateResources(ctx context.Context, cluster *Cluster) error {
	var bostionHost *Node
	var bostionHostIp string
	if !cluster.Type.IsCloud() {
		for _, node := range cluster.Nodes {
			if node.Role == NodeRole_MASTER {
				bostionHost = node
				bostionHostIp = node.Ip
				break
			}
		}
	}
	if cluster.Type.IsCloud() {
		slb := cluster.GetSingleCloudResource(ResourceType_LOAD_BALANCER)
		for _, node := range cluster.Nodes {
			if node.InstanceId == "" || node.Role != NodeRole_MASTER {
				continue
			}
			bostionHost = node
			bostionHostIp = slb.Value
			break
		}
	}
	if bostionHost == nil || bostionHostIp == "" {
		return errors.New("bostion host is not found")
	}
	tarFile, err := utils.DownloadFile(c.conf.Resource.GetUrl())
	if err != nil {
		return err
	}
	remoteTarfile := fmt.Sprintf("/tmp/%s", tarFile)
	remoteBash := utils.NewRemoteBash(utils.Server{Name: bostionHostIp, Host: bostionHostIp, User: bostionHost.User, Port: 22, PrivateKey: cluster.PrivateKey}, c.log)
	userHomePath, err := remoteBash.GetUserHome()
	if err != nil {
		return err
	}
	resourceFileShell := fmt.Sprintf("ls %s | wc -l", utils.MergePath(userHomePath, "resource"))
	fileNumber, err := remoteBash.Run(resourceFileShell)
	if err != nil {
		return err
	}
	if cast.ToInt(strings.TrimSpace(fileNumber)) > 0 {
		return nil
	}
	fileNumber, err = remoteBash.Run("ls", remoteTarfile, "| wc -l")
	if err != nil {
		return err
	}
	if cast.ToInt(strings.TrimSpace(fileNumber)) == 0 {
		err = remoteBash.SftpFile(tarFile, remoteTarfile)
		if err != nil {
			return err
		}
	}
	err = remoteBash.RunWithLogging("tar", "-C", userHomePath, "-zxvf", remoteTarfile)
	if err != nil {
		return err
	}
	return nil
}

var ArchMap = map[string]NodeArchType{
	"x86_64":  NodeArchType_AMD64,
	"aarch64": NodeArchType_ARM64,
}

var GPUSpecMap = map[string]NodeGPUSpec{
	"nvidia-a10":  NodeGPUSpec_NVIDIA_A10,
	"nvidia-v100": NodeGPUSpec_NVIDIA_V100,
	"nvidia-t4":   NodeGPUSpec_NVIDIA_T4,
	"nvidia-p100": NodeGPUSpec_NVIDIA_P100,
	"nvidia-p4":   NodeGPUSpec_NVIDIA_P4,
}

func (c *ClusterUsecase) GetNodesSystemInfo(ctx context.Context, cluster *Cluster) error {
	ips := cluster.RangeNodeIps(cluster.GetNodeStartIp(), cluster.GetNodeEndIp())
	errGroup, _ := errgroup.WithContext(ctx)
	errGroup.SetLimit(10)
	shellPath := utils.GetServerStoragePathByNames(utils.ShellPackage)
	nodeInforMaps := make([]map[string]string, 0)
	lock := new(sync.Mutex)
	for _, ip := range ips {
		nodeUser := cluster.NodeUser
		nodeIp := ip
		nodeOk := false
		for _, node := range cluster.Nodes {
			if node.Ip == nodeIp && node.Status != NodeStatus_NodeStatus_UNSPECIFIED {
				nodeOk = true
			}
		}
		if nodeOk {
			continue
		}
		errGroup.Go(func() error {
			nodeInfoMap := make(map[string]string)
			remoteBash := utils.NewRemoteBash(utils.Server{Name: nodeIp, Host: nodeIp, User: nodeUser, Port: 22, PrivateKey: cluster.PrivateKey}, c.log)
			userHomePath, err := remoteBash.GetUserHome()
			if err != nil {
				return err
			}
			_, err = remoteBash.Run("mkdir -p", utils.MergePath(userHomePath, shellPath))
			if err != nil {
				return err
			}
			err = remoteBash.SftpFile(utils.MergePath(shellPath, SystemInfoShell), utils.MergePath(userHomePath, shellPath, SystemInfoShell))
			if err != nil {
				return err
			}
			systemInfoOutput, err := remoteBash.Run("bash", utils.MergePath(userHomePath, shellPath, SystemInfoShell))
			if err != nil {
				// connection refused
				return nil
			}
			systemInfoMap := make(map[string]any)
			if err := json.Unmarshal([]byte(systemInfoOutput), &systemInfoMap); err != nil {
				return err
			}
			for key, val := range systemInfoMap {
				nodeInfoMap[key] = cast.ToString(val)
			}
			lock.Lock()
			nodeInforMaps = append(nodeInforMaps, nodeInfoMap)
			lock.Unlock()
			return nil
		})
	}
	err := errGroup.Wait()
	if err != nil {
		return err
	}
	nodeGroupMaps := make(map[string][]*Node)
	for _, m := range nodeInforMaps {
		nodegroup := &NodeGroup{}
		node := &Node{}
		for key, val := range m {
			switch key {
			case "os":
				nodegroup.Os = val
			case "arch":
				arch, ok := ArchMap[val]
				if !ok {
					arch = NodeArchType_NodeArchType_UNSPECIFIED
				}
				nodegroup.Arch = arch
			case "mem":
				nodegroup.Memory = cast.ToInt32(val)
			case "cpu":
				nodegroup.Cpu = cast.ToInt32(val)
			case "gpu":
				nodegroup.Gpu = cast.ToInt32(val)
			case "gpu_info":
				gpuSpec, ok := GPUSpecMap[val]
				if !ok {
					gpuSpec = NodeGPUSpec_NodeGPUSpec_UNSPECIFIED
				}
				nodegroup.GpuSpec = gpuSpec
			case "disk":
				node.SystemDiskSize = cast.ToInt32(val)
			case "ip":
				node.Ip = cast.ToString(val)
			}
		}
		nodeGroupMaps[cluster.EncodeNodeGroup(nodegroup)] = append(nodeGroupMaps[cluster.EncodeNodeGroup(nodegroup)], node)
	}
	for nodeGroupEncodeKey, nodes := range nodeGroupMaps {
		nodeGroupExits := false
		nodeGrpupId := ""
		for _, ng := range cluster.NodeGroups {
			if cluster.EncodeNodeGroup(ng) == nodeGroupEncodeKey {
				nodeGrpupId = ng.Id
				nodeGroupExits = true
				break
			}
		}
		if nodeGroupExits {
			for _, node := range nodes {
				nodeExits := false
				for _, n := range cluster.Nodes {
					if n.Ip == node.Ip {
						nodeExits = true
						break
					}
				}
				if !nodeExits {
					node.ClusterId = cluster.Id
					node.NodeGroupId = nodeGrpupId
					node.User = cluster.NodeUser
					node.Name = node.Ip
					cluster.Nodes = append(cluster.Nodes, node)
				}
			}
			continue
		}
		nodegroup := cluster.DecodeNodeGroup(nodeGroupEncodeKey)
		nodegroup.Id = uuid.NewString()
		for _, node := range nodes {
			node.ClusterId = cluster.Id
			node.NodeGroupId = nodegroup.Id
			node.User = cluster.NodeUser
			node.Name = node.Ip
		}
		cluster.NodeGroups = append(cluster.NodeGroups, nodegroup)
		cluster.Nodes = append(cluster.Nodes, nodes...)
	}
	return nil
}

func (c *ClusterUsecase) Install(ctx context.Context, cluster *Cluster) error {
	var firstMasterNodeUser string
	var firstMasterNodeIp string
	var firstMasterNodeName string
	for _, v := range cluster.Nodes {
		if v.Role == NodeRole_MASTER {
			firstMasterNodeUser = v.User
			firstMasterNodeIp = v.Ip
			firstMasterNodeName = v.Name
			break
		}
	}
	if firstMasterNodeUser == "" || firstMasterNodeName == "" {
		return errors.New("master node not found")
	}
	if cluster.Type.IsCloud() {
		slb := cluster.GetSingleCloudResource(ResourceType_LOAD_BALANCER)
		firstMasterNodeIp = slb.Value
	}
	remoteBash := utils.NewRemoteBash(
		utils.Server{Name: cluster.Name, Host: firstMasterNodeIp, User: firstMasterNodeUser, Port: 22, PrivateKey: cluster.PrivateKey},
		c.log,
	)
	userHomePath, err := remoteBash.GetUserHome()
	if err != nil {
		return err
	}
	shellPath := utils.GetServerStoragePathByNames(utils.ShellPackage)
	_, err = remoteBash.Run("mkdir", "-p", utils.MergePath(userHomePath, shellPath))
	if err != nil {
		return err
	}
	err = remoteBash.SftpFile(utils.MergePath(shellPath, NodeInitShell), utils.MergePath(userHomePath, shellPath, NodeInitShell))
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("bash", utils.MergePath(userHomePath, shellPath, NodeInitShell), firstMasterNodeName)
	if err != nil {
		return err
	}
	err = remoteBash.SftpFile(utils.MergePath(shellPath, KubernetesShell), utils.MergePath(userHomePath, shellPath, KubernetesShell))
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("bash", utils.MergePath(userHomePath, shellPath, KubernetesShell), utils.MergePath(userHomePath, "resource"))
	if err != nil {
		return err
	}
	clusterConfigPath := utils.MergePath(utils.GetFromContextByKey(ctx, utils.ConfDirKey), ClusterConfiguration)
	clusterConfigData, err := os.ReadFile(clusterConfigPath)
	if err != nil {
		return err
	}
	clusterConfigMap := map[string]string{
		"CLUSTER_NAME":       cluster.Name,
		"CLUSTER_VERSION":    cluster.Version,
		"API_SERVER_ADDRESS": cluster.ApiServerAddress,
		"IMAGE_REPO":         cluster.ImageRepo,
		"SERVICE_CIDR":       ServiceCIDR,
		"POD_CIDR":           PodCIDR,
	}
	cluster.Config = utils.DecodeYaml(string(clusterConfigData), clusterConfigMap)
	err = utils.WriteFile(shellPath, ClusterConfiguration, cluster.Config)
	if err != nil {
		return err
	}
	remoteClusterConfigPath := utils.MergePath(userHomePath, ClusterConfiguration)
	err = remoteBash.SftpFile(utils.MergePath(shellPath, ClusterConfiguration), remoteClusterConfigPath)
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("kubeadm init --config", remoteClusterConfigPath, "--v=5")
	if err != nil {
		remoteBash.RunWithLogging("kubeadm reset --force")
		return err
	}
	err = remoteBash.RunWithLogging("rm -f $HOME/.kube/config && mkdir -p $HOME/.kube && cp -i /etc/kubernetes/admin.conf $HOME/.kube/config && chown $(id -u):$(id -g) $HOME/.kube/config")
	if err != nil {
		return err
	}
	token, err := remoteBash.Run("kubeadm token create")
	if err != nil {
		return err
	}
	cluster.Token = token
	ca, err := remoteBash.Run("cat /etc/kubernetes/pki/ca.crt")
	if err != nil {
		return err
	}
	cluster.CaData = ca
	cert, err := remoteBash.Run("cat /etc/kubernetes/pki/apiserver.crt")
	if err != nil {
		return err
	}
	cluster.CertData = cert
	key, err := remoteBash.Run("cat /etc/kubernetes/pki/apiserver.key")
	if err != nil {
		return err
	}
	cluster.KeyData = key
	return nil
}

func (c *ClusterUsecase) UnInstall(ctx context.Context, cluster *Cluster) error {
	for _, node := range cluster.Nodes {
		if node.Role != NodeRole_WORKER {
			continue
		}
		err := c.uninstallNode(ctx, cluster, node)
		if err != nil {
			return err
		}
	}
	for _, node := range cluster.Nodes {
		if node.Role != NodeRole_WORKER {
			continue
		}
		err := c.uninstallNode(ctx, cluster, node)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ClusterUsecase) HandlerNodes(ctx context.Context, cluster *Cluster) error {
	for _, node := range cluster.Nodes {
		if node.Status == NodeStatus_NODE_CREATING {
			err := c.joinCluster(ctx, cluster, node)
			if err != nil {
				return err
			}
		}
		if node.Status == NodeStatus_NODE_DELETING {
			err := c.uninstallNode(ctx, cluster, node)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *ClusterUsecase) joinCluster(_ context.Context, cluster *Cluster, node *Node) error {
	remoteBash := utils.NewRemoteBash(utils.Server{Name: node.Name, Host: node.Ip, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey}, c.log)
	shellPath := utils.GetServerStoragePathByNames(utils.ShellPackage)
	err := remoteBash.RunWithLogging("bash", utils.MergePath(shellPath, NodeInitShell))
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("bash", utils.MergePath(shellPath, KubernetesShell), "$HOME/resource")
	if err != nil {
		return err
	}
	joinShell := fmt.Sprintf("kubeadm join --token %s --discovery-token-ca-cert-hash sha256:%s --certificate-key %s",
		cluster.Token, cluster.CertData, cluster.KeyData)
	if node.Role == NodeRole_MASTER {
		joinShell += " --control-plane"
	}
	err = remoteBash.RunWithLogging(joinShell)
	if err != nil {
		remoteBash.RunWithLogging("kubeadm reset --force")
		return err
	}
	return nil
}

func (c *ClusterUsecase) uninstallNode(_ context.Context, cluster *Cluster, node *Node) error {
	remoteBash := utils.NewRemoteBash(utils.Server{Name: node.Name, Host: node.Ip, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey}, c.log)
	err := remoteBash.RunWithLogging("kubeadm reset --force")
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("rm -rf $HOME/.kube && rm -rf /etc/kubernetes && rm -rf /etc/cni")
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("systemctl stop containerd && systemctl disable containerd && rm -rf /var/lib/containerd")
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("systemctl stop kubelet && systemctl disable kubelet")
	if err != nil {
		return err
	}
	return nil
}
