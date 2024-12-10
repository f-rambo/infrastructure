package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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
)

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
		resource.Id = uuid.New().String()
	}
	c.CloudResources = append(c.CloudResources, resource)
}

func (c *Cluster) AddSubCloudResource(resourceType ResourceType, parentID string, resource *CloudResource) {
	cloudResource := c.GetCloudResourceByID(resourceType, parentID)
	if cloudResource == nil {
		return
	}
	if cloudResource.SubResources == nil {
		cloudResource.SubResources = make([]*CloudResource, 0)
	}
	resource.Type = resourceType
	if resource.Id == "" {
		resource.Id = uuid.New().String()
	}
	cloudResource.SubResources = append(cloudResource.SubResources, resource)
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
		if len(resource.SubResources) > 0 {
			subResource := getCloudResourceByID(resource.SubResources, id)
			if subResource != nil {
				return subResource
			}
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
	index := -1
	for i, resources := range c.CloudResources {
		if resources.Type == resourceType && resources.Id == id {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}
	cloudResources = append(cloudResources, c.CloudResources[:index]...)
	cloudResources = append(cloudResources, c.CloudResources[index+1:]...)
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and refID
func (c *Cluster) DeleteCloudResourceByRefID(resourceType ResourceType, refID string) {
	cloudResources := make([]*CloudResource, 0)
	index := -1
	for i, resources := range c.CloudResources {
		if resources.Type == resourceType && resources.RefId != refID {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}
	cloudResources = append(cloudResources, c.CloudResources[:index]...)
	cloudResources = append(cloudResources, c.CloudResources[index+1:]...)
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

func (c *Cluster) GenerateNodeGroupName(nodeGroup *NodeGroup) {
	nodeGroup.Name = strings.Join([]string{
		c.Name,
		nodeGroup.Type.String(),
		nodeGroup.Os,
		nodeGroup.Arch,
		cast.ToString(nodeGroup.Cpu),
		cast.ToString(nodeGroup.Memory),
		cast.ToString(nodeGroup.Gpu),
		cast.ToString(nodeGroup.GpuSpec),
	}, "-")
}

func (c ClusterType) IsCloud() bool {
	return c != ClusterType_LOCAL
}

func (c ClusterType) IsIntegratedCloud() bool {
	return c == ClusterType_AWS_EKS || c == ClusterType_ALICLOUD_AKS
}

func (ng *NodeGroup) SetTargetSize(size int32) {
	ng.TargetSize = size
}

type NodeGroups []*NodeGroup

func (n NodeGroups) Len() int {
	return len(n)
}

func (n NodeGroups) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func (n NodeGroups) Less(i, j int) bool {
	if n[i] == nil || n[j] == nil {
		return false
	}
	if n[i].Memory == n[j].Memory {
		return n[i].Cpu < n[j].Cpu
	}
	return n[i].Memory < n[j].Memory
}

func (c *Cluster) GetNodeGroup(nodeGroupId string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.Id == nodeGroupId {
			return nodeGroup
		}
	}
	return nil
}

func (c *Cluster) GetNodeGroupByCloudId(cloudNodeGroupId string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.CloudNodeGroupId == cloudNodeGroupId {
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

func (c *Cluster) DistributeNodePrivateSubnets(nodeIndex int) string {
	tags := GetTags()
	tags[ResourceTypeKeyValue_ACCESS] = ResourceTypeKeyValue_ACCESS_PRIVATE
	subnets := c.GetCloudResourceByTags(ResourceType_SUBNET, tags)
	if len(subnets) == 0 {
		return ""
	}
	nodeSize := len(c.Nodes)
	subnetsSize := len(subnets)
	if nodeSize <= subnetsSize {
		return subnets[nodeIndex%subnetsSize].RefId
	}
	interval := nodeSize / subnetsSize
	return subnets[(nodeIndex/interval)%subnetsSize].RefId
}

// get zone id by subnet ref id
func (c *Cluster) GetZoneIDBySubnetRefID(subnetRefID string, zoneKey ResourceTypeKeyValue) string {
	for _, subnet := range c.GetCloudResource(ResourceType_SUBNET) {
		if subnet.RefId == subnetRefID {
			tagMaps := c.DecodeTags(subnet.Tags)
			if _, ok := tagMaps[zoneKey]; !ok {
				return ""
			}
			return cast.ToString(tagMaps[zoneKey])

		}
	}
	return ""
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

func (c *Cluster) MigrateToBostionHost(ctx context.Context) error {

	return nil
}

type ClusterUsecase struct {
	log *log.Helper
}

func NewClusterUsecase(logger log.Logger) *ClusterUsecase {
	return &ClusterUsecase{log: log.NewHelper(logger)}
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
	ServiceShell    string = "service.sh"
	SyncShell       string = "sync.sh"
	NodeInitShell   string = "nodeinit.sh"
	KubernetesShell string = "kubernetes.sh"
	SystemInfoShell string = "systeminfo.sh"

	ClusterConfiguration        string = "cluster.yaml"
	NormalNodeJoinConfiguration string = "nodejoin.yaml"
	MasterNodeJoinConfiguration string = "masterjoin.yaml"
)

func (c *ClusterUsecase) MigrateToBostionHost(ctx context.Context, cluster *Cluster) error {
	if cluster.BostionHost.User == "" {
		return errors.New("bostion host username is empty")
	}
	if cluster.BostionHost.ExternalIp == "" {
		return errors.New("bostion host external ip is empty")
	}
	remoteBash := utils.NewRemoteBash(utils.Server{
		Name:       "bostion-host",
		Host:       cluster.BostionHost.ExternalIp,
		User:       cluster.BostionHost.User,
		Port:       cluster.BostionHost.SshPort,
		PrivateKey: cluster.PrivateKey,
	}, c.log)
	stdout, err := remoteBash.Run("uname -m")
	if err != nil {
		return err
	}
	arch := strings.TrimSpace(stdout)
	if _, ok := ARCH_MAP[arch]; !ok {
		return errors.New("bostion host arch is not supported")
	}
	cluster.BostionHost.Arch = ARCH_MAP[arch]
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return err
	}
	resourcePath, err := utils.GetServerStorePathByNames(utils.ResourcePackage)
	if err != nil {
		return err
	}
	syncShellPath := utils.MergePath(shellPath, SyncShell)
	homePath, err := utils.GetServerStorePathByNames()
	if err != nil {
		return err
	}
	err = utils.NewBash(c.log).RunCommandWithLogging("sudo bash", syncShellPath,
		cluster.BostionHost.ExternalIp,
		cast.ToString(cluster.BostionHost.SshPort),
		cluster.BostionHost.User,
		cluster.PrivateKey,
		homePath,
		shellPath,
		resourcePath,
	)
	if err != nil {
		return err
	}
	serviceShellPath := utils.MergePath(shellPath, ServiceShell)
	err = remoteBash.RunWithLogging("bash", serviceShellPath, BostionHostEnv)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterUsecase) GetNodesSystemInfo(ctx context.Context, cluster *Cluster) error {
	errGroup, _ := errgroup.WithContext(ctx)
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return err
	}
	for _, node := range cluster.Nodes {
		if node.InternalIp == "" || node.User == "" {
			continue
		}
		nodegroup := &NodeGroup{ClusterId: cluster.Id, Id: uuid.New().String()}
		node := node
		errGroup.Go(func() error {
			remoteBash := utils.NewRemoteBash(
				utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
				c.log,
			)
			systemInfoOutput, err := remoteBash.Run("bash", utils.MergePath(shellPath, SystemInfoShell))
			if err != nil {
				return err
			}
			systemInfoMap := make(map[string]any)
			if err := json.Unmarshal([]byte(systemInfoOutput), &systemInfoMap); err != nil {
				return err
			}
			for key, val := range systemInfoMap {
				switch key {
				case "os":
					nodegroup.Os = cast.ToString(val)
				case "arch":
					nodegroup.Arch = cast.ToString(val)
				case "mem":
					nodegroup.Memory = cast.ToInt32(val)
				case "cpu":
					nodegroup.Cpu = cast.ToInt32(val)
				case "gpu":
					nodegroup.Gpu = cast.ToInt32(val)
				case "gpu_info":
					nodegroup.GpuSpec = cast.ToString(val)
				case "disk":
					nodegroup.DataDiskSize = cast.ToInt32(val)
				case "inner_ip":
					node.InternalIp = cast.ToString(val)
				}
			}
			cluster.GenerateNodeGroupName(nodegroup)
			exitsNodeGroup := cluster.GetNodeGroupByName(nodegroup.Name)
			if exitsNodeGroup == nil {
				cluster.NodeGroups = append(cluster.NodeGroups, nodegroup)
			} else {
				nodegroup.Id = exitsNodeGroup.Id
			}
			node.NodeGroupId = nodegroup.Id
			return nil
		})
	}
	err = errGroup.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterUsecase) Install(ctx context.Context, cluster *Cluster) error {
	remoteBash := utils.NewRemoteBash(
		utils.Server{Name: cluster.Name, Host: cluster.MasterIp, User: cluster.MasterUser, Port: 22, PrivateKey: cluster.PrivateKey},
		c.log,
	)
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return err
	}
	err = remoteBash.RunWithLogging("bash", utils.MergePath(shellPath, NodeInitShell))
	if err != nil {
		return err
	}
	configPath, err := utils.GetFromContextByKey(ctx, utils.ConfKey)
	if err != nil {
		return err
	}
	clusterConfigData, err := os.ReadFile(utils.MergePath(configPath, ClusterConfiguration))
	if err != nil {
		return err
	}
	clusterConfigMap := map[string]string{"CLUSTER_NAME": cluster.Name, "CLUSTER_VERSION": cluster.Version, "MASTER_IP": cluster.MasterIp, "IMAGE_REPO": ""}
	clusterConfigDataStr := utils.DecodeYaml(string(clusterConfigData), clusterConfigMap)
	clusterConfigPath := fmt.Sprintf("$HOME/%s", ClusterConfiguration)
	err = remoteBash.RunWithLogging("echo", clusterConfigDataStr, ">", clusterConfigPath)
	if err != nil {
		return err
	}
	errGroup, _ := errgroup.WithContext(ctx)
	errGroup.Go(func() error {
		err = remoteBash.RunWithLogging("kubeadm init --config", clusterConfigPath, "--v=5")
		if err != nil {
			remoteBash.RunWithLogging("kubeadm reset --force")
			return err
		}
		return nil
	})
	errGroup.Go(func() error {
		return c.restartKubelet(remoteBash)
	})
	err = errGroup.Wait()
	if err != nil {
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
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		err := c.uninstallNode(remoteBash)
		if err != nil {
			return err
		}
		node.Status = NodeStatus_NODE_DELETED
	}
	for _, node := range cluster.Nodes {
		if node.Role != NodeRole_WORKER {
			continue
		}
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		err := c.uninstallNode(remoteBash)
		if err != nil {
			return err
		}
		node.Status = NodeStatus_NODE_DELETED
	}
	return nil
}

func (c *ClusterUsecase) HandlerNodes(ctx context.Context, cluster *Cluster) error {
	for _, node := range cluster.Nodes {
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		if node.Status == NodeStatus_NODE_CREATING {
			joinShell := fmt.Sprintf("kubeadm join --token %s --discovery-token-ca-cert-hash sha256:%s --certificate-key %s",
				cluster.Token, cluster.CertData, cluster.KeyData)
			if node.Role == NodeRole_MASTER {
				joinShell += " --control-plane"
			}
			errGroup, _ := errgroup.WithContext(ctx)
			errGroup.Go(func() error {
				err := remoteBash.RunWithLogging(joinShell)
				if err != nil {
					remoteBash.RunWithLogging("kubeadm reset --force")
					return err
				}
				return nil
			})
			errGroup.Go(func() error {
				return c.restartKubelet(remoteBash)
			})
			err := errGroup.Wait()
			if err != nil {
				return err
			}
			node.Status = NodeStatus_NODE_RUNNING
		}
		if node.Status == NodeStatus_NODE_DELETING {
			err := c.uninstallNode(remoteBash)
			if err != nil {
				return err
			}
			node.Status = NodeStatus_NODE_DELETED
		}
	}
	return nil
}

func (c *ClusterUsecase) restartKubelet(remoteBash *utils.RemoteBash) error {
	for {
		err := remoteBash.RunWithLogging("systemctl disable kubelet && systemctl stop kubelet")
		if err != nil {
			return err
		}
		time.Sleep(time.Second * 10)
		output, err := remoteBash.Run("ll /etc/kubernetes/kubelet.conf | wc -l")
		if err != nil {
			return err
		}
		if cast.ToInt(output) == 0 {
			continue
		}
		err = remoteBash.RunWithLogging("systemctl enable kubelet && systemctl restart kubelet")
		if err != nil {
			return err
		}
		return nil
	}
}

func (cc *ClusterUsecase) uninstallNode(remoteBash *utils.RemoteBash) error {
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
