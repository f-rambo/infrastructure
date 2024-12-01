package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	clusterApi "github.com/f-rambo/cloud-copilot/infrastructure/api/cluster"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/spf13/cast"
	"golang.org/x/sync/errgroup"
)

var ARCH_MAP = map[string]string{
	"x86_64":  "amd64",
	"aarch64": "arm64",
}

const (
	Local       = "local"
	BostionHost = "bostionhost"
	Cluster     = "cluster"

	ServerPort = 9000
)

var (
	ServiceShell    string = "service.sh"
	SyncShell       string = "sync.sh"
	NodeInitShell   string = "nodeinit.sh"
	KubernetesShell string = "kubernetes.sh"
	systemInfoShell string = "systeminfo.sh"

	ClusterConfiguration        string = "cluster.yaml"
	NormalNodeJoinConfiguration string = "nodejoin.yaml"
	MasterNodeJoinConfiguration string = "masterjoin.yaml"
)

type ClusterInterface struct {
	clusterApi.UnimplementedClusterInterfaceServer
	awsUc *biz.AwsCloudUsecase
	gcpUc *biz.GoogleCloudUsecase
	aliUc *biz.AliCloudUsecase
	log   *log.Helper
	c     *conf.Server
}

func NewClusterInterface(awsUc *biz.AwsCloudUsecase, gcpUc *biz.GoogleCloudUsecase, aliUc *biz.AliCloudUsecase, logger log.Logger, c *conf.Server) *ClusterInterface {
	return &ClusterInterface{
		awsUc: awsUc,
		gcpUc: gcpUc,
		aliUc: aliUc,
		log:   log.NewHelper(logger),
		c:     c,
	}
}

func (c *ClusterInterface) Start(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	if cluster.Type.IsCloud() {
		return cluster, nil
	}
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS_EC2 {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.CreateNetwork,
			c.awsUc.SetByNodeGroups,
			c.awsUc.ImportKeyPair,
			c.awsUc.ManageInstance,
			c.awsUc.ManageBostionHost,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS {
		c.aliUc.Connections(cluster)
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.CreateNetwork,
			c.aliUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.aliUc.ManageInstance,
			c.aliUc.ManageBostionHost,
		}
	}
	if cluster.Type == biz.ClusterType_AWS_EKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.CreateNetwork,
			c.awsUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.awsUc.ManageKubernetesCluster,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_AKS {
		c.aliUc.Connections(cluster)
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.CreateNetwork,
			c.aliUc.SetByNodeGroups,
			c.aliUc.ImportKeyPair,
			c.aliUc.ManageKubernetesCluster,
		}
	}
	if cluster.Type == biz.ClusterType_GCP_GKE {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.gcpUc.Connections,
			c.gcpUc.CreateNetwork,
			c.gcpUc.SetByNodeGroups,
			c.gcpUc.ImportKeyPair,
			c.gcpUc.ManageKubernetesCluster,
		}
	}
	for _, f := range funcs {
		err := f(ctx, cluster)
		if err != nil {
			return cluster, err
		}
	}
	return cluster, nil
}

func (c *ClusterInterface) Stop(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	if cluster.Type.IsCloud() {
		return cluster, nil
	}
	var funcs []func(context.Context, *biz.Cluster) error
	if cluster.Type == biz.ClusterType_AWS_EC2 {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.ManageInstance,
			c.awsUc.ManageBostionHost,
			c.awsUc.DeleteKeyPair,
			c.awsUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS {
		c.aliUc.Connections(cluster)
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.ManageInstance,
			c.aliUc.ManageBostionHost,
			c.aliUc.DeleteKeyPair,
			c.aliUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_GCP_GKE {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.gcpUc.Connections,
			c.gcpUc.ManageKubernetesCluster,
			c.gcpUc.DeleteKeyPair,
			c.gcpUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_AWS_EKS {
		funcs = []func(context.Context, *biz.Cluster) error{
			c.awsUc.Connections,
			c.awsUc.DeleteKubernetesCluster,
			c.awsUc.DeleteKeyPair,
			c.awsUc.DeleteNetwork,
		}
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_AKS {
		c.aliUc.Connections(cluster)
		funcs = []func(context.Context, *biz.Cluster) error{
			c.aliUc.ManageKubernetesCluster,
			c.aliUc.DeleteKeyPair,
			c.aliUc.DeleteNetwork,
		}
	}
	for _, f := range funcs {
		err := f(ctx, cluster)
		if err != nil {
			return cluster, err
		}
	}
	return cluster, nil
}

func (c *ClusterInterface) GetRegions(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	if cluster.Type.IsCloud() {
		return cluster, nil
	}
	if cluster.Type == biz.ClusterType_AWS_EC2 || cluster.Type == biz.ClusterType_AWS_EKS {
		err := c.awsUc.GetAvailabilityZones(ctx, cluster)
		if err != nil {
			return nil, err
		}
		return cluster, nil
	}
	if cluster.Type == biz.ClusterType_ALICLOUD_ECS || cluster.Type == biz.ClusterType_ALICLOUD_AKS {
		err := c.aliUc.GetAvailabilityZones(ctx, cluster)
		if err != nil {
			return nil, err
		}
		return cluster, nil
	}
	return cluster, errors.New("cluster type is not supported")
}

func (c *ClusterInterface) MigrateToBostionHost(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	if cluster.BostionHost.User == "" {
		return cluster, errors.New("bostion host username is empty")
	}
	if cluster.BostionHost.ExternalIp == "" {
		return cluster, errors.New("bostion host external ip is empty")
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
		return cluster, err
	}
	arch := strings.TrimSpace(stdout)
	if _, ok := ARCH_MAP[arch]; !ok {
		return cluster, errors.New("bostion host arch is not supported")
	}
	cluster.BostionHost.Arch = ARCH_MAP[arch]
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return cluster, err
	}
	resourcePath, err := utils.GetServerStorePathByNames(utils.ResourcePackage)
	if err != nil {
		return cluster, err
	}
	syncShellPath := utils.MergePath(shellPath, SyncShell)
	homePath, err := utils.GetServerStorePathByNames()
	if err != nil {
		return cluster, err
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
		return cluster, err
	}
	serviceShellPath := utils.MergePath(shellPath, ServiceShell)
	err = remoteBash.RunWithLogging("bash", serviceShellPath, BostionHost)
	if err != nil {
		return cluster, err
	}
	return cluster, nil
}

func (c *ClusterInterface) GetNodesSystemInfo(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	errGroup, _ := errgroup.WithContext(ctx)
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return cluster, err
	}
	for _, node := range cluster.Nodes {
		if node.InternalIp == "" || node.User == "" {
			continue
		}
		nodegroup := &biz.NodeGroup{ClusterId: cluster.Id, Id: uuid.New().String()}
		node := node
		errGroup.Go(func() error {
			remoteBash := utils.NewRemoteBash(
				utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
				c.log,
			)
			systemInfoOutput, err := remoteBash.Run("bash", utils.MergePath(shellPath, systemInfoShell))
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
		return cluster, err
	}
	return cluster, nil
}

func (c *ClusterInterface) Install(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	remoteBash := utils.NewRemoteBash(
		utils.Server{Name: cluster.Name, Host: cluster.MasterIp, User: cluster.MasterUser, Port: 22, PrivateKey: cluster.PrivateKey},
		c.log,
	)
	shellPath, err := utils.GetServerStorePathByNames(utils.ShellPackage)
	if err != nil {
		return cluster, err
	}
	err = remoteBash.RunWithLogging("bash", utils.MergePath(shellPath, NodeInitShell))
	if err != nil {
		return cluster, err
	}
	configPath, err := utils.GetFromContextByKey(ctx, utils.ConfKey)
	if err != nil {
		return cluster, err
	}
	clusterConfigData, err := os.ReadFile(utils.MergePath(configPath, ClusterConfiguration))
	if err != nil {
		return cluster, err
	}
	clusterConfigMap := map[string]string{"CLUSTER_NAME": cluster.Name, "CLUSTER_VERSION": cluster.Version, "MASTER_IP": cluster.MasterIp, "IMAGE_REPO": ""}
	clusterConfigDataStr := utils.DecodeYaml(string(clusterConfigData), clusterConfigMap)
	clusterConfigPath := fmt.Sprintf("$HOME/%s", ClusterConfiguration)
	err = remoteBash.RunWithLogging("echo", clusterConfigDataStr, ">", clusterConfigPath)
	if err != nil {
		return cluster, err
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
		return cluster, err
	}
	err = remoteBash.RunWithLogging("rm -f $HOME/.kube/config && mkdir -p $HOME/.kube && cp -i /etc/kubernetes/admin.conf $HOME/.kube/config && chown $(id -u):$(id -g) $HOME/.kube/config")
	if err != nil {
		return cluster, err
	}
	token, err := remoteBash.Run("kubeadm token create")
	if err != nil {
		return cluster, err
	}
	cluster.Token = token
	ca, err := remoteBash.Run("cat /etc/kubernetes/pki/ca.crt")
	if err != nil {
		return cluster, err
	}
	cluster.CaData = ca
	cert, err := remoteBash.Run("cat /etc/kubernetes/pki/apiserver.crt")
	if err != nil {
		return cluster, err
	}
	cluster.CertData = cert
	key, err := remoteBash.Run("cat /etc/kubernetes/pki/apiserver.key")
	if err != nil {
		return cluster, err
	}
	cluster.KeyData = key
	return cluster, nil
}

func (c *ClusterInterface) UnInstall(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	for _, node := range cluster.Nodes {
		if node.Role != biz.NodeRole_WORKER {
			continue
		}
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		err := c.uninstallNode(remoteBash)
		if err != nil {
			return cluster, err
		}
		node.Status = biz.NodeStatus_NODE_DELETED
	}
	for _, node := range cluster.Nodes {
		if node.Role != biz.NodeRole_WORKER {
			continue
		}
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		err := c.uninstallNode(remoteBash)
		if err != nil {
			return cluster, err
		}
		node.Status = biz.NodeStatus_NODE_DELETED
	}
	return cluster, nil
}

func (c *ClusterInterface) HandlerNodes(ctx context.Context, cluster *biz.Cluster) (*biz.Cluster, error) {
	for _, node := range cluster.Nodes {
		remoteBash := utils.NewRemoteBash(
			utils.Server{Name: node.Name, Host: node.InternalIp, User: node.User, Port: 22, PrivateKey: cluster.PrivateKey},
			c.log,
		)
		if node.Status == biz.NodeStatus_NODE_CREATING {
			joinShell := fmt.Sprintf("kubeadm join --token %s --discovery-token-ca-cert-hash sha256:%s --certificate-key %s",
				cluster.Token, cluster.CertData, cluster.KeyData)
			if node.Role == biz.NodeRole_MASTER {
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
				return cluster, err
			}
			node.Status = biz.NodeStatus_NODE_RUNNING
		}
		if node.Status == biz.NodeStatus_NODE_DELETING {
			err := c.uninstallNode(remoteBash)
			if err != nil {
				return cluster, err
			}
			node.Status = biz.NodeStatus_NODE_DELETED
		}
	}
	return cluster, nil
}

func (cc *ClusterInterface) restartKubelet(remoteBash *utils.RemoteBash) error {
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

func (cc *ClusterInterface) uninstallNode(remoteBash *utils.RemoteBash) error {
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
