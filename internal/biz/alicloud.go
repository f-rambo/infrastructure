package biz

import (
	"context"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2/log"
)

const (
	alicloudDefaultRegion = "cn-hangzhou"
)

type AliCloudUsecase struct {
	log *log.Helper
}

func NewAliCloudUseCase(logger log.Logger) *AliCloudUsecase {
	c := &AliCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}

func (a *AliCloudUsecase) Connections(ctx context.Context, cluster *Cluster) error {
	if cluster.Region == "" {
		cluster.Region = alicloudDefaultRegion
	}
	endpoint := fmt.Sprintf("ecs-%s.aliyuncs.com", cluster.Region)
	os.Setenv("ALICLOUD_ACCESS_KEY", cluster.AccessId)
	os.Setenv("ALICLOUD_SECRET_KEY", cluster.AccessKey)
	os.Setenv("ALICLOUD_REGION", cluster.Region)
	os.Setenv("ALICLOUD_DEFAULT_REGION", cluster.Region)
	fmt.Println(endpoint)
	// todo: use rest api
	return nil
}

func (a *AliCloudUsecase) GetAvailabilityZones(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) CreateNetwork(ctx context.Context, cluster *Cluster) error {
	fs := []func(context.Context, *Cluster) error{
		a.createVPC,
		a.createSubnets,
		a.createInternetGateway,
		a.createNatGateway,
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
	return nil
}

func (a *AliCloudUsecase) ImportKeyPair(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) DeleteKeyPair(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) ManageInstance(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) ManageBostionHost(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) DeleteNetwork(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createVPC(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createSubnets(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createInternetGateway(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createNatGateway(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createRouteTables(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createSecurityGroup(ctx context.Context, cluster *Cluster) error {
	return nil
}

func (a *AliCloudUsecase) createSLB(ctx context.Context, cluster *Cluster) error {
	return nil
}
