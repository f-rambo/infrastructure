// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/interfaces"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/server"
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
)

import (
	_ "github.com/joho/godotenv/autoload"
)

// Injectors from wire.go:

// wireApp init kratos application.
func wireApp(confServer *conf.Server, logger log.Logger) (*kratos.App, func(), error) {
	logInterface := interfaces.NewLogInterface(logger, confServer)
	awsCloudUsecase := biz.NewAwsCloudUseCase(logger)
	aliCloudUsecase := biz.NewAliCloudUseCase(logger)
	clusterUsecase := biz.NewClusterUsecase(logger)
	clusterInterface := interfaces.NewClusterInterface(awsCloudUsecase, aliCloudUsecase, clusterUsecase, logger, confServer)
	grpcServer := server.NewGRPCServer(confServer, logInterface, clusterInterface, logger)
	app := newApp(logger, grpcServer)
	return app, func() {
	}, nil
}
