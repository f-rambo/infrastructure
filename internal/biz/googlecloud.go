package biz

import (
	"github.com/go-kratos/kratos/v2/log"
)

type GoogleCloudUsecase struct {
	log *log.Helper
}

func NewGoogleCloudUseCase(logger log.Logger) *GoogleCloudUsecase {
	c := &GoogleCloudUsecase{
		log: log.NewHelper(logger),
	}
	return c
}
