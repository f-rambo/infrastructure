package utils

import (
	"context"

	"github.com/go-kratos/kratos/v2"
)

type MatedataKey string

func (m MatedataKey) String() string {
	return string(m)
}

const (
	ServiceNameKey    MatedataKey = "service"
	ServiceVersionKey MatedataKey = "version"
	RuntimeKey        MatedataKey = "runtime"
	OSKey             MatedataKey = "os"
	ArchKey           MatedataKey = "arch"
	ConfKey           MatedataKey = "conf"
	ConfDirKey        MatedataKey = "confdir"
)

func GetFromContextByKey(ctx context.Context, key MatedataKey) string {
	appInfo, ok := kratos.FromContext(ctx)
	if !ok {
		return ""
	}
	value, ok := appInfo.Metadata()[key.String()]
	if !ok {
		return ""
	}
	return value
}

func GetFromContext(ctx context.Context) map[string]string {
	appInfo, ok := kratos.FromContext(ctx)
	if !ok {
		return nil
	}
	return appInfo.Metadata()
}
