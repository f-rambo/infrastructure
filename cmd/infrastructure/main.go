package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	_ "github.com/joho/godotenv/autoload"
)

// go build -ldflags "-X main.Version=x.y.z"
var (
	// Name is the name of the compiled software.
	Name string
	// Version is the version of the compiled software.
	Version string
	// flagconf is the config flag.
	flagconf string

	Resource string = "resource"

	Shell string = "shell"

	id, _ = os.Hostname()
)

func init() {
	flag.StringVar(&flagconf, "conf", "configs", "config path, eg: -conf config.yaml")
}

func newApp(logger log.Logger, gs *grpc.Server) *kratos.App {
	configDir := filepath.Dir(flagconf)
	resourceDir := fmt.Sprintf("%s/%s", filepath.Dir(configDir), Resource)
	shellDir := fmt.Sprintf("%s/%s", resourceDir, Shell)
	return kratos.New(
		kratos.ID(id),
		kratos.Name(Name),
		kratos.Version(Version),
		kratos.Metadata(map[string]string{
			utils.ServiceNameKey.String():    Name,
			utils.ServiceVersionKey.String(): Version,
			utils.RuntimeKey.String():        runtime.Version(),
			utils.OSKey.String():             runtime.GOOS,
			utils.ArchKey.String():           runtime.GOARCH,
			utils.ConfKey.String():           flagconf,
			utils.ConfDirKey.String():        configDir,
			utils.ResourceDir.String():       resourceDir,
			utils.ShellDir.String():          shellDir,
		}),
		kratos.Logger(logger),
		kratos.Server(gs),
	)
}

func main() {
	flag.Parse()
	c := config.New(
		config.WithSource(
			file.NewSource(flagconf),
		),
	)
	defer c.Close()

	if err := c.Load(); err != nil {
		panic(err)
	}

	var bc conf.Bootstrap
	if err := c.Scan(&bc); err != nil {
		panic(err)
	}

	Name = bc.Server.Name
	Version = bc.Server.Version
	if Name == "" || Version == "" {
		panic("name or version is empty")
	}

	utilLogger := utils.NewLog(&bc)
	defer utilLogger.Close()
	logger := log.With(utilLogger, utils.GetLogContenteKeyvals()...)

	app, cleanup, err := wireApp(&bc, logger)
	if err != nil {
		panic(err)
	}
	defer cleanup()

	// start and wait for stop signal
	if err := app.Run(); err != nil {
		panic(err)
	}
}
