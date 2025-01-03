package interfaces

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/f-rambo/cloud-copilot/infrastructure/api/common"
	logApi "github.com/f-rambo/cloud-copilot/infrastructure/api/log"
	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/f-rambo/cloud-copilot/infrastructure/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

type LogInterface struct {
	logApi.UnimplementedLogInterfaceServer
	log *log.Helper
	c   *conf.Server
}

func NewLogInterface(logger log.Logger, c *conf.Bootstrap) *LogInterface {
	return &LogInterface{
		log: log.NewHelper(logger),
		c:   c.Server,
	}
}

func (l *LogInterface) Ping(ctx context.Context, _ *emptypb.Empty) (*common.Msg, error) {
	return common.Response(), nil
}

func (l *LogInterface) GetLogs(stream logApi.LogInterface_GetLogsServer) error {
	i := 0
	for {
		ctx, cancel := context.WithCancel(stream.Context())
		defer cancel()
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if i > 0 {
			l.log.Info("repeat message, don't need to process")
			continue
		}
		i++

		if req.TailLines == 0 {
			req.TailLines = 30
		}

		logpath := utils.GetLogFilePath()
		if ok := utils.IsFileExist(logpath); !ok {
			return errors.New("log file does not exist")
		}

		file, err := os.Open(logpath)
		if err != nil {
			return err
		}
		defer file.Close()

		// Read initial lines if TailLines is specified
		if req.TailLines > 0 {
			initialLogs, err := utils.ReadLastNLines(file, int(req.TailLines))
			if err != nil {
				return err
			}
			err = stream.Send(&logApi.LogResponse{Log: initialLogs})
			if err != nil {
				return err
			}
		}

		// Move to the end of the file
		_, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}

		// Start watching for new logs
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return err
		}
		defer watcher.Close()

		err = watcher.Add(logpath)
		if err != nil {
			return err
		}

		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					if event.Op&fsnotify.Write == fsnotify.Write {
						newLogs, err := readNewLines(file)
						if err != nil {
							return
						}
						if newLogs != "" {
							err = stream.Send(&logApi.LogResponse{Log: newLogs})
							if err != nil {
								return
							}
						}
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					l.log.Errorf("error watching log file: %v", err)
				case <-ctx.Done():
					l.log.Info("GetLogs stream closed by client")
					return
				}
			}
		}()
	}
}

func readNewLines(file *os.File) (string, error) {
	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}

	newContent, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	if len(newContent) > 0 {
		_, err = file.Seek(currentPos+int64(len(newContent)), io.SeekStart)
		if err != nil {
			return "", err
		}
		return string(newContent), nil
	}

	return "", nil
}
