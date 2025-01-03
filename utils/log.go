package utils

import (
	"path/filepath"

	"github.com/f-rambo/cloud-copilot/infrastructure/internal/conf"
	"github.com/go-kratos/kratos/v2/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

var _ log.Logger = (*logtool)(nil)

type logtool struct {
	logger           log.Logger
	lumberjackLogger *lumberjack.Logger
}

func NewLog(conf *conf.Bootstrap) *logtool {
	logConf := conf.Log
	lumberjackLogger := &lumberjack.Logger{
		Filename:   GetLogFilePath(),
		MaxSize:    int(logConf.MaxSize),
		MaxBackups: int(logConf.MaxBackups),
		MaxAge:     int(logConf.MaxAge),
		LocalTime:  true,
	}
	return &logtool{
		logger:           log.NewStdLogger(lumberjackLogger),
		lumberjackLogger: lumberjackLogger,
	}
}

func (l *logtool) Log(level log.Level, keyvals ...interface{}) error {
	return l.logger.Log(level, keyvals...)
}

func (l *logtool) Close() error {
	if l.lumberjackLogger != nil {
		return l.lumberjackLogger.Close()
	}
	return nil
}

func GetLogContenteKeyvals() []interface{} {
	return []interface{}{
		"ts", log.Timestamp("2006-01-02 15:04:05"),
		"caller", log.DefaultCaller,
	}
}

func GetLogFilePath() string {
	return filepath.Join(GetServerStoragePathByNames("log"), "log.log")
}
