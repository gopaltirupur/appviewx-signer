package logger

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type IDType int

const (
	id IDType = iota
)

type logger struct {
	zap   *zap.Logger
	level zap.AtomicLevel
}

var wrapLogger *logger

func init() {

	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "when"
	config.EncoderConfig.CallerKey = "who"
	config.EncoderConfig.MessageKey = "what"
	// config.EncoderConfig.EncodeTime = SyslogTimeEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.Encoding = "console"

	if strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else if strings.ToLower(os.Getenv("LOG_LEVEL")) == "info" {
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	}

	l, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)

	if err != nil {
		panic(err)
	}
	wrapLogger = &logger{
		zap:   l,
		level: config.Level,
	}
}

func SyslogTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02T15:04:05.000000Z"))
}

// func NewContext(ctx context.Context, fields ...zapcore.Field) context.Context {
// 	return context.WithValue(ctx, id, WithContext(ctx).With(fields...))
// }

// func WithContext(ctx context.Context) *zap.Logger {
// 	if ctx == nil {
// 		return wrapLogger.zap
// 	}
// 	if ctxLogger, ok := ctx.Value(id).(*zap.Logger); ok {
// 		return ctxLogger
// 	}
// 	return wrapLogger.zap
// }

func WithContext(ctx context.Context) logr.InfoLogger {
	var log logr.Logger
	if ctx == nil {
		ctx = context.Background()
		log = logr.Logger.WithValues(log, ctx.Value)
	} else {
		log = logr.Logger.WithValues(log, ctx.Value)
	}
	return log.V(1)
}
