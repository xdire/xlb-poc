package storage

import (
	"context"
	"crypto/tls"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/entity"
)

type IManagerBackendOptions interface {
	GetHostString() []string
	GetLocalPath() string
	IsTestMode() bool
	LogLevel() zerolog.Level
	CaCert() tls.Certificate
}

type IManagerBackend interface {
	Init(ctx context.Context, opt IManagerBackendOptions) error
	Close() error
	CreateClient(name string) (*entity.Client, error)
	GetClient(uuid string) (*entity.Client, error)
	CreateFrontend(opt *entity.Frontend) (*entity.Frontend, error)
	GetFrontend(uuid string) (*entity.Frontend, error)
	UpdateFrontend(uuid string, opt *entity.Frontend) error
	DeleteFrontend(uuid string) error
	CreateFrontendTLS(frontendUuid, clientUuid string) (*entity.FrontendTLSData, error)
	ListFrontend(onlyActive bool) ([]*entity.Frontend, error)
}
