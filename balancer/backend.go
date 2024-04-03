package balancer

import (
	"crypto/tls"
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/entity"
	"io"
	"net"
	"os"
	"time"
)

type BackendOptions struct {
	routes   []string
	logLevel zerolog.Level
}

type Backend struct {
	id       string
	routes   []*entity.FrontendRoute
	timeout  time.Duration
	logger   zerolog.Logger
	strategy *RoundRobin
}

func NewBackend(f *entity.Frontend, opt BackendOptions) (*Backend, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("cannot create backend, cannot generate id")
	}
	if f.Routes == nil || len(f.Routes) == 0 {
		return nil, fmt.Errorf("cannot create backend, no routes provided")
	}

	logger := zerolog.New(os.Stdout).
		Level(opt.logLevel).With().Timestamp().
		Caller().Str("bid", id.String()).Logger()

	return &Backend{
		id:       id.String(),
		routes:   f.Routes,
		logger:   logger,
		timeout:  time.Second * time.Duration(f.RouteTimeoutSec),
		strategy: NewRoundRobin(0, int64(len(f.Routes))),
	}, nil
}

func (b *Backend) Attach(ch *tls.Conn) error {

	errTransport := make(chan error)
	defer func(ch net.Conn) {
		err := ch.Close()
		if err != nil {
			b.logger.Warn().Msg("attached channel closed")
		}
		close(errTransport)
	}(ch)

	addr := b.Next()
	conn, err := net.DialTimeout("tcp", addr, b.timeout)
	if err != nil {
		b.logger.Error().Msg("backend target unreachable")
		return err
	}

	sendReceive := func(w io.Writer, r io.Reader) {
		_, err := io.Copy(w, r)
		if err != nil {
			errTransport <- err
		}
	}

	go sendReceive(conn, ch)
	go sendReceive(ch, conn)

	err = <-errTransport
	if err != nil && err != io.EOF {
		b.logger.Error().Err(err).Msg("backend channel closed with error")
	}

	return nil
}

func (b *Backend) Next() string {
	id := b.strategy.Next()
	return b.routes[id].Dest
}
