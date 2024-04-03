package balancer

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/entity"
	"github.com/xdire/xlb-poc/storage"
	"github.com/xdire/xlb-poc/tlssec"
	"net"
	"os"
	"strings"
	"sync"
)

var mgrMtx sync.Mutex
var singleton *Manager

type Manager struct {
	mtx       sync.Mutex
	frontend  map[string]*entity.Frontend
	backend   map[string]*Backend
	tlsBundle tlssec.TLSBundle
	mgrCtx    context.Context
	stopFunc  context.CancelFunc
}

func GetManager() (*Manager, error) {
	mgrMtx.Lock()
	defer mgrMtx.Unlock()
	if singleton != nil {
		return singleton, nil
	}
	return nil, fmt.Errorf("no manager instance available")
}

func NewManager(ctx context.Context, tlsBundle tlssec.TLSBundle) *Manager {
	mgrMtx.Lock()
	defer mgrMtx.Unlock()
	if singleton == nil {
		cCtx, cCancel := context.WithCancel(ctx)
		return &Manager{
			frontend:  make(map[string]*entity.Frontend),
			backend:   make(map[string]*Backend),
			tlsBundle: tlsBundle,
			mgrCtx:    cCtx,
			stopFunc:  cCancel,
		}
	}
	return singleton
}

func (mgr *Manager) InitWithStorage(ctx context.Context, stor storage.IManagerBackend) error {
	frontend, err := stor.ListFrontend(true)
	if err != nil {
		return err
	}
	for _, fe := range frontend {
		err = mgr.AddFrontend(fe)
		if err != nil {
			return err
		}
	}
	mgr.runBalancer(ctx)
	return nil
}

func (mgr *Manager) Stop() {
	mgr.stopFunc()
}

func (mgr *Manager) AddFrontend(fe *entity.Frontend) error {
	mgr.mtx.Lock()
	defer mgr.mtx.Unlock()
	mgr.frontend[fe.AccessKey] = fe
	return nil
}

func (mgr *Manager) RemoveFrontend(fe *entity.Frontend) error {
	return nil
}

func (mgr *Manager) runBalancer(ctx context.Context) {

	log := zerolog.New(os.Stdout).Level(zerolog.InfoLevel)

	config := &tls.Config{
		Certificates: []tls.Certificate{mgr.tlsBundle.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    mgr.tlsBundle.CertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 2022 TLS v1.2 compliant
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 2022 TLS v1.2 compliant
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,       // 2022 TLS v1.2 compliant
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,       // 2022 TLS v1.2 compliant
			tls.TLS_AES_128_GCM_SHA256,                // 2022 TLS v1.3 compliant
			tls.TLS_CHACHA20_POLY1305_SHA256,          // 2022 TLS v1.3 compliant
			tls.TLS_AES_256_GCM_SHA384,                // 2022 TLS v1.3 compliant
		},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	}

	listen, err := tls.Listen("tcp", "0.0.0.0:9090", config)
	if err != nil {
		fmt.Printf("\ncannot create frontend listener")
		return
	}

	// Spawn the coroutine to watch for the context break
	go func(l net.Listener) {
		<-ctx.Done()
		err := listen.Close()
		fmt.Printf("\nbalance manager listener closing")
		if err != nil {
			fmt.Printf("\nerror closing balance manager listener: %v", err)
		}
	}(listen)

	for {
		// Accept the message
		conn, err := listen.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed network") {
				log.Err(err).Msg("closed")
			}
			log.Err(err).Msg("failed to accept connection")
			return
		}
		tlsConn := conn.(*tls.Conn)
		// Proceed with the handshake
		err = tlsConn.Handshake()
		if err != nil {
			log.Err(err).Msg("failed to complete handshake")
			return
		}
		// Verify and find correct FE/BE
		// TODO Verify presence/nil check and internal validity of certificate
		certs := tlsConn.ConnectionState().PeerCertificates
		curCrt := certs[0]
		frontendAK := curCrt.Subject.CommonName
		if fe, found := mgr.frontend[frontendAK]; found {
			if be, bFound := mgr.backend[frontendAK]; bFound {
				go func() {
					err := be.Attach(tlsConn)
					if err != nil {
						log.Err(err).Msg("cannot attach to backend")
					}
				}()
			} else {
				newBe, _ := NewBackend(fe, BackendOptions{
					logLevel: zerolog.DebugLevel,
				})
				mgr.backend[fe.AccessKey] = newBe
				go func() {
					err := newBe.Attach(tlsConn)
					if err != nil {
						log.Err(err).Msg("cannot attach to backend")
					}
				}()
			}
		}
	}
}
