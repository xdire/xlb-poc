package balancer

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/xdire/xlb-poc/entity"
	"github.com/xdire/xlb-poc/storage"
	"github.com/xdire/xlb-poc/tlssec"
	"log"
	"sync"
)

var mgrMtx sync.Mutex
var singleton *Manager

//type backend struct {
//	routes []backendRoute
//}
//
//type backendRoute struct {
//	dialTo    string
//	capacity  int
//	util      int
//	totalUtil int
//}
//
//func newBackend(conn net.Listener, fe *entity.Frontend) {
//
//}

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

//func (mgr *Manager) runFrontend(ctx context.Context, fe *entity.Frontend) error {
//	go func() {
//
//		be, err := NewBackend(fe, BackendOptions{})
//		if err != nil {
//			fmt.Printf("\ncannot instantiate backend")
//		}
//		err := be.Attach(listen)
//		if err != nil {
//			return
//		}
//
//	}()
//}

func (mgr *Manager) runBalancer(ctx context.Context) {
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

	for {
		// Accept the message
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v\n", err)
			continue
		}
		tlsConn := conn.(*tls.Conn)
		// Proceed with the handshake
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf("failed to complete handshake: %s\n", err)
			return
		}
		// Verify and find correct FE/BE
		certs := tlsConn.ConnectionState().PeerCertificates
		curCrt := certs[0]
		frontendAK := curCrt.Subject.CommonName
		if fe, found := mgr.frontend[frontendAK]; found {
			if be, bFound := mgr.backend[frontendAK]; bFound {
				go be.Attach(tlsConn)
			} else {
				newBe, _ := NewBackend(fe, BackendOptions{})
				mgr.backend[fe.AccessKey] = newBe
				go newBe.Attach(tlsConn)
			}
		}
	}
}
