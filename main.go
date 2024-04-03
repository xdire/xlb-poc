package main

import (
	"context"
	"crypto/tls"
	"fmt"
	_ "github.com/golang/protobuf/ptypes"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/api"
	"github.com/xdire/xlb-poc/balancer"
	"github.com/xdire/xlb-poc/storage"
	storage_backend "github.com/xdire/xlb-poc/storage-backend"
	"github.com/xdire/xlb-poc/tlssec"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log := zerolog.New(os.Stdout).Level(zerolog.InfoLevel)
	ctx, cancel := context.WithCancel(context.Background())
	signals(cancel, log)
	//
	// Preload TLS Bundle, @see Makefile tls
	//
	tlsBundle, err := loadTLSBundle()
	if err != nil {
		log.Err(err).Msg("cannot load tls bundle")
		os.Exit(1)
	}
	//
	// Initialize DB Layer
	//
	var dataBackend storage.IManagerBackend
	dataBackend = &storage_backend.StorageBackendBadger{}
	err = dataBackend.Init(ctx, storage_backend.StorageBackendBadgerOptions{
		FilePath: "./data",
		TestMode: false,
		LogLvl:   zerolog.InfoLevel,
		CACert:   tlsBundle.Certificate,
	})
	if err != nil {
		log.Err(err).Msg("cannot init storage backend")
		os.Exit(1)
	}
	//
	// Create HTTP Server
	//
	router := assignRoutesWithStorage(dataBackend, tlsBundle)
	go startHTTPSServer(ctx, router, tlsBundle, log)

	bal := balancer.NewManager(ctx, *tlsBundle)
	err = bal.InitWithStorage(ctx, dataBackend)
	if err != nil {
		log.Err(err).Msg("cannot initialize balancer")
		return
	}

	<-ctx.Done()
}

func assignRoutesWithStorage(db storage.IManagerBackend, bundle *tlssec.TLSBundle) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/client", routeWithState(api.HandleClientCreate, db, bundle)).Methods("POST")
	router.HandleFunc("/api/v1/client/auth", routeWithState(api.HandleClientToken, db, bundle)).Methods("POST")
	router.HandleFunc("/api/v1/client/frontend", routeWithState(api.HandleClientFrontendCreate, db, bundle)).Methods("POST")
	router.HandleFunc("/api/v1/client/frontend/list", routeWithState(api.HandleClientFrontendList, db, bundle)).Methods("GET")
	router.HandleFunc("/api/v1/client/frontend/{uuid}", routeWithState(api.HandleClientFrontendGet, db, bundle)).Methods("GET")
	router.HandleFunc("/api/v1/client/frontend/{uuid}", routeWithState(api.HandleClientFrontendUpdate, db, bundle)).Methods("PATCH")
	router.HandleFunc("/api/v1/client/frontend/{uuid}/tls", routeWithState(api.HandleClientFrontendTLS, db, bundle)).Methods("GET")
	return router
}

func routeWithState(f func(http.ResponseWriter, *http.Request, storage.IManagerBackend, *tlssec.TLSBundle), db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		f(writer, request, db, tlsBundle)
	}
}

func startHTTPSServer(ctx context.Context, router *mux.Router, tlsBundle *tlssec.TLSBundle, log zerolog.Logger) {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", 8083),
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsBundle.Certificate},
			ClientAuth:   tls.NoClientCert,
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
		},
	}
	// Start server
	errs := make(chan error)
	go func() {
		log.Info().Msg("http server started")
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			errs <- err
		}
		errs <- nil
		log.Err(err).Msg("https server exited")
	}()
	select {
	case <-ctx.Done():
		_ = server.Close()
		break
	case <-errs:
		break
	}
}

func loadTLSBundle() (*tlssec.TLSBundle, error) {
	cert, err := os.ReadFile("cacert.pem")
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile("cakey.pem")
	if err != nil {
		return nil, err
	}
	return tlssec.FromPKI(string(cert), string(key))
}

func signals(cancelFunc context.CancelFunc, log zerolog.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
	go func() {
		sig := <-sigCh
		log.Info().Msgf("exited with signal %v", sig)
		cancelFunc()
	}()
}
