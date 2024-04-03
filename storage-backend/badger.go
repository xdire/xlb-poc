package storage_backend

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/entity"
	"github.com/xdire/xlb-poc/storage"
	"github.com/xdire/xlb-poc/tlssec"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"sync"
	"time"
)

type StorageBackendBadgerOptions struct {
	FilePath string
	TestMode bool
	LogLvl   zerolog.Level
	CACert   tls.Certificate
}

func (s StorageBackendBadgerOptions) GetHostString() []string {
	panic("not supported")
}

func (s StorageBackendBadgerOptions) GetLocalPath() string {
	return s.FilePath
}

func (s StorageBackendBadgerOptions) IsTestMode() bool {
	return s.TestMode
}

func (s StorageBackendBadgerOptions) LogLevel() zerolog.Level {
	return s.LogLvl
}

func (s StorageBackendBadgerOptions) CaCert() tls.Certificate {
	return s.CACert
}

type StorageBackendBadger struct {
	logger zerolog.Logger
	init   bool
	mut    sync.Mutex
	db     *badger.DB
	opt    storage.IManagerBackendOptions
}

func (s *StorageBackendBadger) Init(ctx context.Context, opt storage.IManagerBackendOptions) error {
	s.mut.Lock()
	defer s.mut.Unlock()
	if s.init {
		return nil
	}
	s.logger = zerolog.New(os.Stdout).Level(opt.LogLevel())
	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		s.logger.Err(err).Msg("cannot init badger type of storage backend")
		s.logger.Fatal()
	}
	s.db = db
	s.opt = opt
	go s.maintenance(ctx)
	s.init = true
	return nil
}

func (s *StorageBackendBadger) Close() error {
	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("cannot close badger type of storage backend")
	}
	return nil
}

func (s *StorageBackendBadger) CreateClient(name string) (*entity.Client, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("create client failed, error: %w", err)
	}
	key, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("create client key failed, error: %w", err)
	}
	hash := sha256.New()
	hash.Write([]byte(key.String()))
	sha := hash.Sum(nil)
	keyStr := hex.EncodeToString(sha)

	client := &entity.Client{
		Uuid:      id.String(),
		Key:       keyStr,
		Name:      name,
		CreatedAt: timestamppb.Now(),
	}

	writeBuf, err := proto.Marshal(client)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal client entity to representation")
	}

	err = s.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte("cl_"+client.Uuid), writeBuf)
		err := txn.SetEntry(e)
		return err
	})

	if err != nil {
		return nil, fmt.Errorf("client create failed, error: %w", err)
	}
	return client, nil
}

func (s *StorageBackendBadger) GetClient(uuid string) (*entity.Client, error) {
	client := &entity.Client{}
	err := s.db.View(func(txn *badger.Txn) error {
		// Seek with prefix
		item, err := txn.Get([]byte("cl_" + uuid))
		if err != nil {
			return err
		}
		// Access value
		err = item.Value(func(val []byte) error {
			// Transform to proto
			err = proto.Unmarshal(val, client)
			if err != nil {
				return fmt.Errorf("cannot unmarshal client, error: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *StorageBackendBadger) GetFrontend(uuid string) (*entity.Frontend, error) {
	fe := &entity.Frontend{}
	err := s.db.View(func(txn *badger.Txn) error {
		// Seek with prefix
		item, err := txn.Get([]byte("fe_" + uuid))
		if err != nil {
			return err
		}
		// Access value
		err = item.Value(func(val []byte) error {
			// Transform to proto
			err = proto.Unmarshal(val, fe)
			if err != nil {
				return fmt.Errorf("cannot unmarshal frontend, error: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fe, nil
}

func (s *StorageBackendBadger) CreateFrontend(fe *entity.Frontend) (*entity.Frontend, error) {

	if len(fe.ClientId) == 0 {
		return nil, fmt.Errorf("frontend should have client assigned")
	}
	// Generate UUID
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("create frontend failed, error: %w", err)
	}

	// Generate Access Key
	key, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("create client key failed, error: %w", err)
	}
	hash := sha256.New()
	hash.Write([]byte(key.String()))
	sha := hash.Sum(nil)
	keyStr := hex.EncodeToString(sha)

	// Update fields
	fe.Uuid = id.String()
	fe.AccessKey = keyStr

	writeBuf, err := proto.Marshal(fe)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal client entity to representation")
	}

	txn := s.db.NewTransaction(true)
	// Set frontend entity
	err = txn.Set([]byte("fe_"+fe.Uuid), writeBuf)
	if err != nil {
		txn.Discard()
		return nil, fmt.Errorf("cannot create frontend, txn failure, error: %w", err)
	}
	// Set pivot entry for client
	err = txn.Set([]byte("clife_"+fe.ClientId), []byte(fe.Uuid))
	if err != nil {
		txn.Discard()
		return nil, fmt.Errorf("cannot create frontend, txn failure, error: %w", err)
	}
	// Set access key entry
	err = txn.Set([]byte("feac_"+fe.AccessKey), []byte(fe.Uuid))
	if err != nil {
		txn.Discard()
		return nil, fmt.Errorf("cannot create frontend, txn failure, error: %w", err)
	}
	// Commit TXN
	err = txn.Commit()
	if err != nil {
		return nil, fmt.Errorf("cannot create frontend, txn failure, error: %w", err)
	}

	return fe, nil
}

func (s *StorageBackendBadger) UpdateFrontend(uuid string, opt *entity.Frontend) error {
	fe := &entity.Frontend{}
	txn := s.db.NewTransaction(true)
	item, err := txn.Get([]byte("fe_" + uuid))
	if err != nil {
		txn.Discard()
		return err
	}

	// Access value
	err = item.Value(func(val []byte) error {
		// Transform to proto
		err = proto.Unmarshal(val, fe)
		if err != nil {
			return fmt.Errorf("cannot unmarshal frontend, error: %w", err)
		}
		return nil
	})
	if err != nil {
		txn.Discard()
		return err
	}

	fe.Active = opt.Active
	fe.Routes = opt.Routes
	fe.Strategy = opt.Strategy
	fe.RouteTimeoutSec = opt.RouteTimeoutSec

	writeBuf, err := proto.Marshal(fe)
	if err != nil {
		return fmt.Errorf("cannot marshal to representation, error %w", err)
	}

	err = txn.Set([]byte("fe_"+uuid), writeBuf)
	if err != nil {
		txn.Discard()
		return err
	}

	err = txn.Commit()
	if err != nil {
		return fmt.Errorf("cannot commit transaction, error: %w", err)
	}

	return nil
}

func (s *StorageBackendBadger) DeleteFrontend(uuid string) error {
	fe := &entity.Frontend{}
	txn := s.db.NewTransaction(true)
	item, err := txn.Get([]byte("fe_" + uuid))
	if err != nil {
		txn.Discard()
		return err
	}
	// Access value
	err = item.Value(func(val []byte) error {
		// Transform to proto
		err = proto.Unmarshal(val, fe)
		if err != nil {
			return fmt.Errorf("cannot unmarshal frontend, error: %w", err)
		}
		return nil
	})
	if err != nil {
		txn.Discard()
		return err
	}
	err = s.db.Update(func(txn *badger.Txn) error {
		// Delete record for the frontend
		err := txn.Delete([]byte("fe_" + uuid))
		if err != nil {
			// still try to delete access record
			s.logger.Err(err).Msg("cannot delete frontend in transaction")
		}
		// Delete record for the frontend access, try to delete anyway as command
		// should shut down ceritifcate access
		err = txn.Delete([]byte("feac_" + fe.AccessKey))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete failed, error: %w", err)
	}
	return nil
}

func (s *StorageBackendBadger) CreateFrontendTLS(frontendUuid, clientUuid string) (*entity.FrontendTLSData, error) {
	frontend := &entity.Frontend{}
	client := &entity.Client{}
	err := s.db.View(func(txn *badger.Txn) error {
		// Seek frontend with prefix
		feItem, err := txn.Get([]byte("fe_" + frontendUuid))
		if err != nil {
			return err
		}
		// Access value
		err = feItem.Value(func(val []byte) error {
			// Transform to proto
			err = proto.Unmarshal(val, frontend)
			if err != nil {
				return fmt.Errorf("cannot unmarshal frontend, error: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Check if Frontend client matches with client it tries to create for
		if frontend.ClientId != clientUuid {
			return fmt.Errorf("frontend unathorized for client")
		}

		// Seek client with prefix
		cliItem, err := txn.Get([]byte("cl_" + clientUuid))
		if err != nil {
			return err
		}
		// Access value
		err = cliItem.Value(func(val []byte) error {
			// Transform to proto
			err = proto.Unmarshal(val, client)
			if err != nil {
				return fmt.Errorf("cannot unmarshal client, error: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot match frontend and client, error %w", err)
	}
	cert, err := tlssec.GenerateSignedCert(s.opt.CaCert(), 3072, tlssec.CertificateOptions{
		Email:        []string{client.Name},
		Organization: []string{client.Uuid},
		CommonName:   frontend.AccessKey,
		StartFrom:    time.Time{},
		ValidUntil:   time.Now().Add(1 * time.Hour * 24 * 365),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot generate cert, error %w", err)
	}
	certificate, err := tlssec.B64Certificate(cert)
	if err != nil {
		return nil, err
	}
	ke, err := tlssec.B64Key(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &entity.FrontendTLSData{
		Key:         ke,
		Certificate: certificate,
	}, nil
}

func (s *StorageBackendBadger) ListFrontend(onlyActive bool) ([]*entity.Frontend, error) {
	out := make([]*entity.Frontend, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("fe_")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				fe := &entity.Frontend{}
				fmt.Printf("key=%s, value=%s\n", k, v)
				// Transform to proto
				err := proto.Unmarshal(v, fe)
				if err != nil {
					return fmt.Errorf("cannot unmarshal frontend record, error: %w", err)
				}
				if onlyActive && fe.Active {
					out = append(out, fe)
				} else if !onlyActive {
					out = append(out, fe)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *StorageBackendBadger) maintenance(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
runLoop:
	for {
		select {
		// Track context resolution
		case <-ctx.Done():
			err := s.Close()
			if err != nil {
				s.logger.Err(err).Msg("badger backend error on close")
			}
			break runLoop
		// Track GC loops required for LSM
		case <-ticker.C:
		gcLoop:
			for {
			moreGC:
				err := s.db.RunValueLogGC(0.7)
				// As per badger docs — run compaction until nothing to compact
				if err == nil {
					goto moreGC
				}
				break gcLoop
			}
		}
	}
}
