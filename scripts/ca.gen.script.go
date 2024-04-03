package main

import (
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/tlssec"
	"os"
	"time"
)

const cert_file_name = "cacert.pem"
const key_file_name = "cakey.pem"

func main() {
	log := zerolog.New(os.Stdout).Level(zerolog.InfoLevel)
	// Generate CA bundle
	cert, err := tlssec.GenerateCACert(tlssec.CertificateOptions{
		Country:      []string{"United States"},
		Organization: []string{"xdire"},
		CommonName:   "ca_xlb",
		StartFrom:    time.Now(),
		ValidUntil:   time.Now().Add(time.Hour * 24 * 730),
	}, 3072)
	if err != nil {
		log.Err(err).Msg("cannot generate certificate")
		os.Exit(1)
	}
	// Dump certificate information
	certF, err := os.Create(cert_file_name)
	defer certF.Close()
	if err != nil {
		log.Err(err).Msg("cannot create ca file")
		clean(certF, nil)
		os.Exit(1)
	}
	// Create CAKEY File
	keyF, err := os.Create(key_file_name)
	defer keyF.Close()
	if err != nil {
		log.Err(err).Msg("cannot create ca key file")
		clean(certF, keyF)
		os.Exit(1)
	}
	// Generate
	certS, _ := tlssec.CertificateToString(cert)
	keyS, _ := tlssec.KeyToString(cert.PrivateKey)
	// Write files
	_ = certF.Truncate(0)
	_ = keyF.Truncate(0)
	_, err = certF.Write([]byte(certS))
	_, err = keyF.Write([]byte(keyS))
	if err != nil {
		clean(certF, keyF)
		log.Err(err).Msg("cannot fill end files")
		os.Exit(1)
	}
	certStat, _ := certF.Stat()
	keyStat, _ := keyF.Stat()
	log.Info().Msgf("completed, files updated %s %s", certStat.Name(), keyStat.Name())
}

func clean(f1 *os.File, f2 *os.File) {
	if f1 != nil {
		_ = f1.Close()
	}
	if f2 != nil {
		_ = f2.Close()
	}
	_ = os.Remove(cert_file_name)
	_ = os.Remove(key_file_name)
}
