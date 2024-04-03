package tlssec

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type TLSBundle struct {
	Certificate tls.Certificate
	PublicKey   crypto.PublicKey
	PrivateKey  crypto.PrivateKey
	CertPool    *x509.CertPool
}

type pemBlockContainer struct {
	cert *pem.Block
	key  *pem.Block
}

type CertificateOptions struct {
	Email        []string
	Country      []string
	Organization []string
	Unit         []string
	Locality     []string
	CommonName   string
	StartFrom    time.Time
	ValidUntil   time.Time
}

func (o CertificateOptions) Prepare(cert *x509.Certificate) {
	subj := pkix.Name{}
	if len(o.Email) > 0 {
		cert.EmailAddresses = o.Email
	}
	if len(o.Country) > 0 {
		subj.Country = o.Country
	}
	if len(o.Organization) > 0 {
		subj.Organization = o.Organization
	}
	if len(o.Unit) > 0 {
		subj.OrganizationalUnit = o.Unit
	}
	if len(o.Locality) > 0 {
		subj.Locality = o.Locality
	}
	if len(o.CommonName) > 0 {
		subj.CommonName = o.CommonName
	}
	cert.Subject = subj
	cert.NotBefore = o.StartFrom
	if o.ValidUntil.Before(time.Now()) {
		cert.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	} else {
		cert.NotAfter = o.ValidUntil
	}
}

func GenerateCACert(options CertificateOptions, strength int) (*tls.Certificate, error) {
	newKey, err := rsa.GenerateKey(rand.Reader, strength)
	if err != nil {
		return nil, err
	}
	// Create serial number of uniform randomized
	serial, err := getNewSerial()
	// Create template for Certificate CA
	template := &x509.Certificate{
		SerialNumber:          serial,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	options.Prepare(template)
	// Create certificate
	cert, err := x509.CreateCertificate(rand.Reader, template, template, newKey.Public(), newKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  newKey,
	}, nil
}

func GenerateSignedCert(caCert tls.Certificate, strength int, options CertificateOptions) (*tls.Certificate, error) {
	newKey, err := rsa.GenerateKey(rand.Reader, strength)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("cannot create signed certificate, cannot decrypt CA certificate, error: %+v", err)
	}
	// Create serial number of uniform randomized
	serial, err := getNewSerial()
	// Create template for Certificate CA
	template := &x509.Certificate{
		SerialNumber:          serial,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	options.Prepare(template)
	// Create certificate
	derivative, err := x509.CreateCertificate(rand.Reader, template, ca, &newKey.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derivative key error: %v", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{derivative},
		PrivateKey:  newKey,
	}, nil
}

func LoadFromPEM(ps string) (*TLSBundle, error) {
	storage := &pemBlockContainer{}
	blockScan, rest := pem.Decode([]byte(ps))
	// Until storage is fulfilled or there no more blocks to parse: do
	for (storage.cert == nil || storage.key == nil) && blockScan != nil {
		mapPemBlock(blockScan, storage)
		blockScan, rest = pem.Decode(rest)
	}
	// Check if storage fulfilled after the pemBlock scans
	if storage.cert != nil && storage.key != nil {
		return nil, fmt.Errorf("no information decoded from PEM")
	}
	// Create certificate entity from PEM data
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(storage.cert), pem.EncodeToMemory(storage.key))
	if err != nil {
		return nil, fmt.Errorf("cannot create certificate from PEM, error: %w", err)
	}
	return FromPKICert(&cert)
}

func FromPKI(certificate string, privateKey string) (*TLSBundle, error) {
	trimC := strings.Trim(certificate, " ")
	trimK := strings.Trim(privateKey, " ")
	cert, err := tls.X509KeyPair([]byte(trimC), []byte(trimK))
	if err != nil {
		// Try possible flattening in PKI credential
		normalizedCert := stringToPEMFormat(trimC)
		normalizedKey := stringToPEMFormat(trimK)
		cert, err = tls.X509KeyPair([]byte(normalizedCert), []byte(normalizedKey))
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate, error %w", err)
		}
		return FromPKICert(&cert)
	}
	return FromPKICert(&cert)
}

func FromPKICert(cert *tls.Certificate) (*TLSBundle, error) {
	var err error
	// Create Leaf form of certificate
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("cannot load ceritifcate, error: %v", err)
	}
	config := &TLSBundle{
		Certificate: *cert,
		PublicKey:   cert.Leaf.PublicKey,
		CertPool:    x509.NewCertPool(),
		PrivateKey:  cert.PrivateKey,
	}
	config.CertPool.AddCert(cert.Leaf)
	return config, nil
}

func getNewSerial() (*big.Int, error) {
	// Create limit for random integer of 128 bit
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	// Create serial number of uniform randomized
	serial, err := rand.Int(rand.Reader, limit)
	return serial, err
}

func B64Certificate(cert *tls.Certificate) (string, error) {
	res, err := CertificateToString(cert)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(res)), nil
}

func B64Key(key interface{}) (string, error) {
	res, err := KeyToString(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(res)), nil
}

func CertificateToString(cert *tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("incorrect certificate data in cert structure")
	}
	// PEM format
	certBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Certificate[0]},
	)
	return string(certBytes), nil
}

func KeyToString(key interface{}) (string, error) {
	k, isRSA := key.(*rsa.PrivateKey)
	if !isRSA {
		return "", fmt.Errorf("invalid rsa format")
	}
	if err := k.Validate(); err != nil {
		return "", fmt.Errorf("key validation failed")
	}
	// PEM format
	keyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k)},
	)
	return string(keyBytes), nil
}

func mapPemBlock(block *pem.Block, pbc *pemBlockContainer) {
	if block == nil {
		return
	}
	if strings.Index(block.Type, "CERTIFICATE") > -1 {
		pbc.cert = block
	} else if strings.Index(block.Type, "PRIVATE KEY") > -1 {
		pbc.key = block
	}
}

// Re-format PEM string which might lost format during the data conversions
func stringToPEMFormat(pem string) string {
	spaced := strings.Split(pem, " ")
	nline := strings.Join(spaced, "\n")
	res := strings.ReplaceAll(nline, "-----BEGIN\nCERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
	res = strings.ReplaceAll(res, "-----END\nCERTIFICATE-----", "-----END CERTIFICATE-----")
	res = strings.ReplaceAll(res, "-----BEGIN\nRSA\nPRIVATE\nKEY-----", "-----BEGIN RSA PRIVATE KEY-----")
	res = strings.ReplaceAll(res, "-----END\nRSA\nPRIVATE\nKEY-----", "-----END RSA PRIVATE KEY-----")
	return res
}
