package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

var errNoCertOrKeyProvided = errors.New("cert or key has not provided")

type CertType int

const (
	CertTypeRoot         CertType = iota // 根证书
	CertTypeIntermediate                 // 中间证书
	CertTypeServer                       // 域名证书
)

// A Certificate is one certificates, include Certificate and PrivateKey
type Certificate struct {
	x509.Certificate
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
}

type CertChain struct {
	rootPair  *Certificate // Root Pair is the root certificate.
	interPair *Certificate // Intermediate Pair is the intermediate certificate.

	mapMu    sync.Mutex
	certPool *x509.CertPool // CertPool is a set of certificates.
	certMap  map[string]*Certificate
}

func NewCertChain() *CertChain {
	return &CertChain{
		certMap: make(map[string]*Certificate),
	}
}

// LoadRootPair Load Root certificate and key from file
func (cc *CertChain) LoadRootPair(certFile, keyFile string) (err error) {
	cc.rootPair, err = LoadPair(certFile, keyFile)
	return
}

func (cc *CertChain) LoadRootPairEmbed(certPEMBlock, keyPEMBlock []byte) (err error) {
	cc.rootPair, err = LoadPairEmbed(certPEMBlock, keyPEMBlock)
	return
}

// LoadInterPair Load Intermediate certificate and key from file
func (cc *CertChain) LoadInterPair(certFile, keyFile string) (err error) {
	cc.interPair, err = LoadPair(certFile, keyFile)
	return
}

func (cc *CertChain) LoadInterPairEmbed(certPEMBlock, keyPEMBlock []byte) (err error) {
	cc.interPair, err = LoadPairEmbed(certPEMBlock, keyPEMBlock)
	return
}

// 获取根证书
func (cc *CertChain) GetRootPair() *Certificate {
	if cc.rootPair != nil {
		return cc.rootPair
	}
	cc.rootPair, _ = cc.generatePair(CertTypeRoot, "Jedi Root CA")
	return cc.rootPair
}

// 获取中间证书
func (cc *CertChain) GetInterPair() *Certificate {
	if cc.interPair != nil {
		return cc.interPair
	}
	cc.interPair, _ = cc.generatePair(CertTypeIntermediate, "Jedi Inter CA")

	return cc.interPair
}

func (cc *CertChain) GetCertPool() *x509.CertPool {
	if cc.certPool == nil {
		cc.certPool = x509.NewCertPool()
	}
	return cc.certPool
}

// 获取域名证书
func (cc *CertChain) GetServerPair(domain string) (*Certificate, error) {
	if len(domain) == 0 {
		return nil, errors.New("domain is empty")
	}

	if cc.certPool == nil {
		cc.certPool = x509.NewCertPool()
	}

	return cc.generatePair(CertTypeServer, domain)
}

// SaveRootPair save root certificate and keyfile to file
func (cc *CertChain) SaveRootPair(certFile, keyFile string) error {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return errNoCertOrKeyProvided
	}

	root := cc.GetRootPair()

	return root.Save(certFile, keyFile)
}

// SaveInterPair save intermediate certificate and keyfile to file
func (cc *CertChain) SaveInterPair(certFile, keyFile string) error {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return errNoCertOrKeyProvided
	}

	inter := cc.GetInterPair()

	return inter.Save(certFile, keyFile)
}

// 生成证书，包括根证书、中间证书和域名证书
func (cc *CertChain) generatePair(certType CertType, name string) (*Certificate, error) {
	if cc.certMap[name] != nil {
		cc.mapMu.Lock()
		cert := cc.certMap[name]
		cc.mapMu.Unlock()
		return cert, nil
	}

	key := GeneratePrivateKey()

	csr := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(int64(certType) + time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
			Organization:       []string{"JediLtd"},
			OrganizationalUnit: []string{"JediProxy"},
			CommonName:         name,
		},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  certType != CertTypeServer,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	if certType == CertTypeRoot {
		csr.MaxPathLen = 1
	}

	if certType == CertTypeIntermediate {
		csr.MaxPathLenZero = true
		csr.MaxPathLen = 0
	}

	if certType == CertTypeServer {
		csr.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		csr.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} // 服务端认证
		// make certificate valid over localhost.
		csr.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}

	var parentCert *Certificate

	if certType == CertTypeRoot {
		// 根证书自签
		parentCert = &Certificate{*csr, key}
	} else if certType == CertTypeIntermediate {
		// 中间证书使用根证书签名
		parentCert = cc.GetRootPair()
	} else {
		// 域名证书使用中间证书签名
		parentCert = cc.GetInterPair()
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, csr, &parentCert.Certificate, key.Public(), parentCert.PrivateKey)
	if err != nil {
		return nil, err
	}

	// 转为 x509 中间证书
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	c := &Certificate{*cert, key}

	if certType == CertTypeServer {
		cc.GetCertPool().AddCert(cert)
		cc.mapMu.Lock()
		cc.certMap[name] = c
		cc.mapMu.Unlock()
	}

	return c, nil
}

// 生成 ECC 私钥
func GeneratePrivateKey() (key *ecdsa.PrivateKey) {
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return
}

// PEM To ECC Private Key
func ParsePemToPrivateKey(keyPEMBlock []byte) (*ecdsa.PrivateKey, error) {
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return nil, fmt.Errorf("failed to decrypt PEM block containing private key")
	}

	if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
		return nil, fmt.Errorf("unknown PEM header %q", keyDERBlock.Type)
	}

	if pKey, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return pKey, nil
	}

	return nil, fmt.Errorf("unknown private key type")
}

// LoadPair load certificate and keyfile from file
// https://github.com/valyala/fasthttp/blob/master/server.go#L1740
func LoadPair(certFile, keyFile string) (cert *Certificate, err error) {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return nil, errNoCertOrKeyProvided
	}

	// load cert and key by tls.LoadX509KeyPair
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return
	}

	cert = &Certificate{
		Certificate: *x509Cert,
		PrivateKey:  tlsCert.PrivateKey,
	}
	return
}

// LoadPairEmbed does the same as LoadPair but using in-memory data.
func LoadPairEmbed(certPEMBlock, keyPEMBlock []byte) (cert *Certificate, err error) {
	// load cert and key by tls.LoadX509KeyPair
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return
	}

	cert = &Certificate{
		Certificate: *x509Cert,
		PrivateKey:  tlsCert.PrivateKey,
	}
	return
}

func (c *Certificate) ToPem() (cert, key []byte, err error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}

	cert = pem.EncodeToMemory(block)

	priv, ok := c.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		err = errors.New("private key type does not match public key type")
		return
	}

	decodedBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return
	}

	key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: decodedBytes})

	return
}

func (c *Certificate) Save(certFile, keyFile string) error {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return errNoCertOrKeyProvided
	}

	cert, key, err := c.ToPem()
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(certFile, cert, 0644); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0644); err != nil {
		return err
	}
	return nil
}
