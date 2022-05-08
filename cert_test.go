package main

import (
	"crypto/x509"
	"fmt"
	"testing"
)

func TestGenerateRootPair(t *testing.T) {
	c := NewCertChain()

	cert := c.GetRootPair()

	err := verifyCACert(cert, cert)

	if err != nil {
		t.Error(err)
	}

	c.SaveRootPair("cert/ca.cert.pem", "cert/ca.key.pem")
}

func TestGenerateInterPair(t *testing.T) {
	c := NewCertChain()
	c.LoadRootPair("cert/ca.cert.pem", "cert/ca.key.pem")
	root := c.GetRootPair()
	inter := c.GetInterPair()

	err := verifyCACert(root, inter)

	if err != nil {
		t.Error(err)
	}
	c.SaveInterPair("cert/inter.cert.pem", "cert/inter.key.pem")
}

func TestGenerateServerpair(t *testing.T) {
	c := NewCertChain()
	c.LoadRootPair("cert/ca.cert.pem", "cert/ca.key.pem")
	c.LoadInterPair("cert/inter.cert.pem", "cert/inter.key.pem")
	root := c.GetRootPair()
	inter := c.GetInterPair()
	server, err := c.GetServerPair("foreverz.cn")

	if err != nil {
		t.Error(err)
	}

	err = verifyLow(root, inter, server)
	if err != nil {
		t.Error(err)
	}

	server.Save("cert/server.cert.pem", "cert/server.key.pem")
}

func verifyCACert(root, child *Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(&root.Certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := child.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: " + err.Error())
	}

	return nil
}

func verifyLow(root, intermediate, child *Certificate) error {
	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	roots.AddCert(&root.Certificate)
	inter.AddCert(&intermediate.Certificate)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	}

	if _, err := child.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: " + err.Error())
	}

	return nil
}
